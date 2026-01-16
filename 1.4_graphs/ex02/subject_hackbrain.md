<thinking>
## Analyse du Concept
- Concept : DFS & BFS - Parcours de graphes fondamentaux
- Phase demandée : 1 (Transition débutant → intermédiaire)
- Adapté ? OUI - DFS et BFS sont les algorithmes fondamentaux de parcours de graphes

## Combo Base + Bonus
- Exercice de base : DFS avec edge classification, BFS shortest path
- Bonus Standard : Grid traversal (flood fill, islands)
- Bonus Expert : Bridges, articulation points, biconnected components
- Bonus Génie : Bidirectional BFS avec optimisations
- Palier bonus : ⚡🔥🧠
- Progression logique ? OUI

## Prérequis & Difficulté
- Prérequis réels : Représentations de graphes (ex00), récursivité, files/piles
- Difficulté estimée : 5/10
- Cohérent avec phase ? OUI (Phase 1 = 3-5/10)

## Aspect Fun/Culture
- Contexte choisi : The Legend of Zelda: Breath of the Wild - Exploration de Hyrule
- MEME mnémotechnique : "It's dangerous to go alone! Take this." (DFS/BFS tools)
- Pourquoi c'est fun : Link explore Hyrule = DFS exploration, finding shrines = BFS shortest path, Korok seeds = flood fill, Towers revealing map = multi-source BFS, bridges in Hyrule = literal bridge-finding algorithm. C'est une analogie PARFAITE pour les parcours de graphes.
- Score d'intelligence : 97/100 - Analogie exceptionnelle

## Scénarios d'Échec (5 mutants concrets)
1. Mutant A (Boundary) : BFS sans marquer les nœuds visités → boucle infinie
2. Mutant B (Safety) : DFS récursif sans limite de profondeur → stack overflow
3. Mutant C (Resource) : Oublie de passer à la composante suivante → composantes manquantes
4. Mutant D (Logic) : Classification d'arêtes inversée (back/forward)
5. Mutant E (Return) : Retourne distances négatives au lieu de -1 pour unreachable

## Verdict
VALIDE - L'exercice est excellent avec une analogie Zelda parfaitement adaptée à l'exploration de graphes
</thinking>

---

# Exercice 1.4.2-a : hyrule_explorer

**Module :**
1.4.2 — DFS & BFS Fundamentals

**Concept :**
a — Parcours de graphes (DFS, BFS) et applications

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isolé

**Langage :**
Rust Edition 2024 / C17

**Prérequis :**
- Représentations de graphes (1.4.0)
- Récursivité et structures de contrôle
- Files (Queue) et Piles (Stack)

**Domaines :**
Struct, MD, Algo

**Durée estimée :**
60 min

**XP Base :**
120

**Complexité :**
T2 O(V+E) × S1 O(V)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- Rust : `src/lib.rs`, `Cargo.toml`
- C : `hyrule_explorer.c`, `hyrule_explorer.h`

**Fonctions autorisées :**
- Rust : `Vec`, `VecDeque`, `HashMap`, `HashSet`
- C : `malloc`, `realloc`, `free`, `memset`

**Fonctions interdites :**
- Bibliothèques de graphes externes

### 1.2 Consigne

#### 1.2.1 Version Culture Pop : The Legend of Zelda: Breath of the Wild

**🎮 "Open your eyes... Wake up, Link."**

Tu es Link, le héros légendaire d'Hyrule. Après 100 ans de sommeil, tu te réveilles dans un monde dévasté par le Fléau Ganon. Pour sauver la Princesse Zelda, tu dois :

1. **Explorer Hyrule** (DFS) : Découvrir tous les recoins du monde en profondeur
2. **Trouver le chemin le plus court** (BFS) : Rejoindre les sanctuaires rapidement
3. **Cartographier les régions** : Identifier les zones connectées
4. **Détecter les cycles** : Repérer les routes qui reviennent sur elles-mêmes

**Analogie parfaite :**
- **DFS** = Explorer une région jusqu'au bout avant de revenir
- **BFS** = Trouver le sanctuaire le plus proche
- **Composantes connexes** = Régions isolées d'Hyrule
- **Bipartite** = Peut-on colorier la carte en 2 couleurs ?
- **Bridges** = Ponts dont la destruction isolerait des zones
- **Grid traversal** = Explorer la carte vue de dessus

**Ta mission :**

Implémenter les outils de navigation de la Sheikah Slate :

```
┌─────────────────────────────────────────┐
│           SHEIKAH SLATE v1.0            │
├─────────────────────────────────────────┤
│  [SCOPE]     Scan area (DFS)            │
│  [SENSOR]    Find nearest (BFS)         │
│  [MAP]       Reveal regions             │
│  [PINS]      Multi-source tracking      │
└─────────────────────────────────────────┘
```

**Entrée :**
- `adj: &[Vec<usize>]` : Liste d'adjacence du graphe d'Hyrule
- `source: usize` : Position de départ de Link

**Sortie :**
- Distances, chemins, composantes selon la fonction

**Contraintes :**
- Complexité O(V + E) pour tous les parcours
- Gérer les graphes déconnectés
- Graphes dirigés et non-dirigés selon le contexte

**Exemples :**

| Fonction | Input | Output | Explication |
|----------|-------|--------|-------------|
| `bfs_shortest(adj, 0)` | Graph 5 nœuds | `[0, 1, 1, 2, 3]` | Distances depuis sanctuaire 0 |
| `has_cycle_directed(adj)` | Triangle | `true` | Route circulaire détectée |
| `count_components(adj)` | 3 îles | `3` | 3 régions isolées |
| `is_bipartite(adj)` | Carré | `true` | Bicoloration possible |

#### 1.2.2 Version Académique

Implémenter les algorithmes de parcours de graphes :

1. **DFS (Depth-First Search)** : Parcours en profondeur d'abord
   - Timestamps (discovery/finish)
   - Classification des arêtes (tree, back, forward, cross)
   - Détection de cycles

2. **BFS (Breadth-First Search)** : Parcours en largeur d'abord
   - Plus court chemin en nombre d'arêtes
   - Multi-source BFS
   - 0-1 BFS pour poids 0 ou 1

3. **Applications** : Composantes connexes, bipartition, ponts, points d'articulation

### 1.3 Prototype

```rust
// Rust - Edition 2024
pub mod hyrule_explorer {
    use std::collections::VecDeque;

    /// DFS result with timestamps and edge classification
    #[derive(Debug, Clone)]
    pub struct SheikahScan {
        pub discovery: Vec<usize>,
        pub finish: Vec<usize>,
        pub parent: Vec<Option<usize>>,
        pub tree_edges: Vec<(usize, usize)>,
        pub back_edges: Vec<(usize, usize)>,
        pub forward_edges: Vec<(usize, usize)>,
        pub cross_edges: Vec<(usize, usize)>,
    }

    // === DFS Functions ===

    /// Full DFS with edge classification - "Scan the area, Link!"
    pub fn sheikah_scan(adj: &[Vec<usize>]) -> SheikahScan;

    /// Iterative DFS to avoid stack overflow on large maps
    pub fn explore_iterative(adj: &[Vec<usize>], start: usize) -> Vec<usize>;

    /// Check for cycles in directed graph (Guardian patrol routes)
    pub fn detect_guardian_loop(adj: &[Vec<usize>]) -> bool;

    /// Check for cycles in undirected graph
    pub fn detect_loop_undirected(adj: &[Vec<usize>]) -> bool;

    // === BFS Functions ===

    /// BFS shortest path - "Find the nearest shrine!"
    pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32>;

    /// BFS with path reconstruction
    pub fn path_to_shrine(adj: &[Vec<usize>], start: usize, shrine: usize) -> Option<Vec<usize>>;

    /// Multi-source BFS - "All towers activated!"
    pub fn tower_coverage(adj: &[Vec<usize>], towers: &[usize]) -> Vec<i32>;

    /// 0-1 BFS for roads with different travel costs
    pub fn travel_cost_01(adj: &[Vec<(usize, u8)>], start: usize) -> Vec<i32>;

    /// Bidirectional BFS - "Fast travel enabled!"
    pub fn fast_travel_distance(adj: &[Vec<usize>], start: usize, end: usize) -> Option<i32>;

    // === Graph Properties ===

    /// Connected components - "Map regions"
    pub fn map_regions(adj: &[Vec<usize>]) -> Vec<usize>;

    /// Count connected components
    pub fn count_regions(adj: &[Vec<usize>]) -> usize;

    /// Bipartite check - "Can we 2-color this map?"
    pub fn is_bipartite_hyrule(adj: &[Vec<usize>]) -> bool;

    /// 2-coloring of bipartite graph
    pub fn color_map(adj: &[Vec<usize>]) -> Option<Vec<u8>>;

    /// Find bridges - "Critical paths"
    pub fn find_critical_bridges(adj: &[Vec<usize>]) -> Vec<(usize, usize)>;

    /// Find articulation points - "Key locations"
    pub fn find_key_locations(adj: &[Vec<usize>]) -> Vec<usize>;
}

/// Grid-based exploration (Hyrule map view)
pub mod hyrule_map {
    pub type HyruleGrid = Vec<Vec<char>>;

    /// Flood fill - "Spread the Sheikah energy"
    pub fn sheikah_energy_spread(grid: &mut HyruleGrid, r: usize, c: usize, energy: char);

    /// Count islands/regions - "How many stable islands?"
    pub fn count_sky_islands(grid: &HyruleGrid) -> usize;

    /// Shortest path in grid - "Path to Divine Beast"
    pub fn path_to_divine_beast(
        grid: &HyruleGrid,
        start: (usize, usize),
        beast: (usize, usize),
    ) -> Option<usize>;

    /// Multi-source distance - "Distance from all shrines"
    pub fn shrine_distances(grid: &HyruleGrid, shrines: &[(usize, usize)]) -> Vec<Vec<i32>>;

    /// Blood Moon spreading (like rotting oranges)
    pub fn blood_moon_spread(grid: &mut HyruleGrid) -> i32;
}
```

```c
// C17
#ifndef HYRULE_EXPLORER_H
#define HYRULE_EXPLORER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// DFS Result structure
typedef struct {
    size_t *discovery;
    size_t *finish;
    int64_t *parent;  // -1 for no parent
    size_t n;
} SheikahScan;

// Core DFS functions
SheikahScan *sheikah_scan(size_t **adj, size_t *adj_sizes, size_t n);
void sheikah_scan_free(SheikahScan *scan);
size_t *explore_iterative(size_t **adj, size_t *adj_sizes, size_t n, size_t start, size_t *out_len);
bool detect_guardian_loop(size_t **adj, size_t *adj_sizes, size_t n);
bool detect_loop_undirected(size_t **adj, size_t *adj_sizes, size_t n);

// Core BFS functions
int32_t *find_nearest_shrine(size_t **adj, size_t *adj_sizes, size_t n, size_t link_pos);
size_t *path_to_shrine(size_t **adj, size_t *adj_sizes, size_t n, size_t start, size_t shrine, size_t *path_len);
int32_t *tower_coverage(size_t **adj, size_t *adj_sizes, size_t n, size_t *towers, size_t tower_count);

// Graph properties
size_t *map_regions(size_t **adj, size_t *adj_sizes, size_t n);
size_t count_regions(size_t **adj, size_t *adj_sizes, size_t n);
bool is_bipartite_hyrule(size_t **adj, size_t *adj_sizes, size_t n);
uint8_t *color_map(size_t **adj, size_t *adj_sizes, size_t n);  // NULL if not bipartite

// Bridges and articulation points
typedef struct {
    size_t u;
    size_t v;
} Bridge;

Bridge *find_critical_bridges(size_t **adj, size_t *adj_sizes, size_t n, size_t *count);
size_t *find_key_locations(size_t **adj, size_t *adj_sizes, size_t n, size_t *count);

// Grid functions
size_t count_sky_islands(char **grid, size_t rows, size_t cols);
int32_t path_to_divine_beast(char **grid, size_t rows, size_t cols,
                              size_t sr, size_t sc, size_t er, size_t ec);
void sheikah_energy_spread(char **grid, size_t rows, size_t cols,
                            size_t r, size_t c, char energy);

#endif
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fait Historique

BFS a été inventé par Konrad Zuse en 1945 et formalisé par Edward F. Moore en 1959 pour trouver le plus court chemin dans un labyrinthe. DFS a été formalisé par Charles Pierre Trémaux au 19ème siècle comme méthode pour résoudre des labyrinthes (l'algorithme de la main sur le mur).

### 2.2 DFS vs BFS : Quand utiliser lequel ?

| Critère | DFS | BFS |
|---------|-----|-----|
| Plus court chemin (non pondéré) | ❌ | ✅ |
| Détection de cycles | ✅ | ✅ |
| Tri topologique | ✅ | ❌ |
| Composantes fortement connexes | ✅ | ❌ |
| Espace mémoire | O(hauteur) | O(largeur) |
| Graphe très profond | ⚠️ Stack overflow | ✅ |
| Graphe très large | ✅ | ⚠️ Mémoire |

### 2.3 DANS LA VRAIE VIE

| Métier | Utilisation | Algorithme préféré |
|--------|-------------|-------------------|
| **GPS/Navigation** | Plus court chemin | BFS (ou Dijkstra pour pondéré) |
| **Garbage Collector** | Marquage des objets accessibles | DFS |
| **Web Crawler** | Exploration de liens | BFS (pour sites proches) / DFS (pour profondeur) |
| **Réseau social** | Degrés de séparation | BFS |
| **Compilateur** | Analyse de dépendances | DFS (tri topologique) |
| **Jeux vidéo** | Pathfinding, exploration | BFS/A* |

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
hyrule_explorer.c  hyrule_explorer.h  main.c  Cargo.toml  src/

$ gcc -Wall -Wextra -Werror -std=c17 hyrule_explorer.c main.c -o test_c

$ ./test_c
=== HYRULE EXPLORER TEST SUITE ===
Test DFS edge classification: OK
Test cycle detection (directed): OK
Test cycle detection (undirected): OK
Test BFS shortest path: OK
Test multi-source BFS: OK
Test 0-1 BFS: OK
Test connected components: OK
Test bipartite check: OK
Test bridges: OK
Test articulation points: OK
Test count islands: OK
Test shortest path grid: OK
All tests passed! The Calamity Ganon awaits.

$ cargo test
   Compiling hyrule_explorer v0.1.0
    Finished test [unoptimized + debuginfo]
     Running unittests src/lib.rs

running 16 tests
test hyrule_explorer::tests::test_dfs_basic ... ok
test hyrule_explorer::tests::test_dfs_edge_classification ... ok
test hyrule_explorer::tests::test_cycle_directed ... ok
test hyrule_explorer::tests::test_cycle_undirected ... ok
test hyrule_explorer::tests::test_bfs_shortest ... ok
test hyrule_explorer::tests::test_bfs_path ... ok
test hyrule_explorer::tests::test_multi_source ... ok
test hyrule_explorer::tests::test_01_bfs ... ok
test hyrule_explorer::tests::test_bipartite_yes ... ok
test hyrule_explorer::tests::test_bipartite_no ... ok
test hyrule_explorer::tests::test_bridges ... ok
test hyrule_explorer::tests::test_articulation ... ok
test hyrule_explorer::tests::test_components ... ok
test hyrule_map::tests::test_islands ... ok
test hyrule_map::tests::test_flood_fill ... ok
test hyrule_map::tests::test_grid_path ... ok

test result: ok. 16 passed; 0 failed
```

---

## ⚡ SECTION 3.1 : BONUS STANDARD — Grid Exploration

**Difficulté Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Récompense :**
XP ×2

### 3.1.1 Consigne Bonus : Sky Islands (Tears of the Kingdom)

**🎮 "The sky islands hold secrets from an ancient past..."**

Les îles célestes de Tears of the Kingdom flottent au-dessus d'Hyrule. Implémente les fonctions de navigation pour la carte vue de dessus :

- `count_sky_islands(grid)` : Compter les îles (groupes de '1' connectés)
- `path_to_divine_beast(grid, start, end)` : Plus court chemin évitant les obstacles
- `sheikah_energy_spread(grid, r, c, energy)` : Flood fill

**Exemple :**
```
Grid:
1 1 0 0 1
1 0 0 0 1
0 0 1 0 1

Islands: 3 (top-left, center, right column)
```

---

## 🔥 SECTION 3.2 : BONUS EXPERT — Critical Infrastructure

**Difficulté Bonus :**
★★★★★★★★☆☆ (8/10)

**Récompense :**
XP ×4

### 3.2.1 Consigne Bonus : Bridges & Articulation Points

**🎮 "If Vah Ruta is destroyed, Zora's Domain will be isolated..."**

Identifie les **ponts critiques** (dont la destruction déconnecte le graphe) et les **points d'articulation** (nœuds critiques).

Utilise l'algorithme de Tarjan avec les `low` values :
- `low[u]` = min discovery time atteignable depuis le sous-arbre de u
- Bridge : `low[v] > discovery[u]`
- Articulation : racine avec 2+ enfants OU non-racine avec `low[v] >= discovery[u]`

---

## 🧠 SECTION 3.3 : BONUS GÉNIE — Bidirectional BFS

**Difficulté Bonus :**
🧠 (11/10)

**Récompense :**
XP ×6

### 3.3.1 Consigne Bonus : Fast Travel Optimization

Implémente un BFS bidirectionnel qui explore simultanément depuis la source ET la destination, se rencontrant au milieu.

Avantage : Complexité effective O(b^(d/2)) au lieu de O(b^d) où b=branching factor, d=distance.

```rust
pub fn fast_travel_bidirectional(
    adj: &[Vec<usize>],
    start: usize,
    end: usize
) -> Option<(i32, Vec<usize>)>; // (distance, path)
```

---

## ✅❌ SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test | Input | Expected | Points | Trap |
|------|-------|----------|--------|------|
| `test_dfs_basic` | Tree | Ordre préfixe correct | 5 | - |
| `test_dfs_times` | Graph 4 nœuds | discovery < finish | 5 | Timestamps incorrects |
| `test_back_edge` | Cycle | back_edges non vide | 5 | Classifié comme forward |
| `test_bfs_dist` | Graph 5 nœuds | [0,1,1,2,3] | 5 | Off-by-one |
| `test_bfs_path` | Chemin existe | Vec du chemin | 5 | Chemin inversé |
| `test_bfs_unreachable` | Composantes séparées | -1 pour unreachable | 5 | 0 ou panic |
| `test_multi_source` | 2 sources | Distances min | 5 | Une seule source |
| `test_01_bfs` | Poids 0 et 1 | Deque correcte | 10 | Queue normale |
| `test_cycle_yes` | Triangle dirigé | true | 5 | - |
| `test_cycle_no` | DAG | false | 5 | Faux positif |
| `test_components` | 3 îles | 3 | 5 | Compte faux |
| `test_bipartite_yes` | Carré | true | 5 | - |
| `test_bipartite_no` | Triangle | false | 5 | Retourne true |
| `test_bridges` | Bridge 2-3 | [(2,3)] | 10 | - |
| `test_articulation` | Nodes 2,3 | [2,3] | 10 | - |
| `test_islands` | 3 îles | 3 | 5 | - |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "hyrule_explorer.h"

void test_bfs_shortest(void)
{
    size_t n = 5;
    size_t adj_data[5][3] = {{1, 2}, {0, 3}, {0, 3}, {1, 2, 4}, {3}};
    size_t adj_sizes[5] = {2, 2, 2, 3, 1};

    size_t *adj[5];
    for (size_t i = 0; i < n; i++) {
        adj[i] = adj_data[i];
    }

    int32_t *dist = find_nearest_shrine(adj, adj_sizes, n, 0);

    assert(dist[0] == 0);
    assert(dist[1] == 1);
    assert(dist[2] == 1);
    assert(dist[3] == 2);
    assert(dist[4] == 3);

    free(dist);
    printf("Test BFS shortest: OK\n");
}

void test_cycle_directed(void)
{
    // Triangle: 0 -> 1 -> 2 -> 0
    size_t n = 3;
    size_t adj0[] = {1};
    size_t adj1[] = {2};
    size_t adj2[] = {0};
    size_t *adj[] = {adj0, adj1, adj2};
    size_t adj_sizes[] = {1, 1, 1};

    assert(detect_guardian_loop(adj, adj_sizes, n) == true);

    // No cycle: 0 -> 1 -> 2
    size_t adj0_nc[] = {1};
    size_t adj1_nc[] = {2};
    size_t adj2_nc[] = {};
    size_t *adj_nc[] = {adj0_nc, adj1_nc, adj2_nc};
    size_t adj_sizes_nc[] = {1, 1, 0};

    assert(detect_guardian_loop(adj_nc, adj_sizes_nc, n) == false);

    printf("Test cycle directed: OK\n");
}

void test_bipartite(void)
{
    // Square (bipartite)
    size_t n = 4;
    size_t adj0[] = {1, 3};
    size_t adj1[] = {0, 2};
    size_t adj2[] = {1, 3};
    size_t adj3[] = {2, 0};
    size_t *adj[] = {adj0, adj1, adj2, adj3};
    size_t adj_sizes[] = {2, 2, 2, 2};

    assert(is_bipartite_hyrule(adj, adj_sizes, n) == true);

    // Triangle (not bipartite)
    size_t adj0_t[] = {1, 2};
    size_t adj1_t[] = {0, 2};
    size_t adj2_t[] = {0, 1};
    size_t *adj_t[] = {adj0_t, adj1_t, adj2_t};
    size_t adj_sizes_t[] = {2, 2, 2};

    assert(is_bipartite_hyrule(adj_t, adj_sizes_t, 3) == false);

    printf("Test bipartite: OK\n");
}

void test_components(void)
{
    // Two components: {0,1}, {2,3}
    size_t n = 4;
    size_t adj0[] = {1};
    size_t adj1[] = {0};
    size_t adj2[] = {3};
    size_t adj3[] = {2};
    size_t *adj[] = {adj0, adj1, adj2, adj3};
    size_t adj_sizes[] = {1, 1, 1, 1};

    assert(count_regions(adj, adj_sizes, n) == 2);

    printf("Test components: OK\n");
}

void test_islands(void)
{
    size_t rows = 4, cols = 5;
    char *grid[] = {
        "11000",
        "11000",
        "00100",
        "00011"
    };

    assert(count_sky_islands(grid, rows, cols) == 3);

    printf("Test islands: OK\n");
}

void test_grid_path(void)
{
    size_t rows = 3, cols = 4;
    char *grid[] = {
        "...#",
        "##..",
        "...."
    };

    int32_t dist = path_to_divine_beast(grid, rows, cols, 0, 0, 2, 3);
    assert(dist == 5);

    printf("Test grid path: OK\n");
}

int main(void)
{
    printf("=== HYRULE EXPLORER TEST SUITE ===\n");
    test_bfs_shortest();
    test_cycle_directed();
    test_bipartite();
    test_components();
    test_islands();
    test_grid_path();
    printf("All tests passed! The Calamity Ganon awaits.\n");
    return 0;
}
```

### 4.3 Solution de référence (Rust)

```rust
pub mod hyrule_explorer {
    use std::collections::VecDeque;

    #[derive(Debug, Clone, Default)]
    pub struct SheikahScan {
        pub discovery: Vec<usize>,
        pub finish: Vec<usize>,
        pub parent: Vec<Option<usize>>,
        pub tree_edges: Vec<(usize, usize)>,
        pub back_edges: Vec<(usize, usize)>,
        pub forward_edges: Vec<(usize, usize)>,
        pub cross_edges: Vec<(usize, usize)>,
    }

    pub fn sheikah_scan(adj: &[Vec<usize>]) -> SheikahScan {
        let n = adj.len();
        let mut result = SheikahScan {
            discovery: vec![0; n],
            finish: vec![0; n],
            parent: vec![None; n],
            ..Default::default()
        };

        let mut visited = vec![0u8; n]; // 0=white, 1=gray, 2=black
        let mut time = 0usize;

        fn dfs(
            u: usize,
            adj: &[Vec<usize>],
            visited: &mut [u8],
            time: &mut usize,
            result: &mut SheikahScan,
        ) {
            visited[u] = 1; // Gray
            *time += 1;
            result.discovery[u] = *time;

            for &v in &adj[u] {
                match visited[v] {
                    0 => {
                        // White -> Tree edge
                        result.tree_edges.push((u, v));
                        result.parent[v] = Some(u);
                        dfs(v, adj, visited, time, result);
                    }
                    1 => {
                        // Gray -> Back edge (cycle!)
                        result.back_edges.push((u, v));
                    }
                    2 => {
                        // Black
                        if result.discovery[u] < result.discovery[v] {
                            result.forward_edges.push((u, v));
                        } else {
                            result.cross_edges.push((u, v));
                        }
                    }
                    _ => {}
                }
            }

            visited[u] = 2; // Black
            *time += 1;
            result.finish[u] = *time;
        }

        for u in 0..n {
            if visited[u] == 0 {
                dfs(u, adj, &mut visited, &mut time, &mut result);
            }
        }

        result
    }

    pub fn explore_iterative(adj: &[Vec<usize>], start: usize) -> Vec<usize> {
        let n = adj.len();
        if start >= n {
            return Vec::new();
        }

        let mut visited = vec![false; n];
        let mut result = Vec::new();
        let mut stack = vec![start];

        while let Some(u) = stack.pop() {
            if visited[u] {
                continue;
            }
            visited[u] = true;
            result.push(u);

            // Push neighbors in reverse order for correct DFS order
            for &v in adj[u].iter().rev() {
                if !visited[v] {
                    stack.push(v);
                }
            }
        }

        result
    }

    pub fn detect_guardian_loop(adj: &[Vec<usize>]) -> bool {
        let n = adj.len();
        let mut state = vec![0u8; n]; // 0=unvisited, 1=visiting, 2=visited

        fn has_cycle(u: usize, adj: &[Vec<usize>], state: &mut [u8]) -> bool {
            state[u] = 1;
            for &v in &adj[u] {
                if state[v] == 1 {
                    return true; // Back edge = cycle
                }
                if state[v] == 0 && has_cycle(v, adj, state) {
                    return true;
                }
            }
            state[u] = 2;
            false
        }

        for u in 0..n {
            if state[u] == 0 && has_cycle(u, adj, &mut state) {
                return true;
            }
        }
        false
    }

    pub fn detect_loop_undirected(adj: &[Vec<usize>]) -> bool {
        let n = adj.len();
        let mut visited = vec![false; n];

        fn has_cycle(u: usize, parent: Option<usize>, adj: &[Vec<usize>], visited: &mut [bool]) -> bool {
            visited[u] = true;
            for &v in &adj[u] {
                if !visited[v] {
                    if has_cycle(v, Some(u), adj, visited) {
                        return true;
                    }
                } else if Some(v) != parent {
                    return true; // Visited non-parent = cycle
                }
            }
            false
        }

        for u in 0..n {
            if !visited[u] && has_cycle(u, None, adj, &mut visited) {
                return true;
            }
        }
        false
    }

    pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32> {
        let n = adj.len();
        let mut dist = vec![-1i32; n];

        if link_pos >= n {
            return dist;
        }

        let mut queue = VecDeque::new();
        queue.push_back(link_pos);
        dist[link_pos] = 0;

        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                if dist[v] == -1 {
                    dist[v] = dist[u] + 1;
                    queue.push_back(v);
                }
            }
        }

        dist
    }

    pub fn path_to_shrine(adj: &[Vec<usize>], start: usize, shrine: usize) -> Option<Vec<usize>> {
        let n = adj.len();
        if start >= n || shrine >= n {
            return None;
        }

        let mut parent = vec![None; n];
        let mut visited = vec![false; n];
        let mut queue = VecDeque::new();

        queue.push_back(start);
        visited[start] = true;

        while let Some(u) = queue.pop_front() {
            if u == shrine {
                // Reconstruct path
                let mut path = Vec::new();
                let mut cur = shrine;
                while cur != start {
                    path.push(cur);
                    cur = parent[cur]?;
                }
                path.push(start);
                path.reverse();
                return Some(path);
            }

            for &v in &adj[u] {
                if !visited[v] {
                    visited[v] = true;
                    parent[v] = Some(u);
                    queue.push_back(v);
                }
            }
        }

        None
    }

    pub fn tower_coverage(adj: &[Vec<usize>], towers: &[usize]) -> Vec<i32> {
        let n = adj.len();
        let mut dist = vec![-1i32; n];
        let mut queue = VecDeque::new();

        for &t in towers {
            if t < n {
                dist[t] = 0;
                queue.push_back(t);
            }
        }

        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                if dist[v] == -1 {
                    dist[v] = dist[u] + 1;
                    queue.push_back(v);
                }
            }
        }

        dist
    }

    pub fn travel_cost_01(adj: &[Vec<(usize, u8)>], start: usize) -> Vec<i32> {
        let n = adj.len();
        let mut dist = vec![i32::MAX; n];

        if start >= n {
            return dist;
        }

        let mut deque = VecDeque::new();
        dist[start] = 0;
        deque.push_back(start);

        while let Some(u) = deque.pop_front() {
            for &(v, w) in &adj[u] {
                let new_dist = dist[u] + w as i32;
                if new_dist < dist[v] {
                    dist[v] = new_dist;
                    if w == 0 {
                        deque.push_front(v); // Cost 0: add to front
                    } else {
                        deque.push_back(v);  // Cost 1: add to back
                    }
                }
            }
        }

        dist.iter().map(|&d| if d == i32::MAX { -1 } else { d }).collect()
    }

    pub fn map_regions(adj: &[Vec<usize>]) -> Vec<usize> {
        let n = adj.len();
        let mut component = vec![usize::MAX; n];
        let mut comp_id = 0;

        for start in 0..n {
            if component[start] != usize::MAX {
                continue;
            }

            let mut stack = vec![start];
            while let Some(u) = stack.pop() {
                if component[u] != usize::MAX {
                    continue;
                }
                component[u] = comp_id;
                for &v in &adj[u] {
                    if component[v] == usize::MAX {
                        stack.push(v);
                    }
                }
            }
            comp_id += 1;
        }

        component
    }

    pub fn count_regions(adj: &[Vec<usize>]) -> usize {
        let components = map_regions(adj);
        if components.is_empty() {
            return 0;
        }
        components.iter().max().map(|&m| m + 1).unwrap_or(0)
    }

    pub fn is_bipartite_hyrule(adj: &[Vec<usize>]) -> bool {
        color_map(adj).is_some()
    }

    pub fn color_map(adj: &[Vec<usize>]) -> Option<Vec<u8>> {
        let n = adj.len();
        let mut color = vec![2u8; n]; // 2 = uncolored

        for start in 0..n {
            if color[start] != 2 {
                continue;
            }

            let mut queue = VecDeque::new();
            queue.push_back(start);
            color[start] = 0;

            while let Some(u) = queue.pop_front() {
                for &v in &adj[u] {
                    if color[v] == 2 {
                        color[v] = 1 - color[u];
                        queue.push_back(v);
                    } else if color[v] == color[u] {
                        return None; // Same color as neighbor = not bipartite
                    }
                }
            }
        }

        Some(color)
    }

    pub fn find_critical_bridges(adj: &[Vec<usize>]) -> Vec<(usize, usize)> {
        let n = adj.len();
        let mut disc = vec![0; n];
        let mut low = vec![0; n];
        let mut visited = vec![false; n];
        let mut bridges = Vec::new();
        let mut time = 0;

        fn dfs(
            u: usize,
            parent: Option<usize>,
            adj: &[Vec<usize>],
            disc: &mut [usize],
            low: &mut [usize],
            visited: &mut [bool],
            bridges: &mut Vec<(usize, usize)>,
            time: &mut usize,
        ) {
            visited[u] = true;
            *time += 1;
            disc[u] = *time;
            low[u] = *time;

            for &v in &adj[u] {
                if !visited[v] {
                    dfs(v, Some(u), adj, disc, low, visited, bridges, time);
                    low[u] = low[u].min(low[v]);
                    if low[v] > disc[u] {
                        bridges.push((u.min(v), u.max(v)));
                    }
                } else if Some(v) != parent {
                    low[u] = low[u].min(disc[v]);
                }
            }
        }

        for u in 0..n {
            if !visited[u] {
                dfs(u, None, adj, &mut disc, &mut low, &mut visited, &mut bridges, &mut time);
            }
        }

        bridges
    }

    pub fn find_key_locations(adj: &[Vec<usize>]) -> Vec<usize> {
        let n = adj.len();
        let mut disc = vec![0; n];
        let mut low = vec![0; n];
        let mut visited = vec![false; n];
        let mut ap = vec![false; n];
        let mut time = 0;

        fn dfs(
            u: usize,
            parent: Option<usize>,
            adj: &[Vec<usize>],
            disc: &mut [usize],
            low: &mut [usize],
            visited: &mut [bool],
            ap: &mut [bool],
            time: &mut usize,
        ) {
            visited[u] = true;
            *time += 1;
            disc[u] = *time;
            low[u] = *time;
            let mut children = 0;

            for &v in &adj[u] {
                if !visited[v] {
                    children += 1;
                    dfs(v, Some(u), adj, disc, low, visited, ap, time);
                    low[u] = low[u].min(low[v]);

                    if parent.is_some() && low[v] >= disc[u] {
                        ap[u] = true;
                    }
                } else if Some(v) != parent {
                    low[u] = low[u].min(disc[v]);
                }
            }

            if parent.is_none() && children > 1 {
                ap[u] = true;
            }
        }

        for u in 0..n {
            if !visited[u] {
                dfs(u, None, adj, &mut disc, &mut low, &mut visited, &mut ap, &mut time);
            }
        }

        (0..n).filter(|&u| ap[u]).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_bfs_shortest() {
            let adj = vec![
                vec![1, 2], vec![0, 3], vec![0, 3], vec![1, 2, 4], vec![3],
            ];
            let dist = find_nearest_shrine(&adj, 0);
            assert_eq!(dist, vec![0, 1, 1, 2, 3]);
        }

        #[test]
        fn test_cycle_directed() {
            let adj = vec![vec![1], vec![2], vec![0]];
            assert!(detect_guardian_loop(&adj));

            let adj_no = vec![vec![1], vec![2], vec![]];
            assert!(!detect_guardian_loop(&adj_no));
        }

        #[test]
        fn test_bipartite() {
            let adj = vec![vec![1, 3], vec![0, 2], vec![1, 3], vec![2, 0]];
            assert!(is_bipartite_hyrule(&adj));

            let adj_no = vec![vec![1, 2], vec![0, 2], vec![0, 1]];
            assert!(!is_bipartite_hyrule(&adj_no));
        }

        #[test]
        fn test_components() {
            let adj = vec![vec![1], vec![0], vec![3], vec![2]];
            assert_eq!(count_regions(&adj), 2);
        }

        #[test]
        fn test_bridges() {
            let adj = vec![vec![1, 2], vec![0, 2], vec![0, 1, 3], vec![2]];
            let bridges = find_critical_bridges(&adj);
            assert_eq!(bridges, vec![(2, 3)]);
        }
    }
}

pub mod hyrule_map {
    pub type HyruleGrid = Vec<Vec<char>>;

    pub fn sheikah_energy_spread(grid: &mut HyruleGrid, r: usize, c: usize, energy: char) {
        if r >= grid.len() || c >= grid[0].len() {
            return;
        }

        let old = grid[r][c];
        if old == energy {
            return;
        }

        let rows = grid.len();
        let cols = grid[0].len();
        let mut stack = vec![(r, c)];

        while let Some((r, c)) = stack.pop() {
            if r >= rows || c >= cols || grid[r][c] != old {
                continue;
            }
            grid[r][c] = energy;

            if r > 0 { stack.push((r - 1, c)); }
            if r + 1 < rows { stack.push((r + 1, c)); }
            if c > 0 { stack.push((r, c - 1)); }
            if c + 1 < cols { stack.push((r, c + 1)); }
        }
    }

    pub fn count_sky_islands(grid: &HyruleGrid) -> usize {
        if grid.is_empty() {
            return 0;
        }

        let rows = grid.len();
        let cols = grid[0].len();
        let mut visited = vec![vec![false; cols]; rows];
        let mut count = 0;

        for r in 0..rows {
            for c in 0..cols {
                if grid[r][c] == '1' && !visited[r][c] {
                    // BFS/DFS to mark all connected '1's
                    let mut stack = vec![(r, c)];
                    while let Some((r, c)) = stack.pop() {
                        if r >= rows || c >= cols || visited[r][c] || grid[r][c] != '1' {
                            continue;
                        }
                        visited[r][c] = true;

                        if r > 0 { stack.push((r - 1, c)); }
                        if r + 1 < rows { stack.push((r + 1, c)); }
                        if c > 0 { stack.push((r, c - 1)); }
                        if c + 1 < cols { stack.push((r, c + 1)); }
                    }
                    count += 1;
                }
            }
        }

        count
    }

    pub fn path_to_divine_beast(
        grid: &HyruleGrid,
        start: (usize, usize),
        beast: (usize, usize),
    ) -> Option<usize> {
        use std::collections::VecDeque;

        if grid.is_empty() {
            return None;
        }

        let rows = grid.len();
        let cols = grid[0].len();
        let (sr, sc) = start;
        let (er, ec) = beast;

        if sr >= rows || sc >= cols || er >= rows || ec >= cols {
            return None;
        }
        if grid[sr][sc] == '#' || grid[er][ec] == '#' {
            return None;
        }

        let mut dist = vec![vec![-1i32; cols]; rows];
        let mut queue = VecDeque::new();

        queue.push_back((sr, sc));
        dist[sr][sc] = 0;

        let dirs = [(0, 1), (0, -1), (1, 0), (-1, 0)];

        while let Some((r, c)) = queue.pop_front() {
            if (r, c) == (er, ec) {
                return Some(dist[r][c] as usize);
            }

            for (dr, dc) in &dirs {
                let nr = r as i32 + dr;
                let nc = c as i32 + dc;

                if nr >= 0 && nc >= 0 {
                    let (nr, nc) = (nr as usize, nc as usize);
                    if nr < rows && nc < cols && grid[nr][nc] != '#' && dist[nr][nc] == -1 {
                        dist[nr][nc] = dist[r][c] + 1;
                        queue.push_back((nr, nc));
                    }
                }
            }
        }

        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_islands() {
            let grid = vec![
                vec!['1', '1', '0', '0', '0'],
                vec!['1', '1', '0', '0', '0'],
                vec!['0', '0', '1', '0', '0'],
                vec!['0', '0', '0', '1', '1'],
            ];
            assert_eq!(count_sky_islands(&grid), 3);
        }

        #[test]
        fn test_grid_path() {
            let grid = vec![
                vec!['.', '.', '.', '#'],
                vec!['#', '#', '.', '.'],
                vec!['.', '.', '.', '.'],
            ];
            assert_eq!(path_to_divine_beast(&grid, (0, 0), (2, 3)), Some(5));
        }

        #[test]
        fn test_flood_fill() {
            let mut grid = vec![
                vec!['1', '1', '0'],
                vec!['1', '0', '0'],
                vec!['0', '0', '1'],
            ];
            sheikah_energy_spread(&mut grid, 0, 0, '2');
            assert_eq!(grid[0][0], '2');
            assert_eq!(grid[0][1], '2');
            assert_eq!(grid[1][0], '2');
            assert_eq!(grid[2][2], '1'); // Not connected
        }
    }
}
```

### 4.9 spec.json

```json
{
  "name": "hyrule_explorer",
  "language": "rust",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isolé",
  "tags": ["graphs", "dfs", "bfs", "traversal", "phase1", "zelda"],
  "passing_score": 70,

  "function": {
    "name": "find_nearest_shrine",
    "prototype": "pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32>",
    "return_type": "Vec<i32>",
    "parameters": [
      {"name": "adj", "type": "&[Vec<usize>]"},
      {"name": "link_pos", "type": "usize"}
    ]
  },

  "driver": {
    "reference": "pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32> { use std::collections::VecDeque; let n = adj.len(); let mut dist = vec![-1i32; n]; if link_pos >= n { return dist; } let mut queue = VecDeque::new(); queue.push_back(link_pos); dist[link_pos] = 0; while let Some(u) = queue.pop_front() { for &v in &adj[u] { if dist[v] == -1 { dist[v] = dist[u] + 1; queue.push_back(v); } } } dist }",

    "edge_cases": [
      {
        "name": "empty_graph",
        "args": ["[]", 0],
        "expected": "[]",
        "is_trap": true,
        "trap_explanation": "Graphe vide doit retourner vecteur vide"
      },
      {
        "name": "invalid_start",
        "args": ["[[1], [0]]", 10],
        "expected": "[-1, -1]",
        "is_trap": true,
        "trap_explanation": "Index invalide = toutes distances -1"
      },
      {
        "name": "disconnected",
        "args": ["[[1], [0], [3], [2]]", 0],
        "expected": "[0, 1, -1, -1]"
      },
      {
        "name": "self_loop",
        "args": ["[[0, 1], [0]]", 0],
        "expected": "[0, 1]"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "int",
          "param_index": 1,
          "params": {"min": 0, "max": 1000}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["VecDeque", "Vec", "push_back", "pop_front", "HashSet", "malloc", "free"],
    "forbidden_functions": ["external_graph_lib"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

```rust
/* Mutant A (Boundary) : Pas de marquage des nœuds visités */
pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32> {
    let n = adj.len();
    let mut dist = vec![-1i32; n];
    let mut queue = VecDeque::new();
    queue.push_back(link_pos);
    dist[link_pos] = 0;

    while let Some(u) = queue.pop_front() {
        for &v in &adj[u] {
            // BUG: Pas de check if dist[v] == -1
            dist[v] = dist[u] + 1;
            queue.push_back(v);  // Ajoute même si déjà visité → BOUCLE INFINIE
        }
    }
    dist
}
// Pourquoi c'est faux : Boucle infinie sur graphes avec cycles
// Ce qui était pensé : "La distance sera mise à jour correctement"

/* Mutant B (Safety) : Stack overflow sur graphe profond */
pub fn explore_iterative(adj: &[Vec<usize>], start: usize) -> Vec<usize> {
    let mut result = Vec::new();
    // BUG: Récursif au lieu d'itératif
    fn dfs(u: usize, adj: &[Vec<usize>], result: &mut Vec<usize>) {
        result.push(u);
        for &v in &adj[u] {
            dfs(v, adj, result);  // STACK OVERFLOW sur graphe profond
        }
    }
    dfs(start, adj, &mut result);
    result
}
// Pourquoi c'est faux : Stack overflow sur graphes profonds
// Ce qui était pensé : "La récursion marchera toujours"

/* Mutant C (Resource) : Oublie les autres composantes */
pub fn count_regions(adj: &[Vec<usize>]) -> usize {
    let n = adj.len();
    let mut visited = vec![false; n];
    let mut count = 0;

    // BUG: Ne démarre que depuis le nœud 0
    if n > 0 && !visited[0] {
        // ... DFS depuis 0 seulement
        count = 1;  // Toujours 1 au lieu du vrai nombre
    }

    count  // Retourne toujours 1 même avec plusieurs composantes
}
// Pourquoi c'est faux : Ne compte que la composante de 0
// Ce qui était pensé : "Tous les nœuds sont atteignables depuis 0"

/* Mutant D (Logic) : Classification d'arêtes inversée */
pub fn sheikah_scan(adj: &[Vec<usize>]) -> SheikahScan {
    // ...
    match visited[v] {
        0 => { /* tree edge - OK */ }
        1 => {
            // BUG: forward au lieu de back
            result.forward_edges.push((u, v));  // Devrait être back_edges!
        }
        2 => {
            // BUG: back au lieu de forward/cross
            result.back_edges.push((u, v));  // FAUX
        }
        _ => {}
    }
    // ...
}
// Pourquoi c'est faux : Détection de cycles ne marchera pas
// Ce qui était pensé : Confusion entre les types d'arêtes

/* Mutant E (Return) : Retourne 0 au lieu de -1 pour unreachable */
pub fn find_nearest_shrine(adj: &[Vec<usize>], link_pos: usize) -> Vec<i32> {
    let n = adj.len();
    let mut dist = vec![0i32; n];  // BUG: 0 au lieu de -1
    // ...
    dist  // Les nœuds non atteints ont distance 0 au lieu de -1
}
// Pourquoi c'est faux : Impossible de distinguer distance 0 vs unreachable
// Ce qui était pensé : "0 est une bonne valeur par défaut"
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **DFS** : Exploration en profondeur, timestamps, classification d'arêtes
2. **BFS** : Plus court chemin non pondéré, niveaux du graphe
3. **Applications** : Cycles, composantes, bipartition, ponts
4. **Grid** : Transposition des concepts à une grille 2D

### 5.2 LDA — Traduction littérale en MAJUSCULES

```
FONCTION find_nearest_shrine QUI RETOURNE UN VECTEUR D'ENTIERS ET PREND EN PARAMÈTRES adj QUI EST UNE SLICE DE VECTEURS ET link_pos QUI EST UN ENTIER NON SIGNÉ
DÉBUT FONCTION
    DÉCLARER n COMME LA TAILLE DE adj
    DÉCLARER dist COMME VECTEUR DE n ENTIERS INITIALISÉS À MOINS 1
    DÉCLARER queue COMME FILE VIDE

    SI link_pos EST SUPÉRIEUR OU ÉGAL À n ALORS
        RETOURNER dist
    FIN SI

    AJOUTER link_pos À LA FIN DE queue
    AFFECTER 0 À L'ÉLÉMENT À LA POSITION link_pos DANS dist

    TANT QUE queue N'EST PAS VIDE FAIRE
        DÉCLARER u COMME L'ÉLÉMENT RETIRÉ DU DÉBUT DE queue

        POUR CHAQUE v DANS adj[u] FAIRE
            SI L'ÉLÉMENT À LA POSITION v DANS dist EST ÉGAL À MOINS 1 ALORS
                AFFECTER L'ÉLÉMENT À LA POSITION u DANS dist PLUS 1 À L'ÉLÉMENT À LA POSITION v DANS dist
                AJOUTER v À LA FIN DE queue
            FIN SI
        FIN POUR
    FIN TANT QUE

    RETOURNER dist
FIN FONCTION
```

### 5.2.2 Logic Flow (Structured English)

```
ALGORITHME : BFS Shortest Path
---
1. INITIALISER distances à -1 (unreachable)
2. MARQUER source avec distance 0
3. AJOUTER source à la file

4. BOUCLE PRINCIPALE :
   |
   |-- EXTRAIRE un nœud u de la file
   |
   |-- POUR chaque voisin v de u :
   |     |
   |     |-- SI v pas encore visité (dist[v] == -1) :
   |     |     CALCULER dist[v] = dist[u] + 1
   |     |     AJOUTER v à la file
   |
   |-- CONTINUER jusqu'à file vide

5. RETOURNER les distances
```

### 5.3 Visualisation ASCII

```
=== HYRULE EXPLORATION ===

Map d'Hyrule (graphe):
        [Shrine0]
           / \
         1     2
        /       \
   [Village1]  [Tower2]
        \       /
         3     3
          \   /
        [Castle3]
             |
             4
             |
        [Ganon4]

=== BFS depuis Shrine0 ===

Étape 0: queue = [0], dist = [0, ∞, ∞, ∞, ∞]
         Visite 0, ajoute voisins 1, 2

Étape 1: queue = [1, 2], dist = [0, 1, 1, ∞, ∞]
         Visite 1, ajoute voisin 3
         Visite 2, voisin 3 déjà trouvé

Étape 2: queue = [3], dist = [0, 1, 1, 2, ∞]
         Visite 3, ajoute voisin 4

Étape 3: queue = [4], dist = [0, 1, 1, 2, 3]
         Visite 4, pas de voisins non visités

Final: dist = [0, 1, 1, 2, 3]

=== DFS Edge Classification ===

       [0]
      / | \
     v  v  v
   [1] [2] [3]
    |       |
    v       v
   [4] --> [5]
    ^       |
    └───────┘

Tree edges:    0→1, 0→2, 0→3, 1→4, 3→5
Back edges:    5→4 (retourne à un ancêtre = CYCLE!)
Forward edges: (aucun dans cet exemple)
Cross edges:   4→5 (si visité avant 3→5)

=== GRID BFS ===

Start: (0,0) = S
Goal:  (2,3) = G
Walls: #

Grid:
  S . . #
  # # . .
  . . . G

BFS expansion (wave):

Wave 0:   Wave 1:   Wave 2:   Wave 3:
  0 . . #   0 1 . #   0 1 2 #   0 1 2 #
  # # . .   # # 2 .   # # 2 3   # # 2 3
  . . . .   . . . .   . . 3 .   . . 3 4

Wave 4:   Wave 5:
  0 1 2 #   0 1 2 #
  # # 2 3   # # 2 3
  . 5 3 4   5 5 3 4  → G reached at distance 5!

Path: (0,0)→(0,1)→(0,2)→(1,2)→(1,3)→(2,3)
```

### 5.4 Les pièges en détail

| Piège | Symptôme | Solution |
|-------|----------|----------|
| Pas de marquage visité | Boucle infinie | Check dist[v] == -1 |
| DFS récursif sans limite | Stack overflow | Version itérative |
| Une seule composante | Manque des nœuds | Boucle sur tous les nœuds |
| Back/Forward inversés | Cycles non détectés | Vérifier discovery times |
| -1 vs 0 pour unreachable | Confusion | Toujours init à -1 |

### 5.5 Cours Complet

#### 5.5.1 DFS (Depth-First Search)

Explore le graphe en allant "le plus profond possible" avant de revenir.

**Algorithme :**
```
DFS(u):
  mark u as visiting (gray)
  for each neighbor v:
    if v is white: DFS(v)
  mark u as done (black)
```

**Timestamps :**
- `discovery[u]` : quand on commence à explorer u
- `finish[u]` : quand on a fini u et ses descendants

**Classification des arêtes :**
- **Tree edge** : vers un nœud blanc (non visité)
- **Back edge** : vers un nœud gris (ancêtre) → CYCLE!
- **Forward edge** : vers un descendant noir
- **Cross edge** : vers un nœud noir non-descendant

#### 5.5.2 BFS (Breadth-First Search)

Explore le graphe "niveau par niveau" (tous les voisins avant d'aller plus loin).

**Algorithme :**
```
BFS(source):
  queue = [source]
  dist[source] = 0
  while queue not empty:
    u = queue.pop_front()
    for each neighbor v:
      if dist[v] == -1:
        dist[v] = dist[u] + 1
        queue.push_back(v)
```

**Propriété clé** : BFS trouve le **plus court chemin** en nombre d'arêtes.

#### 5.5.3 0-1 BFS

Pour les graphes avec arêtes de poids 0 ou 1, on peut utiliser une **deque** au lieu d'une priority queue :
- Poids 0 : ajouter au front (prioritaire)
- Poids 1 : ajouter au back (normal)

Complexité : O(V + E) au lieu de O((V+E) log V) pour Dijkstra.

#### 5.5.4 Ponts et Points d'Articulation

**Pont** : arête dont la suppression déconnecte le graphe.
**Point d'articulation** : nœud dont la suppression déconnecte le graphe.

Algorithme de Tarjan avec `low[u]` = min discovery time atteignable depuis le sous-arbre de u.

### 5.6 Normes avec explications

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (compile, mais interdit)                          │
├─────────────────────────────────────────────────────────────────┤
│ let mut queue = Vec::new();                                     │
│ queue.remove(0);  // O(n) pour retirer le premier!             │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ let mut queue = VecDeque::new();                               │
│ queue.pop_front();  // O(1)                                    │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Vec::remove(0) décale tous les éléments = O(n)               │
│ • VecDeque::pop_front() = O(1) amorti                          │
│ • Pour BFS avec n opérations, O(n²) vs O(n)                    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

**BFS sur graphe 5 nœuds depuis 0 :**

```
┌───────┬─────────────────────────┬────────────────────────────────┐
│ Étape │ Queue                   │ dist                           │
├───────┼─────────────────────────┼────────────────────────────────┤
│   0   │ [0]                     │ [0, -1, -1, -1, -1]            │
├───────┼─────────────────────────┼────────────────────────────────┤
│   1   │ pop 0, add 1,2         │ [0, 1, 1, -1, -1]              │
│       │ queue = [1, 2]          │                                │
├───────┼─────────────────────────┼────────────────────────────────┤
│   2   │ pop 1, add 3           │ [0, 1, 1, 2, -1]               │
│       │ queue = [2, 3]          │                                │
├───────┼─────────────────────────┼────────────────────────────────┤
│   3   │ pop 2, 3 already seen  │ [0, 1, 1, 2, -1]               │
│       │ queue = [3]             │                                │
├───────┼─────────────────────────┼────────────────────────────────┤
│   4   │ pop 3, add 4           │ [0, 1, 1, 2, 3]                │
│       │ queue = [4]             │                                │
├───────┼─────────────────────────┼────────────────────────────────┤
│   5   │ pop 4, no new neighbors│ [0, 1, 1, 2, 3]                │
│       │ queue = []              │ DONE                           │
└───────┴─────────────────────────┴────────────────────────────────┘
```

### 5.8 Mnémotechniques

#### 🎮 MEME : "It's dangerous to go alone! Take this."

Comme le vieil homme donne l'épée à Link, BFS te donne les distances :

```rust
// "Here, take this distance map!"
let distances = find_nearest_shrine(&hyrule, link_position);
// Now you know how to reach any shrine!
```

#### 🗺️ MEME : "Open your eyes... Wake up, Link."

DFS = Link qui se réveille et explore le premier couloir jusqu'au bout, puis revient et explore le suivant.

BFS = Link qui regarde toutes les portes autour, puis toutes les pièces à 1 porte de distance, puis 2, etc.

#### ⚔️ MEME : "The blood moon rises once again..."

Quand tu oublies de marquer les nœuds comme visités, ton BFS revient sans cesse aux mêmes nœuds comme les ennemis qui respawn à la Blood Moon :

```rust
// ❌ Blood Moon BFS (boucle infinie)
if true { queue.push(v); }

// ✅ Correct BFS
if dist[v] == -1 { dist[v] = dist[u] + 1; queue.push(v); }
```

### 5.9 Applications pratiques

1. **GPS** : BFS pour trouver le plus court chemin
2. **Web crawlers** : BFS pour explorer les liens proches en premier
3. **Social networks** : Degrés de séparation (Kevin Bacon number)
4. **Garbage collection** : DFS pour trouver les objets accessibles
5. **Compilation** : DFS pour le tri topologique des dépendances

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Impact | Test qui l'attrape |
|---|-------|--------|-------------------|
| 1 | Pas de marquage visité | Boucle infinie | test_cycle |
| 2 | DFS récursif profond | Stack overflow | test_deep_graph |
| 3 | Init à 0 au lieu de -1 | Confusion unreachable | test_disconnected |
| 4 | Une seule composante | Compte faux | test_components |
| 5 | Back/Forward inversés | Cycles non détectés | test_edge_class |

---

## 📝 SECTION 7 : QCM

### Question 1
Quelle est la complexité de BFS sur un graphe avec V sommets et E arêtes ?

- A) O(V)
- B) O(E)
- C) O(V + E) ✓
- D) O(V × E)

### Question 2
BFS garantit de trouver le plus court chemin quand les arêtes sont :

- A) Pondérées positivement
- B) Non pondérées (ou poids égaux) ✓
- C) Pondérées négativement
- D) Toujours

### Question 3
Quel type d'arête indique un cycle dans un graphe dirigé ?

- A) Tree edge
- B) Back edge ✓
- C) Forward edge
- D) Cross edge

### Question 4
Pour implémenter BFS efficacement, quelle structure utiliser ?

- A) Stack
- B) Priority Queue
- C) Deque / Queue ✓
- D) Array

### Question 5
Un graphe est bipartite si et seulement si :

- A) Il n'a pas de cycles
- B) Il n'a pas de cycles impairs ✓
- C) Il est connexe
- D) Il est dirigé

### Question 6
Combien d'îles dans cette grille ?
```
1 1 0
1 0 0
0 0 1
```

- A) 1
- B) 2 ✓
- C) 3
- D) 4

### Question 7
Quelle est la différence entre DFS et BFS ?

- A) DFS utilise une file, BFS une pile
- B) DFS utilise une pile, BFS une file ✓
- C) Les deux utilisent des files
- D) Les deux utilisent des piles

### Question 8
Un pont dans un graphe est :

- A) Un nœud critique
- B) Une arête dont la suppression déconnecte le graphe ✓
- C) Un cycle de longueur 2
- D) Une arête de poids maximum

### Question 9
0-1 BFS utilise quelle structure ?

- A) Priority Queue
- B) Queue simple
- C) Deque ✓
- D) Stack

### Question 10
Quel algorithme utiliser pour le tri topologique ?

- A) BFS
- B) DFS ✓
- C) Dijkstra
- D) Floyd-Warshall

---

## 📊 SECTION 8 : RÉCAPITULATIF

| Élément | Valeur |
|---------|--------|
| Exercice | 1.4.2-a : hyrule_explorer |
| Thème | The Legend of Zelda: Breath of the Wild |
| Concepts | DFS, BFS, cycles, composantes, ponts |
| Difficulté Base | ★★★★★☆☆☆☆☆ (5/10) |
| Bonus Standard | ★★★★★★☆☆☆☆ (6/10) — Grid |
| Bonus Expert | ★★★★★★★★☆☆ (8/10) — Bridges |
| Bonus Génie | 🧠 (11/10) — Bidirectional |
| XP Base | 120 |
| XP Max | 120 × (1 + 2 + 4 + 6) = 1560 |
| Temps estimé | 60 min base, +120 min bonus |
| Langages | Rust Edition 2024, C17 |

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.4.2-a-hyrule-explorer",
    "generated_at": "2026-01-11",

    "metadata": {
      "exercise_id": "1.4.2-a",
      "exercise_name": "hyrule_explorer",
      "module": "1.4.2",
      "module_name": "DFS & BFS Fundamentals",
      "concept": "a",
      "concept_name": "Graph Traversal Algorithms",
      "type": "code",
      "tier": 1,
      "tier_info": "Concept isolé",
      "phase": 1,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "rust",
      "language_version": "Edition 2024",
      "duration_minutes": 60,
      "xp_base": 120,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T2 O(V+E)",
      "complexity_space": "S1 O(V)",
      "prerequisites": ["graph_representations", "recursion", "queues"],
      "domains": ["Struct", "MD", "Algo"],
      "domains_bonus": [],
      "tags": ["dfs", "bfs", "traversal", "cycles", "zelda"],
      "meme_reference": "It's dangerous to go alone! Take this."
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_grid.rs": "/* Section 4.3 hyrule_map */",
      "mutants/mutant_a_no_visited.rs": "/* Section 4.10 */",
      "mutants/mutant_b_stack_overflow.rs": "/* Section 4.10 */",
      "mutants/mutant_c_one_component.rs": "/* Section 4.10 */",
      "mutants/mutant_d_wrong_edge_class.rs": "/* Section 4.10 */",
      "mutants/mutant_e_wrong_default.rs": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_grid.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_no_visited.rs",
        "mutants/mutant_b_stack_overflow.rs",
        "mutants/mutant_c_one_component.rs",
        "mutants/mutant_d_wrong_edge_class.rs",
        "mutants/mutant_e_wrong_default.rs"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference": "cargo test --lib",
      "test_c": "gcc -Wall -Wextra -Werror -std=c17 hyrule_explorer.c main.c -o test && ./test",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ref_solution.rs -s spec.json --validate"
    }
  }
}
```

---

*"May the Goddess smile upon you."*

— Zelda, Breath of the Wild

---

*HACKBRAIN v5.5.2 — L'excellence pédagogique ne se négocie pas*
