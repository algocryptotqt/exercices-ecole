<thinking>
## Analyse du Concept
- Concept : Bipartite Matching & Graph Coloring
- Phase demandée : 1
- Adapté ? OUI - Les algorithmes de matching et coloring sont fondamentaux en théorie des graphes

## Combo Base + Bonus
- Exercice de base : Implémenter matching biparti, stable matching, greedy coloring, interval coloring
- Bonus : Hopcroft-Karp O(E√V), Hungarian O(V³), chromatic number exact, Blossom algorithm
- Palier bonus : 🧠 Génie (Hungarian et Blossom sont complexes)
- Progression logique ? OUI - base → algorithmes optimisés → problèmes NP-hard

## Prérequis & Difficulté
- Prérequis réels : BFS/DFS, graphes bipartis, complexité algorithmique
- Difficulté estimée : 5/10 (base), 12/10 (bonus)
- Cohérent avec phase ? OUI

## Aspect Fun/Culture
- Contexte choisi : "Wedding Planning Simulator" - Cupid's Algorithm
- MEME mnémotechnique : "You may now kiss the bride" pour stable matching
- Pourquoi c'est fun : Le "Stable Marriage Problem" porte littéralement ce nom, table seating est un problème classique de graph coloring, et l'optimisation de budget est Hungarian algorithm

## Scénarios d'Échec (5 mutants)
1. Mutant A (Boundary) : Ne pas gérer le cas où left_size != right_size dans matching
2. Mutant B (Safety) : Oublier de vérifier si le graphe est bien biparti avant matching
3. Mutant C (Logic) : Inverser les préférences dans Gale-Shapley (proposer dans le mauvais ordre)
4. Mutant D (Coloring) : Utiliser la même couleur pour des voisins adjacents
5. Mutant E (Return) : Retourner le nombre de couleurs au lieu du tableau de coloration

## Verdict
VALIDE - Excellente correspondance thématique, analogies parfaites
Note créativité : 97/100
</thinking>

---

# Exercice 1.4.9 : cupids_algorithm

**Module :**
1.4.9 — Bipartite Matching & Graph Coloring

**Concept :**
d-l — Maximum bipartite matching, Hungarian algorithm, Stable matching, Graph coloring

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
complet

**Tiers :**
3 — Synthèse (matching + coloring + scheduling)

**Langage :**
Rust Edition 2024 / C17

**Prérequis :**
- 1.4.1 (Représentation de graphes)
- 1.4.2 (BFS/DFS)
- 1.4.5 (Graphes bipartis)

**Domaines :**
Struct, MD, Probas

**Durée estimée :**
90 min

**XP Base :**
200

**Complexité :**
T4 O(V × E) × S2 O(V)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- `cupids_algorithm.rs` (Rust) ou `cupids_algorithm.c` + `cupids_algorithm.h` (C)

**Fonctions autorisées :**
- Rust : std::collections (Vec, VecDeque, HashMap, HashSet, BinaryHeap)
- C : malloc, free, memset, memcpy

**Fonctions interdites :**
- Bibliothèques de graphes externes
- Algorithmes de matching pré-implémentés

### 1.2 Consigne

**💒 CONTEXTE FUN — Wedding Planning Simulator : "L'Algorithme de Cupidon"**

Bienvenue chez **Cupid Corp™**, l'agence matrimoniale la plus algorithmiquement avancée du monde ! Notre IA, surnommée "L'Entremetteur Quantique", doit résoudre les problèmes les plus complexes de l'industrie du mariage :

1. **Le Problème du Mariage Stable** : Comment assortir N personnes proposant avec N personnes recevant des propositions, de sorte qu'aucun couple ne préfère se séparer pour former un nouveau couple ?

2. **Le Casse-tête des Tables** : Comment placer les invités à des tables de sorte qu'aucun ennemi mortel ne soit assis ensemble ? (Tante Gertrude ne doit PAS être près de l'ex de Kevin)

3. **La Planification des Vendeurs** : Le photographe, le DJ, le traiteur... tous ont des créneaux horaires qui se chevauchent. Combien de "ressources" minimum faut-il ?

**Ta mission :**

Implémenter les algorithmes fondamentaux de matching et coloring pour sauver des milliers de mariages !

---

### 1.2.2 Consigne Académique

Le **matching biparti** consiste à trouver un ensemble maximum d'arêtes sans sommets communs dans un graphe biparti. Le **stable matching** (algorithme de Gale-Shapley) garantit qu'aucune paire ne préfère mutuellement se ré-apparier.

Le **graph coloring** assigne des couleurs aux sommets de sorte que deux sommets adjacents n'aient jamais la même couleur. Le **chromatic number** χ(G) est le minimum de couleurs nécessaires.

L'**interval coloring** est un cas spécial où le graphe d'intervalles se chevauche.

---

**Entrée (Matching Biparti) :**
- `left_size` : nombre de sommets à gauche
- `right_size` : nombre de sommets à droite
- `edges` : liste des arêtes (u, v) où u ∈ gauche, v ∈ droite

**Entrée (Stable Matching) :**
- `proposers_prefs` : préférences de chaque proposant (liste ordonnée)
- `receivers_prefs` : préférences de chaque receveur (liste ordonnée)

**Entrée (Graph Coloring) :**
- `adj` : liste d'adjacence du graphe

**Entrée (Interval Coloring) :**
- `intervals` : liste de (start, end)

**Sortie :**
- Matching : (taille, Vec<Option<usize>>) où matching[u] = Some(v)
- Stable Matching : Vec<usize> où result[proposer] = receiver
- Coloring : Vec<usize> où result[v] = color
- Interval : Vec<usize> où result[i] = resource_id

**Contraintes :**
- 1 ≤ n ≤ 1000
- Graphe non orienté pour coloring
- Préférences complètes et strictes pour stable matching

**Exemples :**

| Fonction | Entrée | Sortie | Explication |
|----------|--------|--------|-------------|
| `soulmate_search(3, 3, edges)` | Matching complet | `(3, [Some(0), Some(1), Some(2)])` | Perfect matching |
| `cupids_algorithm(prefs_m, prefs_w)` | Préférences symétriques | `[0, 1, 2]` | Stable pairing |
| `table_seating(C5)` | Cycle impair de 5 | `[0, 1, 0, 1, 2]` | 3 couleurs minimum |
| `vendor_schedule([(1,4),(2,5),(3,6)])` | 3 intervalles chevauchants | `[0, 1, 2]` | 3 ressources |

### 1.3 Prototype

```rust
// ============================================
// BIPARTITE MATCHING
// ============================================

/// Résultat d'un matching biparti
pub struct WeddingMatch {
    pub size: usize,
    pub left_to_right: Vec<Option<usize>>,
    pub right_to_left: Vec<Option<usize>>,
}

/// Maximum bipartite matching via chemins augmentants (Kuhn)
/// Complexité : O(V × E)
pub fn soulmate_search(
    left_size: usize,
    right_size: usize,
    edges: &[(usize, usize)],
) -> WeddingMatch;

/// Vérifie si un perfect matching existe
pub fn perfect_match_possible(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> bool;

// ============================================
// STABLE MATCHING (Gale-Shapley)
// ============================================

/// Algorithme de Gale-Shapley pour le mariage stable
/// Retourne proposers_match[p] = r (proposant p marié à receveur r)
/// Complexité : O(n²)
pub fn cupids_algorithm(
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> Vec<usize>;

/// Vérifie si un matching est stable
pub fn is_marriage_stable(
    matching: &[usize],
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> bool;

// ============================================
// GRAPH COLORING
// ============================================

/// Greedy coloring dans l'ordre des sommets
/// Complexité : O(V + E)
pub fn table_seating(adj: &[Vec<usize>]) -> Vec<usize>;

/// Welsh-Powell : coloring par degré décroissant
pub fn vip_seating(adj: &[Vec<usize>]) -> Vec<usize>;

/// DSatur : coloring par degré de saturation
pub fn drama_free_seating(adj: &[Vec<usize>]) -> Vec<usize>;

/// Vérifie si le graphe est k-colorable
pub fn can_seat_with_k_tables(adj: &[Vec<usize>], k: usize) -> bool;

/// Trouve le nombre chromatique exact (exponentiel!)
pub fn minimum_tables_needed(adj: &[Vec<usize>]) -> usize;

// ============================================
// INTERVAL COLORING
// ============================================

/// Coloring d'intervalles (minimum ressources)
pub fn vendor_schedule(intervals: &[(i64, i64)]) -> Vec<usize>;

/// Nombre minimum de ressources nécessaires
pub fn min_vendors_needed(intervals: &[(i64, i64)]) -> usize;
```

```c
// C17 Prototypes

typedef struct {
    size_t size;
    int *left_to_right;  // -1 si non matché
    int *right_to_left;
} wedding_match_t;

wedding_match_t *soulmate_search(
    size_t left_size,
    size_t right_size,
    const size_t (*edges)[2],
    size_t num_edges
);

int *cupids_algorithm(
    const int *const *proposers_prefs,
    const int *const *receivers_prefs,
    size_t n
);

int *table_seating(const int *const *adj, const size_t *adj_sizes, size_t n);
int *vendor_schedule(const int (*intervals)[2], size_t n);

void free_wedding_match(wedding_match_t *match);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'Histoire du Stable Marriage Problem

L'algorithme de **Gale-Shapley** a été publié en 1962 et a valu à ses auteurs le **Prix Nobel d'Économie 2012** ! Il est utilisé aujourd'hui pour :

- **NRMP** (National Resident Matching Program) : assigner les médecins résidents aux hôpitaux aux USA
- **Admissions universitaires** en Hongrie et Turquie
- **Kidney Exchange** : matching de donneurs de reins

### 2.2 Le Théorème des Quatre Couleurs

Le **Four Color Theorem** (1976) prouve qu'une carte géographique peut toujours être colorée avec 4 couleurs maximum. C'est le premier théorème majeur prouvé par ordinateur !

### 2.3 Section "DANS LA VRAIE VIE"

| Métier | Utilisation | Cas Concret |
|--------|-------------|-------------|
| **Data Scientist** | Stable matching | Recommandation de candidats pour jobs |
| **DevOps** | Interval scheduling | Allocation de ressources cloud |
| **Game Developer** | Graph coloring | Allocation de registres GPU |
| **Network Engineer** | Bipartite matching | Load balancing entre serveurs |
| **Operations Research** | Hungarian algorithm | Optimisation de supply chain |

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
cupids_algorithm.rs  main.rs

$ rustc --edition 2024 -O cupids_algorithm.rs main.rs -o wedding_planner

$ ./wedding_planner
=== Cupid Corp Wedding Planner v1.0 ===

Test 1 - Soulmate Search (Bipartite Matching):
  Left: [Alice, Bob, Charlie]
  Right: [Xavier, Yuki, Zara]
  Edges: Alice-Xavier, Alice-Yuki, Bob-Xavier, Charlie-Zara
  Result: Perfect matching found! Size = 3
  Alice -> Yuki, Bob -> Xavier, Charlie -> Zara
  ✓ PASS

Test 2 - Cupid's Algorithm (Stable Matching):
  Proposers preferences:
    P0: [R1, R0, R2]
    P1: [R0, R1, R2]
    P2: [R0, R1, R2]
  Receivers preferences:
    R0: [P1, P0, P2]
    R1: [P0, P1, P2]
    R2: [P0, P1, P2]
  Result: [1, 0, 2] (P0->R1, P1->R0, P2->R2)
  Stability check: STABLE (no blocking pairs)
  ✓ PASS

Test 3 - Table Seating (Graph Coloring):
  Graph: Pentagon (C5)
  Colors assigned: [0, 1, 0, 1, 2]
  Number of colors: 3
  Valid coloring: YES
  ✓ PASS

Test 4 - Vendor Schedule (Interval Coloring):
  Intervals: [(1,4), (2,5), (3,6), (5,8), (7,9)]
  Max overlap at any point: 3
  Resources assigned: [0, 1, 2, 0, 1]
  ✓ PASS

All tests passed! 💒
```

---

## 🧠 SECTION 3.1 : BONUS GÉNIE (OPTIONNEL)

**Difficulté Bonus :**
🧠 (12/10)

**Récompense :**
XP ×6

**Time Complexity attendue :**
- Hopcroft-Karp : O(E√V)
- Hungarian : O(V³)

**Space Complexity attendue :**
O(V²)

**Domaines Bonus :**
`DP, Optim`

### 3.1.1 Consigne Bonus

**💎 Le Mariage Royal : Optimisation Extrême**

Le Prince et la Princesse de Matchlandia organisent LE mariage du siècle. Mais avec 10,000 invités, les algorithmes naïfs ne suffisent plus !

**Ta mission bonus :**

1. **Hopcroft-Karp** : Accélérer le matching biparti à O(E√V)
2. **Hungarian Algorithm** : Minimiser le coût total du mariage (matching pondéré)
3. **Chromatic Number Exact** : Prouver le nombre minimum de tables
4. **König's Theorem** : Calculer le minimum vertex cover

```rust
// BONUS - Algorithmes avancés

/// Hopcroft-Karp : O(E√V) bipartite matching
pub fn royal_matchmaker(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> WeddingMatch;

/// Hungarian algorithm : O(V³) weighted perfect matching
/// Retourne (coût_total, assignment)
pub fn budget_wedding(cost: &[Vec<i64>]) -> (i64, Vec<usize>);

/// Minimum cost perfect matching
pub fn frugal_wedding(cost: &[Vec<i64>]) -> (i64, Vec<usize>);

/// König's theorem : min vertex cover = max matching in bipartite
pub fn minimum_chaperones(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> Vec<(bool, usize)>;  // (is_left, vertex_id)

/// Maximum independent set in bipartite graph
pub fn guest_vip_list(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> Vec<(bool, usize)>;

/// Chromatic number exact (exponential backtracking)
pub fn exact_table_count(adj: &[Vec<usize>]) -> usize;

/// Chromatic polynomial : nombre de k-colorings
pub fn seating_arrangements(adj: &[Vec<usize>], k: usize) -> i64;
```

### 3.1.2 Ce qui change par rapport à l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Matching | O(VE) Kuhn | O(E√V) Hopcroft-Karp |
| Weighted | Non | O(V³) Hungarian |
| Coloring | Greedy O(V+E) | Exact χ(G) exponential |
| Applications | Basic | König, Vertex Cover |

---

## ✅❌ SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test | Input | Expected | Points |
|------|-------|----------|--------|
| `matching_basic` | K_{3,3} | size=3 | 5 |
| `matching_imperfect` | K_{2,3} | size=2 | 5 |
| `matching_empty` | n=0 | size=0 | 3 |
| `stable_basic` | 3×3 symmetric | stable | 5 |
| `stable_asymmetric` | different prefs | stable | 5 |
| `stable_verify` | known blocking pair | false | 5 |
| `coloring_bipartite` | K_{3,3} | 2 colors | 5 |
| `coloring_odd_cycle` | C5 | 3 colors | 5 |
| `coloring_complete` | K4 | 4 colors | 5 |
| `coloring_valid` | any graph | no adjacent same | 5 |
| `interval_basic` | non-overlapping | 1 resource | 5 |
| `interval_overlap` | max_overlap=3 | 3 resources | 5 |
| `interval_empty` | n=0 | 0 resources | 2 |
| **BONUS** | | | |
| `hopcroft_karp` | large graph | O(E√V) | 10 |
| `hungarian_basic` | 3×3 cost | min_cost=15 | 10 |
| `hungarian_large` | 100×100 | optimal | 10 |
| `chromatic_petersen` | Petersen graph | χ=3 | 5 |

### 4.2 main.rs de test

```rust
use cupids_algorithm::*;

fn main() {
    println!("=== Test Suite: Cupid Corp ===\n");

    // Test 1: Bipartite Matching
    let edges = vec![(0, 0), (0, 1), (1, 0), (2, 2)];
    let result = soulmate_search(3, 3, &edges);
    assert_eq!(result.size, 3);
    println!("✓ Bipartite matching: size = {}", result.size);

    // Test 2: Stable Matching
    let p_prefs = vec![vec![1, 0, 2], vec![0, 1, 2], vec![0, 1, 2]];
    let r_prefs = vec![vec![1, 0, 2], vec![0, 1, 2], vec![0, 1, 2]];
    let matching = cupids_algorithm(&p_prefs, &r_prefs);
    assert!(is_marriage_stable(&matching, &p_prefs, &r_prefs));
    println!("✓ Stable matching: {:?}", matching);

    // Test 3: Graph Coloring (C5)
    let c5 = vec![vec![1, 4], vec![0, 2], vec![1, 3], vec![2, 4], vec![3, 0]];
    let colors = table_seating(&c5);
    let num_colors = colors.iter().max().unwrap() + 1;
    assert_eq!(num_colors, 3);
    // Verify valid coloring
    for (u, neighbors) in c5.iter().enumerate() {
        for &v in neighbors {
            assert_ne!(colors[u], colors[v], "Invalid coloring!");
        }
    }
    println!("✓ C5 coloring: {} colors", num_colors);

    // Test 4: Interval Coloring
    let intervals = vec![(1, 4), (2, 5), (3, 6), (5, 8), (7, 9)];
    let resources = vendor_schedule(&intervals);
    let num_resources = resources.iter().max().unwrap() + 1;
    assert_eq!(num_resources, 3);
    println!("✓ Interval coloring: {} resources", num_resources);

    println!("\n=== All tests passed! 💒 ===");
}
```

### 4.3 Solution de référence

```rust
use std::collections::{VecDeque, HashSet};

// ============================================
// BIPARTITE MATCHING (Kuhn's Algorithm)
// ============================================

pub struct WeddingMatch {
    pub size: usize,
    pub left_to_right: Vec<Option<usize>>,
    pub right_to_left: Vec<Option<usize>>,
}

pub fn soulmate_search(
    left_size: usize,
    right_size: usize,
    edges: &[(usize, usize)],
) -> WeddingMatch {
    // Build adjacency list
    let mut adj = vec![vec![]; left_size];
    for &(u, v) in edges {
        if u < left_size && v < right_size {
            adj[u].push(v);
        }
    }

    let mut left_to_right = vec![None; left_size];
    let mut right_to_left = vec![None; right_size];
    let mut size = 0;

    for u in 0..left_size {
        let mut visited = vec![false; right_size];
        if dfs_augment(u, &adj, &mut left_to_right, &mut right_to_left, &mut visited) {
            size += 1;
        }
    }

    WeddingMatch { size, left_to_right, right_to_left }
}

fn dfs_augment(
    u: usize,
    adj: &[Vec<usize>],
    left_to_right: &mut [Option<usize>],
    right_to_left: &mut [Option<usize>],
    visited: &mut [bool],
) -> bool {
    for &v in &adj[u] {
        if visited[v] {
            continue;
        }
        visited[v] = true;

        if right_to_left[v].is_none() ||
           dfs_augment(right_to_left[v].unwrap(), adj, left_to_right, right_to_left, visited) {
            left_to_right[u] = Some(v);
            right_to_left[v] = Some(u);
            return true;
        }
    }
    false
}

pub fn perfect_match_possible(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> bool {
    if left_size != right_size {
        return false;
    }
    let edges: Vec<(usize, usize)> = adj.iter()
        .enumerate()
        .flat_map(|(u, neighbors)| neighbors.iter().map(move |&v| (u, v)))
        .collect();
    let result = soulmate_search(left_size, right_size, &edges);
    result.size == left_size
}

// ============================================
// STABLE MATCHING (Gale-Shapley)
// ============================================

pub fn cupids_algorithm(
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> Vec<usize> {
    let n = proposers_prefs.len();
    if n == 0 {
        return vec![];
    }

    // Build inverse preference list for receivers
    let mut receiver_rank: Vec<Vec<usize>> = vec![vec![0; n]; n];
    for (r, prefs) in receivers_prefs.iter().enumerate() {
        for (rank, &p) in prefs.iter().enumerate() {
            receiver_rank[r][p] = rank;
        }
    }

    let mut proposer_match = vec![None; n];
    let mut receiver_match = vec![None; n];
    let mut next_proposal = vec![0usize; n];
    let mut free_proposers: VecDeque<usize> = (0..n).collect();

    while let Some(p) = free_proposers.pop_front() {
        if next_proposal[p] >= n {
            continue;
        }

        let r = proposers_prefs[p][next_proposal[p]];
        next_proposal[p] += 1;

        if let Some(current_p) = receiver_match[r] {
            // r is already matched, compare
            if receiver_rank[r][p] < receiver_rank[r][current_p] {
                // r prefers p over current partner
                receiver_match[r] = Some(p);
                proposer_match[p] = Some(r);
                proposer_match[current_p] = None;
                free_proposers.push_back(current_p);
            } else {
                // r rejects p
                free_proposers.push_back(p);
            }
        } else {
            // r is free
            receiver_match[r] = Some(p);
            proposer_match[p] = Some(r);
        }
    }

    proposer_match.into_iter().map(|x| x.unwrap_or(0)).collect()
}

pub fn is_marriage_stable(
    matching: &[usize],
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> bool {
    let n = matching.len();
    if n == 0 {
        return true;
    }

    // Build inverse matching
    let mut receiver_match = vec![0; n];
    for (p, &r) in matching.iter().enumerate() {
        receiver_match[r] = p;
    }

    // Check for blocking pairs
    for p in 0..n {
        let current_r = matching[p];
        let p_rank_current = proposers_prefs[p].iter().position(|&x| x == current_r).unwrap();

        // Check all receivers that p prefers over current match
        for &r in &proposers_prefs[p][..p_rank_current] {
            let r_current_p = receiver_match[r];
            let r_rank_p = receivers_prefs[r].iter().position(|&x| x == p).unwrap();
            let r_rank_current = receivers_prefs[r].iter().position(|&x| x == r_current_p).unwrap();

            if r_rank_p < r_rank_current {
                // Blocking pair: p and r prefer each other
                return false;
            }
        }
    }

    true
}

// ============================================
// GRAPH COLORING
// ============================================

pub fn table_seating(adj: &[Vec<usize>]) -> Vec<usize> {
    let n = adj.len();
    if n == 0 {
        return vec![];
    }

    let mut colors = vec![usize::MAX; n];

    for v in 0..n {
        let mut used = HashSet::new();
        for &u in &adj[v] {
            if colors[u] != usize::MAX {
                used.insert(colors[u]);
            }
        }

        // Find smallest available color
        let mut c = 0;
        while used.contains(&c) {
            c += 1;
        }
        colors[v] = c;
    }

    colors
}

pub fn vip_seating(adj: &[Vec<usize>]) -> Vec<usize> {
    let n = adj.len();
    if n == 0 {
        return vec![];
    }

    // Sort vertices by degree (descending)
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| adj[b].len().cmp(&adj[a].len()));

    let mut colors = vec![usize::MAX; n];

    for &v in &order {
        let mut used = HashSet::new();
        for &u in &adj[v] {
            if colors[u] != usize::MAX {
                used.insert(colors[u]);
            }
        }

        let mut c = 0;
        while used.contains(&c) {
            c += 1;
        }
        colors[v] = c;
    }

    colors
}

pub fn drama_free_seating(adj: &[Vec<usize>]) -> Vec<usize> {
    let n = adj.len();
    if n == 0 {
        return vec![];
    }

    let mut colors = vec![usize::MAX; n];
    let mut saturation = vec![HashSet::new(); n];
    let mut colored = vec![false; n];

    for _ in 0..n {
        // Find uncolored vertex with max saturation, tie-break by degree
        let v = (0..n)
            .filter(|&i| !colored[i])
            .max_by_key(|&i| (saturation[i].len(), adj[i].len()))
            .unwrap();

        // Assign smallest available color
        let mut c = 0;
        while saturation[v].contains(&c) {
            c += 1;
        }
        colors[v] = c;
        colored[v] = true;

        // Update saturation of neighbors
        for &u in &adj[v] {
            saturation[u].insert(c);
        }
    }

    colors
}

pub fn can_seat_with_k_tables(adj: &[Vec<usize>], k: usize) -> bool {
    let n = adj.len();
    if n == 0 {
        return true;
    }
    if k == 0 {
        return false;
    }

    let mut colors = vec![usize::MAX; n];
    backtrack_color(0, &mut colors, adj, k)
}

fn backtrack_color(v: usize, colors: &mut [usize], adj: &[Vec<usize>], k: usize) -> bool {
    if v == colors.len() {
        return true;
    }

    let mut used = HashSet::new();
    for &u in &adj[v] {
        if colors[u] != usize::MAX {
            used.insert(colors[u]);
        }
    }

    for c in 0..k {
        if !used.contains(&c) {
            colors[v] = c;
            if backtrack_color(v + 1, colors, adj, k) {
                return true;
            }
            colors[v] = usize::MAX;
        }
    }

    false
}

pub fn minimum_tables_needed(adj: &[Vec<usize>]) -> usize {
    let n = adj.len();
    if n == 0 {
        return 0;
    }

    // Binary search or linear search for chromatic number
    for k in 1..=n {
        if can_seat_with_k_tables(adj, k) {
            return k;
        }
    }
    n
}

// ============================================
// INTERVAL COLORING
// ============================================

pub fn vendor_schedule(intervals: &[(i64, i64)]) -> Vec<usize> {
    let n = intervals.len();
    if n == 0 {
        return vec![];
    }

    // Create events: (time, is_start, interval_idx)
    let mut events: Vec<(i64, bool, usize)> = Vec::new();
    for (i, &(start, end)) in intervals.iter().enumerate() {
        events.push((start, true, i));
        events.push((end, false, i));
    }

    // Sort by time, ends before starts at same time
    events.sort_by(|a, b| {
        if a.0 != b.0 {
            a.0.cmp(&b.0)
        } else {
            a.1.cmp(&b.1) // false (end) < true (start)
        }
    });

    let mut result = vec![0; n];
    let mut available: Vec<usize> = vec![];
    let mut next_resource = 0;

    for (_, is_start, idx) in events {
        if is_start {
            let resource = if let Some(r) = available.pop() {
                r
            } else {
                let r = next_resource;
                next_resource += 1;
                r
            };
            result[idx] = resource;
        } else {
            available.push(result[idx]);
        }
    }

    result
}

pub fn min_vendors_needed(intervals: &[(i64, i64)]) -> usize {
    if intervals.is_empty() {
        return 0;
    }

    let resources = vendor_schedule(intervals);
    resources.iter().max().map(|&x| x + 1).unwrap_or(0)
}
```

### 4.4 Solutions alternatives acceptées

```rust
// Alternative 1: Matching via BFS au lieu de DFS
pub fn soulmate_search_bfs(
    left_size: usize,
    right_size: usize,
    edges: &[(usize, usize)],
) -> WeddingMatch {
    // BFS-based augmenting paths
    // Equivalent correctness, different traversal order
    // ... implementation ...
}

// Alternative 2: Coloring with different tie-breaking
pub fn table_seating_alt(adj: &[Vec<usize>]) -> Vec<usize> {
    // Process in reverse order or random order
    // Still valid greedy coloring
    // ... implementation ...
}
```

### 4.5 Solutions refusées

```rust
// REFUSÉE: Ne vérifie pas la validité de la coloration
pub fn table_seating_wrong(adj: &[Vec<usize>]) -> Vec<usize> {
    // Assigne des couleurs aléatoires sans vérifier les conflits
    (0..adj.len()).map(|i| i % 3).collect()  // FAUX!
}
// Pourquoi refusée: Ne garantit pas que voisins ont couleurs différentes

// REFUSÉE: Stable matching sans vérifier les blocking pairs
pub fn cupids_wrong(p: &[Vec<usize>], r: &[Vec<usize>]) -> Vec<usize> {
    // Simple greedy sans Gale-Shapley
    (0..p.len()).collect()  // FAUX!
}
// Pourquoi refusée: Ne garantit pas la stabilité
```

### 4.6 Solution bonus de référence

```rust
// ============================================
// BONUS: Hopcroft-Karp O(E√V)
// ============================================

pub fn royal_matchmaker(
    left_size: usize,
    right_size: usize,
    adj: &[Vec<usize>],
) -> WeddingMatch {
    let mut left_match = vec![None; left_size];
    let mut right_match = vec![None; right_size];

    loop {
        // BFS to find layered graph
        let mut dist = vec![usize::MAX; left_size];
        let mut queue = VecDeque::new();

        for u in 0..left_size {
            if left_match[u].is_none() {
                dist[u] = 0;
                queue.push_back(u);
            }
        }

        let mut found = false;
        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                if let Some(u2) = right_match[v] {
                    if dist[u2] == usize::MAX {
                        dist[u2] = dist[u] + 1;
                        queue.push_back(u2);
                    }
                } else {
                    found = true;
                }
            }
        }

        if !found {
            break;
        }

        // DFS to find augmenting paths
        for u in 0..left_size {
            if left_match[u].is_none() {
                hopcroft_dfs(u, &adj, &mut left_match, &mut right_match, &mut dist);
            }
        }
    }

    let size = left_match.iter().filter(|x| x.is_some()).count();
    WeddingMatch {
        size,
        left_to_right: left_match,
        right_to_left: right_match,
    }
}

fn hopcroft_dfs(
    u: usize,
    adj: &[Vec<usize>],
    left_match: &mut [Option<usize>],
    right_match: &mut [Option<usize>],
    dist: &mut [usize],
) -> bool {
    for &v in &adj[u] {
        if let Some(u2) = right_match[v] {
            if dist[u2] == dist[u] + 1 && hopcroft_dfs(u2, adj, left_match, right_match, dist) {
                left_match[u] = Some(v);
                right_match[v] = Some(u);
                return true;
            }
        } else {
            left_match[u] = Some(v);
            right_match[v] = Some(u);
            return true;
        }
    }
    dist[u] = usize::MAX;
    false
}

// ============================================
// BONUS: Hungarian Algorithm O(V³)
// ============================================

pub fn budget_wedding(cost: &[Vec<i64>]) -> (i64, Vec<usize>) {
    let n = cost.len();
    if n == 0 {
        return (0, vec![]);
    }

    let mut u = vec![0i64; n + 1];
    let mut v = vec![0i64; n + 1];
    let mut p = vec![0usize; n + 1];
    let mut way = vec![0usize; n + 1];

    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0usize;
        let mut minv = vec![i64::MAX; n + 1];
        let mut used = vec![false; n + 1];

        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = i64::MAX;
            let mut j1 = 0usize;

            for j in 1..=n {
                if !used[j] {
                    let cur = cost[i0 - 1][j - 1] - u[i0] - v[j];
                    if cur < minv[j] {
                        minv[j] = cur;
                        way[j] = j0;
                    }
                    if minv[j] < delta {
                        delta = minv[j];
                        j1 = j;
                    }
                }
            }

            for j in 0..=n {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }

            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }

        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }

    let mut assignment = vec![0; n];
    for j in 1..=n {
        if p[j] != 0 {
            assignment[p[j] - 1] = j - 1;
        }
    }

    let total_cost: i64 = assignment.iter()
        .enumerate()
        .map(|(i, &j)| cost[i][j])
        .sum();

    (total_cost, assignment)
}

pub fn frugal_wedding(cost: &[Vec<i64>]) -> (i64, Vec<usize>) {
    // For minimum cost, negate and find maximum
    let neg_cost: Vec<Vec<i64>> = cost.iter()
        .map(|row| row.iter().map(|&x| -x).collect())
        .collect();
    let (neg_total, assignment) = budget_wedding(&neg_cost);
    (-neg_total, assignment)
}
```

### 4.9 spec.json

```json
{
  "name": "cupids_algorithm",
  "language": "rust",
  "version": "2024",
  "type": "complet",
  "tier": 3,
  "tier_info": "Synthèse (matching + coloring + scheduling)",
  "tags": ["graphs", "matching", "coloring", "optimization", "phase1"],
  "passing_score": 70,

  "functions": [
    {
      "name": "soulmate_search",
      "prototype": "pub fn soulmate_search(left_size: usize, right_size: usize, edges: &[(usize, usize)]) -> WeddingMatch",
      "return_type": "WeddingMatch",
      "parameters": [
        {"name": "left_size", "type": "usize"},
        {"name": "right_size", "type": "usize"},
        {"name": "edges", "type": "&[(usize, usize)]"}
      ]
    },
    {
      "name": "cupids_algorithm",
      "prototype": "pub fn cupids_algorithm(proposers_prefs: &[Vec<usize>], receivers_prefs: &[Vec<usize>]) -> Vec<usize>",
      "return_type": "Vec<usize>",
      "parameters": [
        {"name": "proposers_prefs", "type": "&[Vec<usize>]"},
        {"name": "receivers_prefs", "type": "&[Vec<usize>]"}
      ]
    },
    {
      "name": "table_seating",
      "prototype": "pub fn table_seating(adj: &[Vec<usize>]) -> Vec<usize>",
      "return_type": "Vec<usize>",
      "parameters": [
        {"name": "adj", "type": "&[Vec<usize>]"}
      ]
    },
    {
      "name": "vendor_schedule",
      "prototype": "pub fn vendor_schedule(intervals: &[(i64, i64)]) -> Vec<usize>",
      "return_type": "Vec<usize>",
      "parameters": [
        {"name": "intervals", "type": "&[(i64, i64)]"}
      ]
    }
  ],

  "driver": {
    "edge_cases": [
      {
        "name": "matching_empty",
        "function": "soulmate_search",
        "args": [0, 0, []],
        "expected": {"size": 0},
        "is_trap": true,
        "trap_explanation": "Empty graph should return empty matching"
      },
      {
        "name": "matching_perfect",
        "function": "soulmate_search",
        "args": [3, 3, [[0,0], [0,1], [1,0], [1,2], [2,1], [2,2]]],
        "expected": {"size": 3}
      },
      {
        "name": "matching_imperfect",
        "function": "soulmate_search",
        "args": [3, 2, [[0,0], [1,0], [2,1]]],
        "expected": {"size": 2}
      },
      {
        "name": "stable_empty",
        "function": "cupids_algorithm",
        "args": [[], []],
        "expected": [],
        "is_trap": true
      },
      {
        "name": "stable_basic",
        "function": "cupids_algorithm",
        "args": [[[0,1,2], [1,0,2], [0,1,2]], [[1,0,2], [0,1,2], [0,1,2]]],
        "expected_property": "stable"
      },
      {
        "name": "coloring_bipartite",
        "function": "table_seating",
        "args": [[[1,2], [0,2], [0,1]]],
        "expected_max_color": 1
      },
      {
        "name": "coloring_c5",
        "function": "table_seating",
        "args": [[[1,4], [0,2], [1,3], [2,4], [3,0]]],
        "expected_colors": 3
      },
      {
        "name": "interval_empty",
        "function": "vendor_schedule",
        "args": [[]],
        "expected": [],
        "is_trap": true
      },
      {
        "name": "interval_overlap_3",
        "function": "vendor_schedule",
        "args": [[[1,4], [2,5], [3,6]]],
        "expected_resources": 3
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 500,
      "generators": [
        {
          "function": "soulmate_search",
          "type": "bipartite_graph",
          "params": {"max_left": 50, "max_right": 50, "edge_prob": 0.3}
        },
        {
          "function": "table_seating",
          "type": "random_graph",
          "params": {"max_vertices": 30, "edge_prob": 0.3}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["Vec", "VecDeque", "HashMap", "HashSet", "BinaryHeap"],
    "forbidden_functions": ["petgraph", "graph_matching"],
    "check_complexity": true,
    "max_time_complexity": "O(V*E)",
    "check_memory": true
  },

  "bonus": {
    "enabled": true,
    "tier": "GÉNIE",
    "multiplier": 6,
    "functions": ["royal_matchmaker", "budget_wedding", "exact_table_count"]
  }
}
```

### 4.10 Solutions Mutantes

```rust
/* Mutant A (Boundary): Off-by-one dans le matching */
pub fn soulmate_search_mutant_a(
    left_size: usize,
    right_size: usize,
    edges: &[(usize, usize)],
) -> WeddingMatch {
    let mut adj = vec![vec![]; left_size];
    for &(u, v) in edges {
        if u <= left_size && v <= right_size {  // BUG: <= au lieu de <
            adj[u].push(v);
        }
    }
    // ... rest of implementation
    WeddingMatch { size: 0, left_to_right: vec![], right_to_left: vec![] }
}
// Pourquoi faux: Index out of bounds pour u == left_size
// Misconception: Confusion entre < et <=

/* Mutant B (Safety): Pas de vérification empty */
pub fn cupids_mutant_b(
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> Vec<usize> {
    let n = proposers_prefs.len();
    // BUG: Pas de vérification n == 0
    let mut receiver_rank: Vec<Vec<usize>> = vec![vec![0; n]; n];
    // Panic si n == 0 et on accède à receivers_prefs[0]
    for (r, prefs) in receivers_prefs.iter().enumerate() {
        for (rank, &p) in prefs.iter().enumerate() {
            receiver_rank[r][p] = rank;
        }
    }
    vec![]
}
// Pourquoi faux: Panic sur input vide
// Misconception: Oublier que les vecteurs peuvent être vides

/* Mutant C (Logic): Coloring sans vérifier les voisins */
pub fn table_seating_mutant_c(adj: &[Vec<usize>]) -> Vec<usize> {
    let n = adj.len();
    let mut colors = vec![0; n];

    for v in 0..n {
        colors[v] = v % 3;  // BUG: Assigne cycliquement sans vérifier
    }

    colors
}
// Pourquoi faux: Ne garantit pas que voisins ont couleurs différentes
// Misconception: Croire qu'une formule simple suffit

/* Mutant D (Algorithm): Gale-Shapley inversé */
pub fn cupids_mutant_d(
    proposers_prefs: &[Vec<usize>],
    receivers_prefs: &[Vec<usize>],
) -> Vec<usize> {
    let n = proposers_prefs.len();
    if n == 0 { return vec![]; }

    // BUG: Compare dans le mauvais sens
    let mut receiver_rank: Vec<Vec<usize>> = vec![vec![0; n]; n];
    for (r, prefs) in receivers_prefs.iter().enumerate() {
        for (rank, &p) in prefs.iter().enumerate() {
            receiver_rank[r][p] = rank;
        }
    }

    let mut proposer_match = vec![None; n];
    let mut receiver_match = vec![None; n];
    let mut next = vec![0usize; n];
    let mut free: VecDeque<usize> = (0..n).collect();

    while let Some(p) = free.pop_front() {
        if next[p] >= n { continue; }
        let r = proposers_prefs[p][next[p]];
        next[p] += 1;

        if let Some(cur) = receiver_match[r] {
            if receiver_rank[r][p] > receiver_rank[r][cur] {  // BUG: > au lieu de <
                receiver_match[r] = Some(p);
                proposer_match[p] = Some(r);
                proposer_match[cur] = None;
                free.push_back(cur);
            } else {
                free.push_back(p);
            }
        } else {
            receiver_match[r] = Some(p);
            proposer_match[p] = Some(r);
        }
    }

    proposer_match.into_iter().map(|x| x.unwrap_or(0)).collect()
}
// Pourquoi faux: Compare préférences inversées → matching instable
// Misconception: Confondre "préfère plus" et "préfère moins"

/* Mutant E (Return): Interval coloring retourne mauvais format */
pub fn vendor_schedule_mutant_e(intervals: &[(i64, i64)]) -> Vec<usize> {
    let n = intervals.len();
    if n == 0 { return vec![]; }

    // BUG: Retourne le nombre de ressources au lieu de l'assignment
    let mut max_overlap = 0;
    let mut current = 0;

    let mut events: Vec<(i64, i32)> = Vec::new();
    for &(s, e) in intervals {
        events.push((s, 1));
        events.push((e, -1));
    }
    events.sort();

    for (_, delta) in events {
        current += delta;
        max_overlap = max_overlap.max(current);
    }

    vec![max_overlap as usize; n]  // BUG: Même valeur pour tous
}
// Pourquoi faux: Retourne le count, pas l'assignment par intervalle
// Misconception: Confondre "combien de ressources" et "quelle ressource pour chaque"
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Matching Biparti** : Trouver le maximum d'associations sans conflit
2. **Stable Matching** : Garantir qu'aucune paire ne préfère se ré-apparier
3. **Graph Coloring** : Assigner des étiquettes sans conflit entre voisins
4. **Interval Scheduling** : Optimiser l'allocation de ressources temporelles

### 5.2 LDA — Traduction Littérale

```
FONCTION soulmate_search QUI RETOURNE UN WeddingMatch ET PREND EN PARAMÈTRES
    left_size QUI EST UN ENTIER NON SIGNÉ ET
    right_size QUI EST UN ENTIER NON SIGNÉ ET
    edges QUI EST UNE RÉFÉRENCE VERS UN TABLEAU DE PAIRES D'ENTIERS
DÉBUT FONCTION
    DÉCLARER adj COMME VECTEUR DE VECTEURS D'ENTIERS INITIALISÉ VIDE POUR left_size ÉLÉMENTS

    POUR CHAQUE (u, v) DANS edges FAIRE
        SI u EST INFÉRIEUR À left_size ET v EST INFÉRIEUR À right_size ALORS
            AJOUTER v À adj[u]
        FIN SI
    FIN POUR

    DÉCLARER left_to_right COMME VECTEUR DE Option INITIALISÉ À None POUR left_size ÉLÉMENTS
    DÉCLARER right_to_left COMME VECTEUR DE Option INITIALISÉ À None POUR right_size ÉLÉMENTS
    DÉCLARER size COMME ENTIER INITIALISÉ À 0

    POUR u ALLANT DE 0 À left_size MOINS 1 FAIRE
        DÉCLARER visited COMME VECTEUR DE BOOLÉENS INITIALISÉ À false
        SI dfs_augment(u, adj, left_to_right, right_to_left, visited) RETOURNE VRAI ALORS
            INCRÉMENTER size DE 1
        FIN SI
    FIN POUR

    RETOURNER WeddingMatch AVEC size, left_to_right, right_to_left
FIN FONCTION
```

### 5.2.2.1 Logic Flow

```
ALGORITHME : Gale-Shapley (Stable Marriage)
---
1. INITIALISER tous les proposants comme "libres"
2. INITIALISER toutes les préférences non-proposées

3. BOUCLE TANT QUE il existe un proposant libre avec des préférences restantes :
   a. SÉLECTIONNER un proposant libre p
   b. RÉCUPÉRER le prochain receveur r dans les préférences de p

   c. SI r est libre :
      - APPARIER p et r
      - MARQUER p comme non-libre

   d. SINON (r est déjà apparié avec p') :
      - SI r préfère p à p' :
          - APPARIER p et r
          - LIBÉRER p'
      - SINON :
          - p reste libre et continue

4. RETOURNER l'appariement stable
```

### 5.3 Visualisation ASCII

```
MATCHING BIPARTI (Kuhn's Algorithm)

Gauche          Droite
┌───┐           ┌───┐
│ 0 │──────────→│ 0 │  ← matched
└───┘           └───┘
  │               ↑
  │    ┌──────────┘
  ↓    │
┌───┐  │        ┌───┐
│ 1 │──┴───────→│ 1 │  ← matched
└───┘           └───┘

┌───┐           ┌───┐
│ 2 │──────────→│ 2 │  ← matched
└───┘           └───┘

Chemins augmentants:
  0 ──→ 0  (direct)
  1 ──→ 0 ──→ 1 (augment through 0)
  2 ──→ 2  (direct)

Result: Perfect matching, size = 3
```

```
GRAPH COLORING (Greedy)

Pentagon C5:
      [0]────────[1]
       │╲        ╱│
       │  ╲    ╱  │
       │   [2]    │
       │  ╱    ╲  │
       │╱        ╲│
      [4]────────[3]

Processing order: 0, 1, 2, 3, 4

Step 1: color[0] = 🔴 (first available)
Step 2: color[1] = 🔵 (0 has 🔴)
Step 3: color[2] = 🔴 (1 has 🔵, 0 not neighbor)
Step 4: color[3] = 🔵 (2 has 🔴, 4 not colored yet)
Step 5: color[4] = 🟢 (0 has 🔴, 3 has 🔵)

Result: χ = 3 colors (optimal for odd cycle)
```

```
STABLE MATCHING (Gale-Shapley)

Proposers (P)    Receivers (R)
    P0 ←──────────→ R1
    P1 ←──────────→ R0
    P2 ←──────────→ R2

Round 1: P0 proposes to R1 (first choice) → R1 accepts
Round 2: P1 proposes to R0 (first choice) → R0 accepts
Round 3: P2 proposes to R0 (first choice) → R0 prefers P1, rejects P2
Round 4: P2 proposes to R1 (second choice) → R1 prefers P0, rejects P2
Round 5: P2 proposes to R2 (third choice) → R2 accepts

Final: Stable! No blocking pairs.
```

### 5.4 Les pièges en détail

| Piège | Description | Solution |
|-------|-------------|----------|
| Graphe vide | n=0 cause index out of bounds | Vérifier `if n == 0 { return }` |
| left ≠ right | Perfect matching impossible | Retourner size < min(left, right) |
| Self-loops | u == v dans edges | Ignorer ou filtrer |
| Préférences incomplètes | Pas tous les choix listés | Erreur ou compléter |
| Coloring cycles impairs | Greedy peut donner non-optimal | DSatur ou backtrack |

### 5.5 Cours Complet

#### 5.5.1 Matching Biparti

Un **graphe biparti** G = (L ∪ R, E) a deux ensembles de sommets L et R, où chaque arête connecte un sommet de L à un sommet de R.

Un **matching** M ⊆ E est un ensemble d'arêtes sans sommets communs. Le **maximum matching** maximise |M|.

**Algorithme de Kuhn** (chemins augmentants) :
- Pour chaque sommet libre à gauche, chercher un chemin augmentant via DFS
- Un chemin augmentant alterne arêtes non-matchées et matchées
- Complexité : O(V × E)

**Théorème de König** :
- Dans un graphe biparti : max matching = min vertex cover

#### 5.5.2 Stable Matching

Le **Stable Marriage Problem** : n proposants et n receveurs, chacun avec une liste de préférences stricte.

Un matching est **stable** s'il n'existe pas de "blocking pair" (p, r) où :
- p préfère r à son partenaire actuel
- r préfère p à son partenaire actuel

**Algorithme de Gale-Shapley** :
1. Tant qu'un proposant est libre avec des choix restants
2. Le proposant propose au prochain receveur
3. Le receveur accepte si libre ou si préfère le nouveau
4. Complexité : O(n²)

**Propriétés** :
- Toujours termine avec un matching stable
- Optimal pour les proposants (pessimal pour les receveurs)

#### 5.5.3 Graph Coloring

Une **k-coloration** assigne à chaque sommet une couleur parmi k, telle que les voisins aient des couleurs différentes.

Le **chromatic number** χ(G) est le minimum k pour lequel une k-coloration existe.

**Greedy Coloring** :
- Parcourir les sommets dans un ordre
- Assigner la plus petite couleur disponible
- Complexité : O(V + E), mais pas optimal

**Welsh-Powell** : Trier par degré décroissant avant greedy

**DSatur** : Trier dynamiquement par saturation degree (nombre de couleurs voisines différentes)

**Théorèmes importants** :
- Graphe biparti ⟺ χ = 2
- Graphe planaire ⟹ χ ≤ 4 (Four Color Theorem)
- χ(G) ≤ Δ(G) + 1 (où Δ est le degré maximum)

#### 5.5.4 Interval Coloring

Cas spécial : le **graphe d'intervalles** où deux sommets sont adjacents si leurs intervalles se chevauchent.

**Propriété clé** : Le nombre chromatique = la clique maximum = l'overlap maximum

**Algorithme** :
1. Trier les événements (début/fin) par temps
2. À chaque début, assigner la première ressource libre
3. À chaque fin, libérer la ressource
4. Complexité : O(n log n)

### 5.6 Normes avec explications

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                   │
├─────────────────────────────────────────────────────────────────┤
│ for i in 0..adj.len() { for j in &adj[i] { ... } }              │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ for (i, neighbors) in adj.iter().enumerate() {                  │
│     for &j in neighbors { ... }                                 │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│ • Idiomatique Rust : enumerate() plus clair que indices manuels │
│ • Pattern destructuring : &j évite le double déréférencement    │
│ • Performance : Iterator fusion possible par le compilateur     │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

**Gale-Shapley avec préférences :**
```
P0: [R1, R0, R2]    R0: [P1, P0, P2]
P1: [R0, R1, R2]    R1: [P0, P1, P2]
P2: [R0, R1, R2]    R2: [P0, P1, P2]
```

| Étape | Proposant | Propose à | Résultat | État |
|-------|-----------|-----------|----------|------|
| 1 | P0 | R1 | R1 accepte | P0↔R1 |
| 2 | P1 | R0 | R0 accepte | P0↔R1, P1↔R0 |
| 3 | P2 | R0 | R0 préfère P1, rejette | P2 libre |
| 4 | P2 | R1 | R1 préfère P0, rejette | P2 libre |
| 5 | P2 | R2 | R2 accepte | P0↔R1, P1↔R0, P2↔R2 |

**Final** : `[1, 0, 2]` (P0→R1, P1→R0, P2→R2)

### 5.8 Mnémotechniques

#### 💒 MEME : "You may now kiss the bride"

L'algorithme de Gale-Shapley est littéralement appelé "Stable Marriage" !

```rust
// Le prêtre (algorithme) dit:
// "Si quelqu'un s'oppose à cette union, qu'il parle maintenant"
if !is_marriage_stable(&matching, &proposers, &receivers) {
    // Il y a un blocking pair - mariage annulé!
    panic!("Objection! This marriage is not stable!");
}
// "Je vous déclare stable-ment appariés"
```

#### 🎨 MEME : "I see your true colors"

Le graph coloring, c'est comme révéler la vraie personnalité de chaque sommet.

```rust
// Chaque sommet doit avoir sa propre couleur parmi ses voisins
// Comme dans Mean Girls: "On Wednesdays we wear pink"
// Mais deux filles du même groupe NE PEUVENT PAS porter la même couleur!
```

#### 👰 MEME : "The Bachelor" / "Love is Blind"

Gale-Shapley = émission de dating algorithmique !

```
Chaque proposant fait sa "rose ceremony"
Les receveurs peuvent "switch" si un meilleur candidat arrive
À la fin: tout le monde est apparié, personne ne veut partir!
```

### 5.9 Applications pratiques

1. **NRMP** : Matching médecins-hôpitaux aux USA
2. **College Admissions** : Hongrie, Turquie
3. **Kidney Exchange** : Matching donneurs-receveurs
4. **Job Market** : Matching candidats-entreprises
5. **Register Allocation** : Compilateurs (graph coloring)
6. **Frequency Assignment** : Télécoms (éviter interférences)
7. **Scheduling** : Cours, examens, ressources

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Impact | Détection |
|---|-------|--------|-----------|
| 1 | Graphe vide | Crash | Test n=0 |
| 2 | Perfect matching impossible | Mauvais résultat | Vérifier size < n |
| 3 | Préférences inversées Gale-Shapley | Matching instable | Vérifier is_stable() |
| 4 | Coloring voisins même couleur | Invalid | Vérifier adjacents |
| 5 | Interval events mal triés | Mauvais count | Trier (time, type) |

---

## 📝 SECTION 7 : QCM

### Q1. Complexité de Hopcroft-Karp ?
- A) O(V²)
- B) O(E²)
- C) O(E√V) ✓
- D) O(V × E)
- E) O(V³)

### Q2. Le stable matching de Gale-Shapley est optimal pour ?
- A) Les deux parties
- B) Les proposants ✓
- C) Les receveurs
- D) Personne
- E) Aléatoire

### Q3. Chromatic number d'un graphe biparti ?
- A) 1
- B) 2 ✓
- C) 3
- D) Dépend du graphe
- E) 4

### Q4. Théorème de König relie ?
- A) Coloring et matching
- B) Max matching et min vertex cover ✓
- C) Flow et cut
- D) Path et cycle
- E) Tree et graph

### Q5. Pour interval coloring, le nombre de couleurs égale ?
- A) Le nombre d'intervalles
- B) La longueur max
- C) L'overlap maximum ✓
- D) 2
- E) Le nombre de endpoints

### Q6. Complexité de Hungarian algorithm ?
- A) O(n²)
- B) O(n³) ✓
- C) O(n⁴)
- D) O(n log n)
- E) O(2ⁿ)

### Q7. Un blocking pair dans stable matching signifie ?
- A) Deux personnes non appariées
- B) Deux personnes qui préfèrent mutuellement se ré-apparier ✓
- C) Une personne sans partenaire
- D) Un cycle dans les préférences
- E) Une impasse algorithmique

### Q8. DSatur ordonne les sommets par ?
- A) Degré
- B) Ordre croissant
- C) Saturation degree ✓
- D) Distance à la source
- E) Aléatoirement

### Q9. Four Color Theorem s'applique aux graphes ?
- A) Bipartis
- B) Planaires ✓
- C) Complets
- D) Arbres
- E) Cycles

### Q10. Greedy coloring utilise au plus combien de couleurs ?
- A) χ(G)
- B) Δ(G)
- C) Δ(G) + 1 ✓
- D) n
- E) 4

---

## 📊 SECTION 8 : RÉCAPITULATIF

| Métrique | Valeur |
|----------|--------|
| **Difficulté** | ★★★★★☆☆☆☆☆ (5/10) |
| **Bonus** | 🧠 Génie (12/10) |
| **Lignes de code** | ~300 (base), ~500 (bonus) |
| **Concepts clés** | 4 (matching, stable, coloring, interval) |
| **Algorithmes** | 8+ |
| **Applications** | Nobel Prize 2012 ! |

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.4.9-cupids-algorithm",
    "generated_at": "2026-01-11",

    "metadata": {
      "exercise_id": "1.4.9",
      "exercise_name": "cupids_algorithm",
      "module": "1.4",
      "module_name": "Graphs",
      "concept": "d-l",
      "concept_name": "Bipartite Matching & Graph Coloring",
      "type": "complet",
      "tier": 3,
      "tier_info": "Synthèse",
      "phase": 1,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "rust",
      "language_version": "2024",
      "duration_minutes": 90,
      "xp_base": 200,
      "xp_bonus_multiplier": 6,
      "bonus_tier": "GÉNIE",
      "bonus_icon": "🧠",
      "complexity_time": "T4 O(V×E)",
      "complexity_space": "S2 O(V)",
      "prerequisites": ["1.4.1", "1.4.2", "1.4.5"],
      "domains": ["Struct", "MD", "Probas"],
      "domains_bonus": ["DP", "Optim"],
      "tags": ["graphs", "matching", "coloring", "gale-shapley", "hungarian", "nobel"],
      "meme_reference": "Wedding Planning Simulator - Cupid's Algorithm"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_solution_bonus.rs": "/* Section 4.6 */",
      "alternatives/alt_bfs.rs": "/* Section 4.4 */",
      "mutants/mutant_a_boundary.rs": "/* Section 4.10 */",
      "mutants/mutant_b_safety.rs": "/* Section 4.10 */",
      "mutants/mutant_c_logic.rs": "/* Section 4.10 */",
      "mutants/mutant_d_algorithm.rs": "/* Section 4.10 */",
      "mutants/mutant_e_return.rs": "/* Section 4.10 */",
      "tests/main.rs": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution_bonus.rs",
        "alternatives/alt_bfs.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.rs",
        "mutants/mutant_b_safety.rs",
        "mutants/mutant_c_logic.rs",
        "mutants/mutant_d_algorithm.rs",
        "mutants/mutant_e_return.rs"
      ]
    }
  }
}
```

---

*HACKBRAIN v5.5.2 — "L'excellence pédagogique ne se négocie pas"*
*Exercise 1.4.9 : Cupid's Algorithm — Where Love Meets O(E√V)*
