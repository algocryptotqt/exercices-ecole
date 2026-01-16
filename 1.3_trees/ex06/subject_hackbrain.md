<thinking>
## Analyse du Concept
- Concept : Interval Trees, Range Trees, KD-Trees (queries géométriques et intervalles)
- Phase demandée : 1
- Adapté ? OUI - Structures spatiales essentielles pour jeux, GPS, bases de données géographiques. Concepts 1.3.28-33.

## Combo Base + Bonus
- Exercice de base : Interval Tree (insert, find_overlap, find_all_overlaps, stab query)
- Bonus Standard : Range Tree 2D avec rectangle queries
- Bonus Expert : KD-Tree avec nearest neighbor et k-nearest
- Bonus Génie : Fractional Cascading pour Range Tree O(log n + k)
- Palier bonus : ⚡ Standard → 💀 Expert → 🧠 Génie
- Progression logique ? OUI - 1D intervals → 2D points → k-D space → optimizations

## Prérequis & Difficulté
- Prérequis réels : BST, comparaisons, géométrie basique
- Difficulté estimée : 5/10 (interval), 6/10 (2D range), 7/10 (KD-tree)
- Cohérent avec phase 1 ? OUI

## Aspect Fun/Culture
- Contexte choisi : "Battle Royale Storm Tracker" (Fortnite/PUBG/Apex)
- MEME mnémotechnique : "The Storm is Coming" + "GG EZ"
- Pourquoi c'est fun :
  - Tout le monde connaît les Battle Royale
  - KD-tree = trouver l'ennemi le plus proche
  - Range query = joueurs dans la safe zone
  - Interval tree = phases de la tempête
  - Analogie PARFAITE avec le gameplay !

## Scénarios d'Échec (5 mutants concrets)
1. Mutant A (Boundary) : Overlap check uses < instead of <= (miss adjacent intervals)
2. Mutant B (Safety) : Ne pas mettre à jour max_end lors de l'insertion
3. Mutant C (Resource) : Oublier de propager max_end après delete
4. Mutant D (Logic) : KD-tree split toujours sur même dimension
5. Mutant E (Return) : find_all_overlaps s'arrête après le premier trouvé

## Verdict
VALIDE - L'analogie Battle Royale est parfaite pour les structures spatiales.
Note d'intelligence estimée : 96/100
</thinking>

---

# Exercice 1.3.6-a : storm_circle_tracker

**Module :**
1.3.6 — Interval & Range Trees

**Concept :**
a — Arbres pour requêtes géométriques et intervalles

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isolé

**Langage :**
Rust Edition 2024 / C (c17)

**Prérequis :**
- 1.3.1 (BST basique)
- Notion de coordonnées 2D
- Comparaisons d'intervalles

**Domaines :**
Struct, Algo, Méca

**Durée estimée :**
50 min

**XP Base :**
130

**Complexité :**
T2 O(log n + k) × S2 O(n)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- `storm_circle_tracker.rs` (Rust)
- `storm_circle_tracker.c` + `storm_circle_tracker.h` (C)

**Fonctions autorisées :**
- Rust : `Vec`, `Box`, `Option`, `Ord`, standard library
- C : `malloc`, `free`, `realloc`, `memcpy`

**Fonctions interdites :**
- Bibliothèques géométriques externes
- R-trees ou structures spatiales pré-faites

### 1.2 Consigne

**🎮 CONTEXTE FUN — Battle Royale Storm Tracker**

Tu développes le système de **Storm Tracking** pour un nouveau Battle Royale : **HACKBRAIN: Last Coder Standing**.

Dans ce jeu, 100 développeurs atterrissent sur une île et doivent coder pour survivre. La **Storm Circle** se rétrécit progressivement, et tu dois :

1. **Savoir quels joueurs sont dans la zone de danger** (overlap query)
2. **Trouver l'ennemi le plus proche** (nearest neighbor - bonus)
3. **Tracker les phases de la storm** (interval tree pour les timings)

```
┌────────────────────────────────────────────────────────────────────┐
│  🌀 STORM TRACKER v2.0                                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│       ████████████████████████████████                            │
│       █  DANGER ZONE  █ 💀 Player_42 █                            │
│       █               █████████████████                            │
│       █   🏃 Player_7  ┌───────────┐  █                            │
│       █               │ SAFE ZONE │  █                            │
│       █    💀 Player_3 │  🏃‍♂️ You  │  █                            │
│       █               └───────────┘  █                            │
│       ████████████████████████████████                            │
│                                                                    │
│   Storm Phase 3: 2:30 remaining                                   │
│   Players in zone: 23/100                                         │
│   Nearest enemy: 47m (Player_7)                                   │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

> *"The storm is coming. Better have your Interval Tree ready."*
> — Epic Coder, 2024

**Ta mission :**

Implémenter un **Interval Tree** pour tracker les phases de la storm et détecter les chevauchements :

1. `new()` : Créer un nouveau tracker
2. `insert(interval)` : Ajouter un intervalle (phase de storm, zone d'activité)
3. `find_overlap(query)` : Trouver UN intervalle qui chevauche la requête
4. `find_all_overlaps(query)` : Trouver TOUS les intervalles chevauchants
5. `stab(point)` : Trouver tous les intervalles contenant un point précis
6. `delete(interval)` : Supprimer un intervalle

**Structure Interval :**
```rust
pub struct Interval {
    pub lo: i64,  // Début de l'intervalle
    pub hi: i64,  // Fin de l'intervalle
}
```

**Entrée :**
- `interval` : Un intervalle [lo, hi]
- `query` : Un intervalle pour rechercher les chevauchements
- `point` : Un point pour la "stab query"

**Sortie :**
- `find_overlap` : `Some(&Interval)` si trouvé, `None` sinon
- `find_all_overlaps` : `Vec<&Interval>` de tous les chevauchements
- `stab` : `Vec<&Interval>` des intervalles contenant le point

**Propriétés de l'Interval Tree :**
```
┌─────────────────────────────────────────────────────────────────────┐
│  INTERVAL TREE (augmented BST)                                      │
├─────────────────────────────────────────────────────────────────────┤
│  1. Trié par LOW endpoint (début de l'intervalle)                   │
│  2. Chaque nœud stocke MAX_END du sous-arbre                        │
│  3. max_end = max(interval.hi, left.max_end, right.max_end)         │
│  4. Overlap: a.lo ≤ b.hi AND b.lo ≤ a.hi                            │
│  5. Pruning: si max_end < query.lo → pas de chevauchement possible  │
└─────────────────────────────────────────────────────────────────────┘
```

**Chevauchement de deux intervalles :**
```
[a.lo ─────── a.hi]
           [b.lo ─────── b.hi]

Overlap si et seulement si: a.lo ≤ b.hi AND b.lo ≤ a.hi
```

**Exemples :**

| Opération | Avant | Après/Résultat | Explication |
|-----------|-------|----------------|-------------|
| `insert([10,20])` | vide | tree avec [10,20] | Phase 1 de storm |
| `insert([15,25])` | [10,20] | [10,20], [15,25] | Phase 2 overlap |
| `find_overlap([12,18])` | tree | Some([10,20]) ou Some([15,25]) | Les deux chevauchent |
| `find_all_overlaps([12,18])` | tree | [[10,20], [15,25]] | Tous les chevauchements |
| `stab(17)` | tree | [[10,20], [15,25]] | Les deux contiennent 17 |
| `insert([30,40])` | tree | ajoute [30,40] | Phase 3, pas d'overlap |
| `find_overlap([35,38])` | tree | Some([30,40]) | Seul overlap |

### 1.2.2 Consigne Académique

Un **Interval Tree** est un arbre binaire de recherche augmenté pour stocker des intervalles et répondre efficacement aux requêtes de chevauchement.

**Augmentation :**
Chaque nœud stocke `max_end`, la valeur maximale de `hi` dans son sous-arbre. Cela permet de "pruner" (élaguer) des sous-arbres entiers lors de la recherche.

**Algorithme de recherche d'overlap :**
```
SEARCH_OVERLAP(node, query):
    if node is null:
        return null

    if node.interval overlaps query:
        return node.interval

    if node.left != null AND node.left.max_end >= query.lo:
        result = SEARCH_OVERLAP(node.left, query)
        if result != null:
            return result

    return SEARCH_OVERLAP(node.right, query)
```

**Complexité :**
- Insert : O(log n)
- Find overlap : O(log n)
- Find all overlaps : O(log n + k) où k = nombre de résultats
- Stab : O(log n + k)

### 1.3 Prototype

**Rust :**
```rust
#[derive(Clone, Debug, PartialEq)]
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
    max_end: i64,
    left: Option<Box<ITNode>>,
    right: Option<Box<ITNode>>,
}

pub struct StormCircleTracker {
    root: Option<Box<ITNode>>,
}

impl StormCircleTracker {
    /// Crée un nouveau tracker vide
    pub fn new() -> Self;

    /// Insère un intervalle
    pub fn insert(&mut self, interval: Interval);

    /// Supprime un intervalle
    pub fn delete(&mut self, interval: &Interval) -> bool;

    /// Trouve UN intervalle qui chevauche la requête
    pub fn find_overlap(&self, query: &Interval) -> Option<&Interval>;

    /// Trouve TOUS les intervalles chevauchant la requête
    pub fn find_all_overlaps(&self, query: &Interval) -> Vec<&Interval>;

    /// Trouve tous les intervalles contenant un point
    pub fn stab(&self, point: i64) -> Vec<&Interval>;

    /// Nombre d'intervalles
    pub fn len(&self) -> usize;

    /// Est-ce vide ?
    pub fn is_empty(&self) -> bool;
}
```

**C :**
```c
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct Interval {
    int64_t lo;
    int64_t hi;
} Interval;

typedef struct ITNode {
    Interval interval;
    int64_t max_end;
    struct ITNode *left;
    struct ITNode *right;
} ITNode;

typedef struct StormCircleTracker {
    ITNode *root;
    size_t size;
} StormCircleTracker;

// Interval operations
Interval interval_new(int64_t lo, int64_t hi);
bool interval_overlaps(const Interval *a, const Interval *b);
bool interval_contains_point(const Interval *interval, int64_t point);

// Tracker operations
StormCircleTracker *tracker_new(void);
void tracker_free(StormCircleTracker *tracker);
void tracker_insert(StormCircleTracker *tracker, Interval interval);
bool tracker_delete(StormCircleTracker *tracker, const Interval *interval);

// Queries
const Interval *tracker_find_overlap(const StormCircleTracker *tracker, const Interval *query);
size_t tracker_find_all_overlaps(const StormCircleTracker *tracker, const Interval *query,
                                  const Interval **results, size_t max_results);
size_t tracker_stab(const StormCircleTracker *tracker, int64_t point,
                    const Interval **results, size_t max_results);

// Utilities
size_t tracker_len(const StormCircleTracker *tracker);
bool tracker_is_empty(const StormCircleTracker *tracker);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'Histoire des Interval Trees

Les Interval Trees ont été introduits par **Edelsbrunner** en 1980 pour des problèmes de géométrie computationnelle. Ils sont maintenant utilisés partout : calendriers, bases de données temporelles, jeux vidéo.

### 2.2 Interval Trees vs Segment Trees

| Structure | Stocke | Requête principale |
|-----------|--------|-------------------|
| Interval Tree | Intervalles entiers | "Quels intervalles chevauchent [a,b] ?" |
| Segment Tree | Valeurs à des points | "Quelle est la somme/min/max sur [a,b] ?" |

### 2.3 Le Secret du max_end

Sans `max_end`, on devrait visiter TOUS les nœuds pour trouver les overlaps. Avec `max_end`, on peut "pruner" (élaguer) des sous-arbres entiers !

```
Si node.left.max_end < query.lo:
  → Aucun intervalle dans le sous-arbre gauche ne peut chevaucher query
  → On saute tout le sous-arbre !
```

### 2.5 DANS LA VRAIE VIE

**Qui utilise les Interval Trees au quotidien ?**

| Métier | Utilisation |
|--------|-------------|
| **Game Developer** | Collision detection, spawn zones, event timing |
| **Calendar App Dev** | Trouver les conflits de réunions |
| **Database Engineer** | Temporal databases, time-series queries |
| **Bioinformatician** | Gene overlapping, genome annotation |
| **Network Engineer** | IP range lookups, firewall rules |

**Cas d'usage concret :**
```sql
-- PostgreSQL utilise des structures similaires pour les range types !
SELECT * FROM reservations
WHERE room_id = 42
  AND time_range && '[2024-01-15 10:00, 2024-01-15 12:00]';
-- && est l'opérateur "overlaps" !
```

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
storm_circle_tracker.rs  storm_circle_tracker.c  storm_circle_tracker.h  main.c  main.rs

$ rustc --edition 2024 storm_circle_tracker.rs main.rs -o test_rust

$ ./test_rust
=== Storm Circle Tracker Tests ===
Test interval overlap detection: OK
Test find_overlap: OK
Test find_all_overlaps: OK
Test stab query: OK
Test no overlap: OK
GG! Storm tracker operational.

$ gcc -std=c17 -Wall -Wextra -Werror storm_circle_tracker.c main.c -o test_c

$ ./test_c
[STORM] Running interval tree tests...
Insert test: PASSED
Overlap test: PASSED
Stab test: PASSED
All 3 tests passed! The circle is closing in...
```

### ⚡ SECTION 3.1 : BONUS STANDARD — 2D Range Tree (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Récompense :**
XP ×2

**Time Complexity attendue :**
O(log² n + k) pour rectangle query

**Space Complexity attendue :**
O(n log n)

**Domaines Bonus :**
`Struct, Algo`

#### 3.1.1 Consigne Bonus

**🎮 THE SAFE ZONE SCANNER — 2D Range Tree**

Maintenant tu dois tracker la position des joueurs en 2D ! La Storm Circle est un rectangle (pour simplifier), et tu dois répondre à :
- "Combien de joueurs sont dans la safe zone ?"
- "Qui sont les joueurs dans cette zone ?"

Un **2D Range Tree** est un BST sur X, où chaque nœud contient un BST secondaire sur Y pour les points de son sous-arbre.

```
                [x=5]
               /     \
          [x=2]       [x=8]

Chaque nœud a un "associated structure" (BST sur Y) pour son sous-arbre.
```

**Ta mission :**

Implémenter `SafeZoneScanner` avec :
- `build(points)` : Construire depuis une liste de points 2D
- `count_rect(x1, x2, y1, y2)` : Compter les points dans le rectangle
- `report_rect(x1, x2, y1, y2)` : Lister les points dans le rectangle

#### 3.1.2 Prototype Bonus

```rust
#[derive(Clone, Debug)]
pub struct Point2D {
    pub x: i64,
    pub y: i64,
}

pub struct SafeZoneScanner {
    root: Option<Box<RT2DNode>>,
}

impl SafeZoneScanner {
    pub fn build(points: &[Point2D]) -> Self;
    pub fn count_rect(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> usize;
    pub fn report_rect(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> Vec<&Point2D>;
}
```

---

### 💀 SECTION 3.2 : BONUS EXPERT — KD-Tree (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★☆☆☆ (7/10)

**Récompense :**
XP ×4

**Time Complexity attendue :**
O(√n + k) pour range query, O(log n) pour nearest neighbor (average)

**Domaines Bonus :**
`Struct, Algo, Méca`

#### 3.2.1 Consigne Bonus

**🎮 THE ENEMY RADAR — KD-Tree**

Tu as besoin de savoir qui est l'ennemi le plus proche ! Le **KD-Tree** est parfait pour les requêtes de plus proche voisin en espace multidimensionnel.

En 2D :
- Niveau 0 : split sur X
- Niveau 1 : split sur Y
- Niveau 2 : split sur X
- ...

```
        (7,2) ─── split X
       /     \
    (5,4)   (9,6) ─── split Y
    /   \      \
 (2,3) (4,7)  (8,1) ─── split X
```

**Ta mission :**

Implémenter `EnemyRadar<const D: usize>` avec :
- `build(points)` : Construire depuis des points k-D
- `nearest(query)` : Trouver le point le plus proche
- `k_nearest(query, k)` : Trouver les k plus proches
- `range_search(center, radius)` : Points dans un cercle

#### 3.2.2 Prototype Bonus

```rust
#[derive(Clone, Debug)]
pub struct Point<const D: usize> {
    pub coords: [f64; D],
}

pub struct EnemyRadar<const D: usize> {
    root: Option<Box<KDNode<D>>>,
}

impl<const D: usize> EnemyRadar<D> {
    pub fn build(points: Vec<Point<D>>) -> Self;
    pub fn nearest(&self, query: &Point<D>) -> Option<&Point<D>>;
    pub fn k_nearest(&self, query: &Point<D>, k: usize) -> Vec<&Point<D>>;
    pub fn range_search(&self, center: &Point<D>, radius: f64) -> Vec<&Point<D>>;
}
```

---

### 🧠 SECTION 3.3 : BONUS GÉNIE — Fractional Cascading (OPTIONNEL)

**Difficulté Bonus :**
🧠 (12/10)

**Récompense :**
XP ×6

**Domaines Bonus :**
`Struct, Algo`

#### 3.3.1 Consigne Bonus

Le **Fractional Cascading** est une technique d'optimisation qui réduit le temps de requête 2D de O(log² n) à O(log n + k).

L'idée : au lieu de faire une recherche binaire à chaque niveau, on maintient des "ponts" entre les structures associées.

```
Sans Fractional Cascading: O(log² n)
  → log n nœuds × log n recherche dans chaque BST secondaire

Avec Fractional Cascading: O(log n + k)
  → Les "ponts" permettent de sauter les recherches binaires
```

---

## ✅❌ SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette (tableau des tests)

| Test | Input | Expected Output | Points | Trap |
|------|-------|-----------------|--------|------|
| `new_empty` | `new()` | `is_empty() == true` | 2 | — |
| `interval_overlaps` | [10,20] vs [15,25] | `true` | 3 | — |
| `interval_no_overlap` | [10,20] vs [30,40] | `false` | 3 | — |
| `interval_adjacent` | [10,20] vs [20,30] | `true` (inclusive) | 3 | Boundary |
| `insert_single` | insert [10,20] | find_overlap([15,18]) = Some | 3 | — |
| `find_overlap_none` | tree sans [25,35] | find_overlap([25,35]) = None | 3 | — |
| `find_all_multiple` | 3 overlapping | Vec de taille 3 | 5 | Early exit |
| `stab_in_interval` | stab(15) sur [10,20] | contains [10,20] | 4 | — |
| `stab_boundary` | stab(10) sur [10,20] | contains [10,20] | 3 | Inclusive |
| `stab_outside` | stab(5) sur [10,20] | empty Vec | 3 | — |
| `max_end_update` | insert [10,50], [20,25] | root.max_end = 50 | 5 | Augmentation |
| `delete_and_query` | delete [10,20] | find_overlap = None | 5 | Cleanup |
| `stress_overlaps` | 1000 intervals | correct count | 5 | Performance |

**Total : 47 points (base)**

### 4.2 main.c de test

```c
#include <stdio.h>
#include <assert.h>
#include "storm_circle_tracker.h"

void test_interval_overlap(void) {
    printf("Test interval overlap... ");

    Interval a = interval_new(10, 20);
    Interval b = interval_new(15, 25);
    Interval c = interval_new(30, 40);
    Interval d = interval_new(20, 30);  // Adjacent to a

    assert(interval_overlaps(&a, &b) == true);
    assert(interval_overlaps(&a, &c) == false);
    assert(interval_overlaps(&a, &d) == true);  // Boundary case

    printf("OK\n");
}

void test_find_overlap(void) {
    printf("Test find overlap... ");

    StormCircleTracker *tracker = tracker_new();

    tracker_insert(tracker, interval_new(15, 20));  // Storm Phase 1
    tracker_insert(tracker, interval_new(10, 30));  // Storm Phase 2
    tracker_insert(tracker, interval_new(5, 12));   // Storm Phase 3
    tracker_insert(tracker, interval_new(17, 19));  // Storm Phase 4

    Interval query = interval_new(14, 16);
    const Interval *overlap = tracker_find_overlap(tracker, &query);

    assert(overlap != NULL);
    assert(interval_overlaps(overlap, &query));

    // Query that shouldn't match
    Interval no_match = interval_new(100, 200);
    assert(tracker_find_overlap(tracker, &no_match) == NULL);

    tracker_free(tracker);
    printf("OK\n");
}

void test_find_all_overlaps(void) {
    printf("Test find all overlaps... ");

    StormCircleTracker *tracker = tracker_new();

    tracker_insert(tracker, interval_new(1, 10));
    tracker_insert(tracker, interval_new(5, 15));
    tracker_insert(tracker, interval_new(20, 30));

    Interval query = interval_new(8, 12);
    const Interval *results[10];
    size_t count = tracker_find_all_overlaps(tracker, &query, results, 10);

    assert(count == 2);  // [1,10] and [5,15]

    tracker_free(tracker);
    printf("OK\n");
}

void test_stab(void) {
    printf("Test stab query... ");

    StormCircleTracker *tracker = tracker_new();

    tracker_insert(tracker, interval_new(1, 10));
    tracker_insert(tracker, interval_new(5, 15));
    tracker_insert(tracker, interval_new(12, 20));

    const Interval *results[10];
    size_t count = tracker_stab(tracker, 7, results, 10);
    assert(count == 2);  // [1,10] and [5,15] contain 7

    count = tracker_stab(tracker, 11, results, 10);
    assert(count == 1);  // Only [5,15] contains 11

    count = tracker_stab(tracker, 25, results, 10);
    assert(count == 0);  // No interval contains 25

    tracker_free(tracker);
    printf("OK\n");
}

int main(void) {
    printf("=== Storm Circle Tracker Tests ===\n\n");

    test_interval_overlap();
    test_find_overlap();
    test_find_all_overlaps();
    test_stab();

    printf("\n✓ All tests passed! The storm is under control.\n");
    return 0;
}
```

### 4.3 Solution de référence

**Rust :**
```rust
use std::cmp::max;

#[derive(Clone, Debug, PartialEq)]
pub struct Interval {
    pub lo: i64,
    pub hi: i64,
}

impl Interval {
    pub fn new(lo: i64, hi: i64) -> Self {
        assert!(lo <= hi, "Invalid interval: lo must be <= hi");
        Interval { lo, hi }
    }

    pub fn overlaps(&self, other: &Interval) -> bool {
        self.lo <= other.hi && other.lo <= self.hi
    }

    pub fn contains_point(&self, point: i64) -> bool {
        self.lo <= point && point <= self.hi
    }
}

struct ITNode {
    interval: Interval,
    max_end: i64,
    left: Option<Box<ITNode>>,
    right: Option<Box<ITNode>>,
}

impl ITNode {
    fn new(interval: Interval) -> Self {
        let max_end = interval.hi;
        ITNode {
            interval,
            max_end,
            left: None,
            right: None,
        }
    }

    fn update_max_end(&mut self) {
        self.max_end = self.interval.hi;
        if let Some(ref left) = self.left {
            self.max_end = max(self.max_end, left.max_end);
        }
        if let Some(ref right) = self.right {
            self.max_end = max(self.max_end, right.max_end);
        }
    }
}

pub struct StormCircleTracker {
    root: Option<Box<ITNode>>,
    size: usize,
}

impl StormCircleTracker {
    pub fn new() -> Self {
        StormCircleTracker { root: None, size: 0 }
    }

    pub fn insert(&mut self, interval: Interval) {
        self.root = Self::insert_rec(self.root.take(), interval);
        self.size += 1;
    }

    fn insert_rec(node: Option<Box<ITNode>>, interval: Interval) -> Option<Box<ITNode>> {
        match node {
            None => Some(Box::new(ITNode::new(interval))),
            Some(mut n) => {
                if interval.lo < n.interval.lo {
                    n.left = Self::insert_rec(n.left.take(), interval);
                } else {
                    n.right = Self::insert_rec(n.right.take(), interval);
                }
                n.update_max_end();
                Some(n)
            }
        }
    }

    pub fn delete(&mut self, interval: &Interval) -> bool {
        let (new_root, deleted) = Self::delete_rec(self.root.take(), interval);
        self.root = new_root;
        if deleted {
            self.size -= 1;
        }
        deleted
    }

    fn delete_rec(node: Option<Box<ITNode>>, interval: &Interval) -> (Option<Box<ITNode>>, bool) {
        match node {
            None => (None, false),
            Some(mut n) => {
                if n.interval == *interval {
                    // Found the node to delete
                    match (n.left.take(), n.right.take()) {
                        (None, None) => (None, true),
                        (Some(left), None) => (Some(left), true),
                        (None, Some(right)) => (Some(right), true),
                        (Some(left), Some(right)) => {
                            // Find minimum in right subtree
                            let (new_right, min_interval) = Self::extract_min(right);
                            n.interval = min_interval;
                            n.left = Some(left);
                            n.right = new_right;
                            n.update_max_end();
                            (Some(n), true)
                        }
                    }
                } else if interval.lo < n.interval.lo {
                    let (new_left, deleted) = Self::delete_rec(n.left.take(), interval);
                    n.left = new_left;
                    n.update_max_end();
                    (Some(n), deleted)
                } else {
                    let (new_right, deleted) = Self::delete_rec(n.right.take(), interval);
                    n.right = new_right;
                    n.update_max_end();
                    (Some(n), deleted)
                }
            }
        }
    }

    fn extract_min(node: Box<ITNode>) -> (Option<Box<ITNode>>, Interval) {
        let mut current = node;
        if current.left.is_none() {
            let interval = current.interval.clone();
            (current.right.take(), interval)
        } else {
            let (new_left, min_interval) = Self::extract_min(current.left.take().unwrap());
            current.left = new_left;
            current.update_max_end();
            (Some(current), min_interval)
        }
    }

    pub fn find_overlap(&self, query: &Interval) -> Option<&Interval> {
        Self::find_overlap_rec(self.root.as_ref(), query)
    }

    fn find_overlap_rec<'a>(node: Option<&'a Box<ITNode>>, query: &Interval) -> Option<&'a Interval> {
        let node = node?;

        // Check if current interval overlaps
        if node.interval.overlaps(query) {
            return Some(&node.interval);
        }

        // Check left subtree if it might contain overlapping intervals
        if let Some(ref left) = node.left {
            if left.max_end >= query.lo {
                if let Some(result) = Self::find_overlap_rec(Some(left), query) {
                    return Some(result);
                }
            }
        }

        // Check right subtree
        Self::find_overlap_rec(node.right.as_ref(), query)
    }

    pub fn find_all_overlaps(&self, query: &Interval) -> Vec<&Interval> {
        let mut results = Vec::new();
        Self::find_all_overlaps_rec(self.root.as_ref(), query, &mut results);
        results
    }

    fn find_all_overlaps_rec<'a>(
        node: Option<&'a Box<ITNode>>,
        query: &Interval,
        results: &mut Vec<&'a Interval>,
    ) {
        let node = match node {
            Some(n) => n,
            None => return,
        };

        // Check left subtree
        if let Some(ref left) = node.left {
            if left.max_end >= query.lo {
                Self::find_all_overlaps_rec(Some(left), query, results);
            }
        }

        // Check current node
        if node.interval.overlaps(query) {
            results.push(&node.interval);
        }

        // Check right subtree only if there might be overlaps
        if node.interval.lo <= query.hi {
            Self::find_all_overlaps_rec(node.right.as_ref(), query, results);
        }
    }

    pub fn stab(&self, point: i64) -> Vec<&Interval> {
        let query = Interval::new(point, point);
        self.find_all_overlaps(&query)
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Default for StormCircleTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_overlaps() {
        let a = Interval::new(10, 20);
        let b = Interval::new(15, 25);
        let c = Interval::new(30, 40);

        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_find_overlap() {
        let mut tracker = StormCircleTracker::new();
        tracker.insert(Interval::new(15, 20));
        tracker.insert(Interval::new(10, 30));
        tracker.insert(Interval::new(5, 12));

        let query = Interval::new(14, 16);
        assert!(tracker.find_overlap(&query).is_some());

        let no_match = Interval::new(100, 200);
        assert!(tracker.find_overlap(&no_match).is_none());
    }

    #[test]
    fn test_stab() {
        let mut tracker = StormCircleTracker::new();
        tracker.insert(Interval::new(1, 10));
        tracker.insert(Interval::new(5, 15));
        tracker.insert(Interval::new(12, 20));

        let stabbed = tracker.stab(7);
        assert_eq!(stabbed.len(), 2);
    }
}
```

### 4.5 Solutions refusées (avec explications)

**Refusée 1 — Overlap check avec < au lieu de <= :**
```rust
pub fn overlaps(&self, other: &Interval) -> bool {
    self.lo < other.hi && other.lo < self.hi  // ❌ < au lieu de <=
}
// Pourquoi refusé : [10,20] et [20,30] devraient overlap (adjacent)
// Ce qui était pensé : "Les intervalles adjacents ne se chevauchent pas"
```

**Refusée 2 — max_end pas mis à jour après insert :**
```rust
fn insert_rec(node: Option<Box<ITNode>>, interval: Interval) -> Option<Box<ITNode>> {
    match node {
        None => Some(Box::new(ITNode::new(interval))),
        Some(mut n) => {
            if interval.lo < n.interval.lo {
                n.left = Self::insert_rec(n.left.take(), interval);
            } else {
                n.right = Self::insert_rec(n.right.take(), interval);
            }
            // ❌ Oubli de n.update_max_end() !
            Some(n)
        }
    }
}
// Pourquoi refusé : max_end incorrect → pruning cassé
```

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "storm_circle_tracker",
  "language": "rust",
  "version": "2024",
  "secondary_language": "c",
  "secondary_version": "c17",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isolé",
  "tags": ["interval-tree", "geometric", "range-query", "phase1", "struct"],
  "passing_score": 70,

  "function": {
    "name": "StormCircleTracker",
    "prototype": "pub struct StormCircleTracker",
    "return_type": "struct",
    "methods": [
      {"name": "new", "signature": "pub fn new() -> Self"},
      {"name": "insert", "signature": "pub fn insert(&mut self, interval: Interval)"},
      {"name": "delete", "signature": "pub fn delete(&mut self, interval: &Interval) -> bool"},
      {"name": "find_overlap", "signature": "pub fn find_overlap(&self, query: &Interval) -> Option<&Interval>"},
      {"name": "find_all_overlaps", "signature": "pub fn find_all_overlaps(&self, query: &Interval) -> Vec<&Interval>"},
      {"name": "stab", "signature": "pub fn stab(&self, point: i64) -> Vec<&Interval>"}
    ]
  },

  "driver": {
    "reference": "impl StormCircleTracker { pub fn new() -> Self { StormCircleTracker { root: None, size: 0 } } pub fn is_empty(&self) -> bool { self.size == 0 } }",

    "edge_cases": [
      {
        "name": "empty_find",
        "setup": "let tracker = StormCircleTracker::new();",
        "action": "tracker.find_overlap(&Interval::new(1, 10))",
        "expected": "None",
        "is_trap": true,
        "trap_explanation": "Find on empty tree must return None"
      },
      {
        "name": "adjacent_intervals",
        "setup": "let a = Interval::new(10, 20); let b = Interval::new(20, 30);",
        "action": "a.overlaps(&b)",
        "expected": "true",
        "is_trap": true,
        "trap_explanation": "Adjacent intervals [10,20] and [20,30] MUST overlap (inclusive)"
      },
      {
        "name": "stab_boundary",
        "setup": "let mut t = StormCircleTracker::new(); t.insert(Interval::new(10, 20));",
        "action": "t.stab(10).len()",
        "expected": "1",
        "is_trap": true,
        "trap_explanation": "Stab at boundary 10 must find [10,20]"
      },
      {
        "name": "max_end_propagation",
        "setup": "let mut t = StormCircleTracker::new(); t.insert(Interval::new(10, 100)); t.insert(Interval::new(5, 8));",
        "action": "t.find_overlap(&Interval::new(50, 60))",
        "expected": "Some([10,100])",
        "is_trap": true,
        "trap_explanation": "max_end must be propagated correctly for pruning to work"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 3000,
      "generators": [
        {
          "type": "int",
          "param_index": 0,
          "params": {"min": 0, "max": 10000}
        },
        {
          "type": "int",
          "param_index": 1,
          "params": {"min": 0, "max": 10000}
        }
      ],
      "properties": [
        "find_overlap_returns_overlapping_interval",
        "find_all_returns_all_overlaps",
        "stab_finds_containing_intervals"
      ]
    }
  },

  "norm": {
    "allowed_functions": ["Vec", "Box", "Option", "max", "malloc", "free", "realloc"],
    "forbidden_functions": ["IntervalTree", "RTree"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  },

  "bonus": [
    {
      "name": "range_tree_2d",
      "tier": "STANDARD",
      "xp_multiplier": 2,
      "required_functions": ["SafeZoneScanner::count_rect", "SafeZoneScanner::report_rect"]
    },
    {
      "name": "kd_tree",
      "tier": "EXPERT",
      "xp_multiplier": 4,
      "required_functions": ["EnemyRadar::nearest", "EnemyRadar::k_nearest"]
    },
    {
      "name": "fractional_cascading",
      "tier": "GENIUS",
      "xp_multiplier": 6,
      "required_functions": []
    }
  ]
}
```

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) — Overlap avec < au lieu de <= :**
```rust
pub fn overlaps(&self, other: &Interval) -> bool {
    self.lo < other.hi && other.lo < self.hi  // ❌
}
// Pourquoi c'est faux : Les intervalles adjacents [10,20], [20,30] ne sont pas détectés
// Ce qui était pensé : "Adjacent = pas de chevauchement"
```

**Mutant B (Safety) — Pas de mise à jour max_end :**
```rust
fn insert_rec(node: Option<Box<ITNode>>, interval: Interval) -> Option<Box<ITNode>> {
    // ... insertion ...
    // ❌ Oubli de update_max_end()
    Some(n)
}
// Pourquoi c'est faux : Le pruning ne fonctionne plus
// Ce qui était pensé : "max_end ne sert qu'à l'affichage"
```

**Mutant C (Resource) — max_end pas recalculé après delete :**
```rust
fn delete_rec(...) -> (Option<Box<ITNode>>, bool) {
    // ... suppression ...
    n.left = new_left;
    // ❌ Pas de n.update_max_end()
    (Some(n), deleted)
}
// Pourquoi c'est faux : max_end devient obsolète, queries échouent
// Ce qui était pensé : "Delete ne change pas max_end"
```

**Mutant D (Logic) — find_all s'arrête après le premier :**
```rust
fn find_all_overlaps_rec(...) {
    if node.interval.overlaps(query) {
        results.push(&node.interval);
        return;  // ❌ Return trop tôt !
    }
    // ...
}
// Pourquoi c'est faux : Ne trouve pas tous les overlaps
// Ce qui était pensé : "Un overlap suffit"
```

**Mutant E (Return) — stab ne vérifie pas les bornes inclusives :**
```rust
pub fn contains_point(&self, point: i64) -> bool {
    self.lo < point && point < self.hi  // ❌ < au lieu de <=
}
// Pourquoi c'est faux : stab(10) sur [10,20] retourne false
// Ce qui était pensé : "Les bornes sont exclusives"
```

---

## 🧠 SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

1. **Interval Trees** : BST augmenté pour requêtes sur intervalles
2. **Augmentation max_end** : Permet le "pruning" de sous-arbres
3. **Requêtes géométriques** : Overlap, stab, range
4. **Trade-offs** : Espace O(n) vs temps O(log n + k)
5. **Applications** : Calendriers, collision detection, bases de données temporelles

### 5.2 LDA — Traduction littérale en français (MAJUSCULES)

```
FONCTION find_overlap QUI RETOURNE UNE OPTION D'INTERVALLE ET PREND EN PARAMÈTRE query QUI EST UN INTERVALLE
DÉBUT FONCTION
    APPELER find_overlap_rec AVEC LA RACINE ET query
FIN FONCTION

FONCTION find_overlap_rec QUI RETOURNE UNE OPTION D'INTERVALLE ET PREND EN PARAMÈTRES node ET query
DÉBUT FONCTION
    SI node EST VIDE ALORS
        RETOURNER VIDE
    FIN SI

    SI L'INTERVALLE DU NŒUD CHEVAUCHE query ALORS
        RETOURNER L'INTERVALLE DU NŒUD
    FIN SI

    SI LE FILS GAUCHE EXISTE ET max_end DU FILS GAUCHE EST SUPÉRIEUR OU ÉGAL À query.lo ALORS
        AFFECTER find_overlap_rec SUR LE FILS GAUCHE À résultat
        SI résultat N'EST PAS VIDE ALORS
            RETOURNER résultat
        FIN SI
    FIN SI

    RETOURNER find_overlap_rec SUR LE FILS DROIT
FIN FONCTION
```

### 5.3 Visualisation ASCII

**Structure de l'Interval Tree :**

```
                              [15-20]
                             max=25
                            /       \
                     [10-25]         [17-19]
                     max=25          max=19
                    /      \
               [5-12]    [12-14]
               max=12     max=14

Intervalles stockés : [5,12], [10,25], [12,14], [15,20], [17,19]
```

**Recherche d'overlap avec query=[16,18] :**

```
1. Start at root [15,20], max=25
   → [15,20] overlaps [16,18]? YES! ✓
   → Return [15,20]

Alternative path if we wanted ALL overlaps:
1. Check root [15,20] → overlaps? YES, add to results
2. Left child max=25 >= 16? YES, explore
   → [10,25] overlaps [16,18]? YES, add
   → Check [5,12]: 12 < 16, skip further
3. Right child [17,19] overlaps? YES, add

Results: [15,20], [10,25], [17,19]
```

**Pruning grâce à max_end :**

```
Query: [100, 150]

         [15-20]
         max=25          ← max=25 < 100, PRUNE ENTIRE SUBTREE!
        /       \
   [10-25]    [17-19]
   max=25     max=19

→ Aucune descente nécessaire, le sous-arbre entier est éliminé !
```

### 5.5 Cours Complet

#### 5.5.1 Qu'est-ce qu'un Interval Tree ?

Un **Interval Tree** est un arbre binaire de recherche **augmenté** pour stocker des intervalles [lo, hi].

**Clé de tri** : Le point de départ `lo`
**Augmentation** : Chaque nœud stocke `max_end`, la valeur maximale de `hi` dans son sous-arbre

#### 5.5.2 Pourquoi l'augmentation max_end ?

Sans `max_end`, pour trouver tous les intervalles chevauchant [a, b], on devrait visiter tous les nœuds (O(n)).

Avec `max_end`, on peut "pruner" : si un sous-arbre a `max_end < a`, alors AUCUN intervalle de ce sous-arbre ne peut chevaucher [a, b].

#### 5.5.3 Complexité

| Opération | Temps |
|-----------|-------|
| Insert | O(log n) |
| Delete | O(log n) |
| Find overlap | O(log n) |
| Find ALL overlaps | O(log n + k) |
| Stab query | O(log n + k) |

#### 5.5.4 Variantes

| Structure | Dimension | Use case |
|-----------|-----------|----------|
| Interval Tree | 1D | Chevauchements d'intervalles |
| Segment Tree | 1D | Somme/min/max sur ranges |
| Range Tree | 2D+ | Points dans rectangles |
| KD-Tree | k-D | Nearest neighbor, range search |
| R-Tree | 2D+ | Rectangles englobants (spatial DB) |

### 5.6 Normes avec explications pédagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                   │
├─────────────────────────────────────────────────────────────────┤
│ fn overlaps(&self, other: &Interval) -> bool {                  │
│     self.lo < other.hi && other.lo < self.hi  // STRICT!        │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ fn overlaps(&self, other: &Interval) -> bool {                  │
│     self.lo <= other.hi && other.lo <= self.hi  // INCLUSIVE    │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Intervalles [10,20] et [20,30] partagent le point 20          │
│ • Dans la plupart des applications, c'est un chevauchement      │
│ • Utilisez < seulement si explicitement demandé                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.8 Mnémotechniques (MEME obligatoire)

#### 🌀 MEME : "The Storm is Coming"

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│   🎮 HACKBRAIN: Last Coder Standing                            │
│                                                                │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  [GAME CHAT]                                            │  │
│   │                                                         │  │
│   │  Player_42: "How do I know if I'm in the storm?"        │  │
│   │                                                         │  │
│   │  Pro_Coder: "Use interval_tree.stab(your_position)"     │  │
│   │                                                         │  │
│   │  Player_42: "What if I want to find ALL danger zones?"  │  │
│   │                                                         │  │
│   │  Pro_Coder: "find_all_overlaps(your_time_range)"        │  │
│   │                                                         │  │
│   │  Player_42: "This is just a game... right?"             │  │
│   │                                                         │  │
│   │  Pro_Coder: "The Storm is Coming. For your code too."   │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Règle à retenir :**
> "max_end est ton radar anti-storm : si max_end < ta position, tu es safe dans ce sous-arbre."

#### 🎯 Règle mnémotechnique de l'overlap

> **"A starts before B ends, AND B starts before A ends"**
> `a.lo <= b.hi && b.lo <= a.hi`

Visualisation :
```
[----A----]
      [----B----]

A commence (lo=10) avant que B finisse (hi=25) ✓
B commence (lo=15) avant que A finisse (hi=20) ✓
→ OVERLAP!
```

### 5.9 Applications pratiques

| Application | Comment l'Interval Tree est utilisé |
|-------------|-------------------------------------|
| **Google Calendar** | Détecter les conflits de réunions |
| **Game Engine** | Collision detection temporelle |
| **Database** | Index sur colonnes de type RANGE |
| **Network** | Firewall rules, IP ranges |
| **Bioinformatics** | Gene overlapping |
| **Scheduling** | Resource allocation |

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Impact | Prévention |
|---|-------|--------|------------|
| 1 | < au lieu de <= pour overlap | Miss les adjacents | Toujours <=  |
| 2 | max_end pas mis à jour | Pruning cassé | update_max_end() après insert/delete |
| 3 | find_all s'arrête tôt | Résultats incomplets | Ne pas return après premier trouvé |
| 4 | stab avec bornes exclusives | Miss les endpoints | Utiliser <= pour contains_point |
| 5 | Pruning condition inversée | Mauvaise exploration | max_end >= query.lo, pas <= |

---

## 📝 SECTION 7 : QCM

### Question 1
**Deux intervalles [a, b] et [c, d] se chevauchent si et seulement si :**

A) a < c < b
B) a ≤ d AND c ≤ b
C) a < d AND c < b
D) a = c
E) b = c
F) a ≤ c ≤ b
G) c ≤ a ≤ d
H) (a ≤ c ≤ b) OR (c ≤ a ≤ d)
I) a ≤ d OR c ≤ b
J) a < b AND c < d

**Réponse : B) a ≤ d AND c ≤ b** (condition nécessaire et suffisante)

---

### Question 2
**Quelle information augmente chaque nœud dans un Interval Tree ?**

A) La somme des intervalles
B) Le nombre d'intervalles dans le sous-arbre
C) La valeur maximale de `hi` dans le sous-arbre (max_end)
D) La valeur minimale de `lo` dans le sous-arbre
E) La longueur moyenne des intervalles
F) La profondeur du sous-arbre
G) Le nombre de chevauchements
H) La médiane des intervalles
I) La valeur maximale de `lo`
J) Aucune augmentation nécessaire

**Réponse : C) La valeur maximale de `hi` dans le sous-arbre (max_end)**

---

### Question 3
**Quelle est la complexité de `find_all_overlaps` sur un Interval Tree équilibré ?**

A) O(1)
B) O(log n)
C) O(n)
D) O(log n + k) où k = nombre de résultats
E) O(n log n)
F) O(k)
G) O(log k)
H) O(n + k)
I) O(k log n)
J) O(n²)

**Réponse : D) O(log n + k)** (log n pour atteindre la zone + k pour collecter)

---

### Question 4
**Si un nœud a max_end = 50 et la query cherche des overlaps avec [100, 150], que fait-on ?**

A) On explore quand même
B) On prune le sous-arbre entier
C) On explore seulement le fils droit
D) On explore seulement le fils gauche
E) On retourne une erreur
F) On ignore le nœud mais pas ses enfants
G) On marque le nœud comme visité
H) On met à jour max_end
I) On supprime le nœud
J) Dépend du contexte

**Réponse : B) On prune le sous-arbre entier** (car max_end < query.lo)

---

## 📊 SECTION 8 : RÉCAPITULATIF

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STORM CIRCLE TRACKER — RÉCAPITULATIF                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CONCEPT CLÉ :                                                              │
│  Un Interval Tree est un BST augmenté avec max_end pour pruning             │
│                                                                             │
│  AUGMENTATION :                                                             │
│  max_end = max(interval.hi, left.max_end, right.max_end)                    │
│                                                                             │
│  CONDITION D'OVERLAP :                                                      │
│  a.lo ≤ b.hi AND b.lo ≤ a.hi                                                │
│                                                                             │
│  PRUNING :                                                                  │
│  Si max_end < query.lo → aucun overlap possible dans le sous-arbre          │
│                                                                             │
│  OPÉRATIONS :                                                               │
│  • Insert : O(log n) — BST insert + update max_end                          │
│  • Find overlap : O(log n) — trouver UN intervalle                          │
│  • Find ALL overlaps : O(log n + k) — trouver TOUS                          │
│  • Stab : O(log n + k) — intervalles contenant un point                     │
│                                                                             │
│  APPLICATIONS : Calendriers, collision, temporal DB, scheduling             │
│                                                                             │
│  MEME : "The Storm is Coming — for your code too"                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.3.6-a-storm-circle-tracker",
    "generated_at": "2025-01-11 17:00:00",

    "metadata": {
      "exercise_id": "1.3.6-a",
      "exercise_name": "storm_circle_tracker",
      "module": "1.3.6",
      "module_name": "Interval & Range Trees",
      "concept": "a",
      "concept_name": "Arbres pour requêtes géométriques et intervalles",
      "type": "code",
      "tier": 1,
      "tier_info": "Concept isolé",
      "phase": 1,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "rust",
      "language_version": "2024",
      "secondary_language": "c",
      "secondary_version": "c17",
      "duration_minutes": 50,
      "xp_base": 130,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T2 O(log n + k)",
      "complexity_space": "S2 O(n)",
      "prerequisites": ["1.3.1-bst", "comparisons"],
      "domains": ["Struct", "Algo", "Méca"],
      "domains_bonus": [],
      "tags": ["interval-tree", "range-query", "geometric", "augmented-bst"],
      "meme_reference": "The Storm is Coming"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_storm_circle_tracker.rs": "/* Section 4.3 Rust */",
      "references/ref_storm_circle_tracker.c": "/* Section 4.3 C */",
      "mutants/mutant_a_boundary.rs": "/* Section 4.10 - Overlap strict */",
      "mutants/mutant_b_safety.rs": "/* Section 4.10 - No max_end update */",
      "mutants/mutant_c_resource.rs": "/* Section 4.10 - Delete no update */",
      "mutants/mutant_d_logic.rs": "/* Section 4.10 - Early exit */",
      "mutants/mutant_e_return.rs": "/* Section 4.10 - Contains strict */",
      "tests/main.c": "/* Section 4.2 */",
      "tests/main.rs": "/* Section 4.3 tests */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_storm_circle_tracker.rs",
        "references/ref_storm_circle_tracker.c"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.rs",
        "mutants/mutant_b_safety.rs",
        "mutants/mutant_c_resource.rs",
        "mutants/mutant_d_logic.rs",
        "mutants/mutant_e_return.rs"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_rust": "rustc --edition 2024 --test storm_circle_tracker.rs -o test && ./test",
      "test_c": "gcc -std=c17 -Wall -Wextra -Werror storm_circle_tracker.c main.c -o test && ./test",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ -s spec.json --validate"
    }
  }
}
```

---

*Exercise généré avec HACKBRAIN v5.5.2 — "L'excellence pédagogique ne se négocie pas"*
*GG! The Storm Circle Tracker is operational. Victory Royale incoming.*
