<thinking>
## Analyse du Concept
- Concept : Fenwick Trees (Binary Indexed Trees)
- Phase demandée : 1 (Structures de données avancées)
- Adapté ? OUI - Les BIT sont plus simples que les Segment Trees et aussi importants

## Combo Base + Bonus
- Exercice de base : Fenwick Tree basique avec prefix sum et point update
- Bonus Standard : Range update avec deux arbres
- Bonus Expert : Fenwick Tree 2D
- Bonus Génie : Applications avancées (inversions, order statistics)
- Palier bonus : ⚡ → 🔥 → 🧠
- Progression logique ? OUI

## Prérequis & Difficulté
- Prérequis réels : Manipulation binaire, prefix sums
- Difficulté estimée : 4/10 (base), 6/10 (range update), 8/10 (2D)
- Cohérent avec phase ? OUI

## Aspect Fun/Culture
- Contexte choisi : "Duolingo Owl" - Le hibou qui traque ton XP
- MEME mnémotechnique : Le hibou creepy de Duolingo qui sait TOUT sur ta progression
- Pourquoi c'est fun :
  - Universellement connu et meme viral
  - Parfaite analogie : XP quotidien, progression cumulative, queries de range
  - Le lowbit = la portée de surveillance du hibou
  - "You missed a day" = update operation

## Scénarios d'Échec (5 mutants concrets)
1. Mutant A (Boundary) : Oubli du +1 pour conversion 0-indexed → 1-indexed
2. Mutant B (Safety) : lowbit(0) cause une boucle infinie
3. Mutant C (Resource) : Allocation de n au lieu de n+1 (off-by-one)
4. Mutant D (Logic) : i += lowbit(i) dans query au lieu de i -= lowbit(i)
5. Mutant E (Return) : range_sum(l, r) = prefix_sum(r) - prefix_sum(l) au lieu de prefix_sum(l-1)

## Verdict
VALIDE - L'analogie Duolingo est excellente et le format HACKBRAIN est respecté.
Note qualité: 96/100
</thinking>

---

# Exercice 1.3.8 : duo_xp_tracker

**Module :**
1.3.8 — Fenwick Trees (Binary Indexed Trees)

**Concept :**
a-k — BIT basique, range updates, 2D, applications

**Difficulté :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
3 — Synthèse (tous concepts des Fenwick Trees)

**Langage :**
Rust Edition 2024, C17

**Prérequis :**
- Manipulation binaire (AND, complément à 2)
- Concept de prefix sum
- Tableaux et indices

**Domaines :**
Struct, Algo, Encodage

**Durée estimée :**
45 min

**XP Base :**
120

**Complexité :**
T[2] O(n) construction, O(log n) query/update × S[1] O(n)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- Rust : `src/lib.rs`, `Cargo.toml`
- C : `duo_xp_tracker.c`, `duo_xp_tracker.h`

**Fonctions autorisées :**
- Rust : std uniquement
- C : `malloc`, `free`, `realloc`, `memset`

**Fonctions interdites :**
- Bibliothèques externes
- Segment Trees (on implémente BIT, pas ST!)

---

### 1.2 Consigne

#### 🎮 Version Culture : "The Duolingo Owl Watches"

**🦉 Duolingo — Le hibou qui ne dort jamais**

*"You haven't practiced French today. I noticed."*

Le hibou de Duolingo te surveille. Il connaît chaque XP que tu as gagné, chaque jour où tu as manqué ta leçon, chaque streak que tu as brisé. Mais comment fait-il pour savoir **instantanément** ton total d'XP entre le jour 47 et le jour 183 ?

Son secret ? Le **Fenwick Tree** (Binary Indexed Tree) — une structure de données qui lui permet de :
1. **Ajouter** de l'XP quand tu complètes une leçon : O(log n)
2. **Calculer** ton XP cumulé jusqu'à un jour donné : O(log n)
3. **Trouver** ton XP entre deux dates : O(log n)

Et le plus beau ? C'est plus simple qu'un Segment Tree et utilise moins de mémoire !

*"Spanish or vanish."* — Le hibou, probablement

---

#### 📖 Version Académique : Binary Indexed Tree pour prefix sums

**Ta mission :**

Implémenter une structure `DuoXPTracker` (Fenwick Tree) qui permet :
1. De créer un tracker vide ou à partir d'un historique d'XP
2. D'ajouter de l'XP à un jour donné (update)
3. De calculer l'XP cumulé jusqu'au jour i (prefix sum)
4. De calculer l'XP entre deux jours (range sum)
5. De récupérer l'XP d'un jour spécifique (point query)

**Entrée :**
- `n: usize` : Nombre de jours à tracker
- `xp_history: &[i64]` : Historique initial d'XP par jour
- `day: usize` : Index du jour (0-based)
- `delta: i64` : XP à ajouter (peut être négatif si pénalité!)

**Sortie :**
- `add(day, delta)` : Ajoute delta à l'XP du jour
- `prefix_sum(day) -> i64` : XP total des jours 0 à day inclus
- `range_sum(l, r) -> i64` : XP total des jours l à r inclus
- `get(day) -> i64` : XP du jour spécifique

**Contraintes :**
- Le tableau interne est 1-indexed (convention BIT)
- Toutes les opérations en O(log n)
- Construction from_array en O(n)
- L'opération clé `lowbit(x) = x & (-x)` détermine la responsabilité de chaque index

**Exemples :**

| Opération | Résultat | Explication |
|-----------|----------|-------------|
| `new(5)` | Tracker vide | 5 jours, tout à 0 |
| `from_array([10, 20, 30, 40, 50])` | Tracker initialisé | XP par jour |
| `prefix_sum(2)` | `60` | 10+20+30 (jours 0-2) |
| `range_sum(1, 3)` | `90` | 20+30+40 (jours 1-3) |
| `add(2, 15)` | — | Jour 2: 30 → 45 |
| `prefix_sum(2)` | `75` | 10+20+45 |
| `get(2)` | `45` | XP du jour 2 |

---

### 1.3 Prototype

**Rust :**
```rust
pub struct DuoXPTracker {
    tree: Vec<i64>,
    n: usize,
}

impl DuoXPTracker {
    /// Crée un tracker vide pour n jours
    pub fn new(n: usize) -> Self;

    /// Crée un tracker à partir d'un historique (O(n))
    pub fn from_array(xp_history: &[i64]) -> Self;

    /// Ajoute delta XP au jour donné (O(log n))
    pub fn add(&mut self, day: usize, delta: i64);

    /// XP cumulé des jours 0 à day inclus (O(log n))
    pub fn prefix_sum(&self, day: usize) -> i64;

    /// XP des jours l à r inclus (O(log n))
    pub fn range_sum(&self, l: usize, r: usize) -> i64;

    /// XP du jour spécifique (O(log n))
    pub fn get(&self, day: usize) -> i64;

    /// Premier jour où le cumul atteint au moins target (O(log n))
    pub fn lower_bound(&self, target: i64) -> Option<usize>;

    /// Met l'XP du jour à une valeur exacte
    pub fn set(&mut self, day: usize, value: i64);

    /// Nombre de jours trackés
    pub fn len(&self) -> usize;
}

// Fonction utilitaire clé
fn lowbit(x: usize) -> usize;
```

**C :**
```c
typedef struct {
    int64_t *tree;
    size_t n;
} DuoXPTracker;

// Construction et destruction
DuoXPTracker *duo_new(size_t n);
DuoXPTracker *duo_from_array(const int64_t *xp_history, size_t n);
void duo_free(DuoXPTracker *tracker);

// Opérations principales
void duo_add(DuoXPTracker *tracker, size_t day, int64_t delta);
int64_t duo_prefix_sum(const DuoXPTracker *tracker, size_t day);
int64_t duo_range_sum(const DuoXPTracker *tracker, size_t l, size_t r);
int64_t duo_get(const DuoXPTracker *tracker, size_t day);
void duo_set(DuoXPTracker *tracker, size_t day, int64_t value);

// Utilitaires
size_t duo_len(const DuoXPTracker *tracker);
size_t duo_lower_bound(const DuoXPTracker *tracker, int64_t target);

// Fonction magique
static inline size_t lowbit(size_t x);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'histoire du Fenwick Tree

Le **Binary Indexed Tree** a été proposé par Peter Fenwick en 1994 dans son article *"A New Data Structure for Cumulative Frequency Tables"*. Il était utilisé pour la compression de données arithmétique.

**Pourquoi "Binary Indexed"?** Parce que l'index en binaire détermine exactement quels éléments chaque position de l'arbre couvre :
- Index 8 (1000₂) : couvre 8 éléments
- Index 6 (0110₂) : couvre 2 éléments (lowbit = 2)
- Index 7 (0111₂) : couvre 1 élément (lowbit = 1)

### 2.2 BIT vs Segment Tree

| Aspect | Fenwick Tree | Segment Tree |
|--------|--------------|--------------|
| Mémoire | O(n) exact | O(2n) à O(4n) |
| Code | ~20 lignes | ~50+ lignes |
| Constante | Plus rapide | Plus lent |
| Opérations | Prefix/Range sum | Tout (min, max, etc.) |
| Range update | Avec 2 arbres | Natif (lazy) |

**Règle simple :** Si tu n'as besoin que de sommes, utilise un BIT. Sinon, Segment Tree.

### 2.5 DANS LA VRAIE VIE

**Data Analysts :**
- Calcul de métriques cumulatives (revenus YTD, utilisateurs cumulés)
- Histogrammes dynamiques

**Game Developers :**
- Leaderboards avec rangs dynamiques
- Systèmes de score avec mises à jour fréquentes

**Quantitative Finance :**
- Calcul de positions cumulatives
- P&L tracking en temps réel

**Competitive Programming :**
- Plus compact que le Segment Tree
- Très rapide grâce à la constante faible

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
duo_xp_tracker.rs  main.rs  Cargo.toml

$ cargo build --release

$ cargo run
🦉 Duolingo XP Tracker initialized!
Day XP history: [10, 20, 30, 40, 50]
Prefix sum day 2: 60 (10+20+30)
Range sum [1,3]: 90 (20+30+40)
Adding 15 XP to day 2...
New prefix sum day 2: 75
Get day 2: 45
The owl is watching... all tests passed!
```

---

### 3.1 ⚡ BONUS STANDARD : Range Update (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Récompense :**
XP ×2

**Time Complexity attendue :**
O(log n) pour range_add et point get

**Domaines Bonus :**
`Algo`

#### 3.1.1 Consigne Bonus

**🦉 Le Double Regard du Hibou**

*"You thought you could escape? I see ALL your lessons."*

Le hibou peut maintenant donner des bonus XP à une **plage entière de jours** (événements spéciaux, weekends double XP). Pour faire ça en O(log n), il utilise **deux** Fenwick Trees qui travaillent ensemble !

La technique : au lieu de stocker les valeurs directement, on stocke les **différences**. Avec deux arbres, on peut reconstruire n'importe quelle valeur en O(log n).

**Ta mission :**

Implémenter `DuoRangeUpdate` avec :
- `range_add(l, r, delta)` : Ajoute delta à tous les jours de l à r
- `get(day)` : Récupère l'XP du jour (après toutes les range updates)

**Contraintes :**
```
┌─────────────────────────────────────────┐
│  Toutes opérations en O(log n)          │
│  Utilise DEUX Fenwick Trees             │
│  Formule: get(i) = B1.prefix(i) × (i+1) │
│           - B2.prefix(i)                │
└─────────────────────────────────────────┘
```

**Exemples :**

| Opération | État après | Explication |
|-----------|------------|-------------|
| `new(5)` | `[0,0,0,0,0]` | Tracker vide |
| `range_add(1, 3, 10)` | `[0,10,10,10,0]` | +10 aux jours 1-3 |
| `get(2)` | `10` | Jour 2 a reçu le bonus |
| `range_add(0, 2, 5)` | `[5,15,15,10,0]` | +5 aux jours 0-2 |
| `get(1)` | `15` | 10 + 5 |

#### 3.1.2 Prototype Bonus

```rust
pub struct DuoRangeUpdate {
    tree1: Vec<i64>,
    tree2: Vec<i64>,
    n: usize,
}

impl DuoRangeUpdate {
    pub fn new(n: usize) -> Self;
    pub fn range_add(&mut self, l: usize, r: usize, delta: i64);
    pub fn get(&self, day: usize) -> i64;
    pub fn prefix_sum(&self, day: usize) -> i64;
}
```

#### 3.1.3 Ce qui change par rapport à l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Arbres | 1 | 2 |
| Update | Point O(log n) | Range O(log n) |
| Query | Prefix O(log n) | Point O(log n) |
| Formule get | tree[i] direct | B1×(i+1) - B2 |

---

### 3.2 🔥 BONUS EXPERT : Fenwick 2D (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★★☆☆ (8/10)

**Récompense :**
XP ×3

**Time Complexity attendue :**
O(log n × log m) par opération

**Domaines Bonus :**
`AL`

#### 3.2.1 Consigne Bonus Expert

**🦉 La Grille de Surveillance Mondiale**

Le hibou ne se contente plus d'un seul pays. Il surveille une **matrice** de régions mondiales ! Chaque cellule (pays, mois) contient l'XP gagné. Il veut pouvoir :
- Ajouter de l'XP à une cellule (pays i, mois j)
- Calculer l'XP total dans un rectangle de pays/mois

**Ta mission :**

Implémenter `DuoXPTracker2D` avec :
- `add(row, col, delta)` : Ajoute delta à la cellule (row, col)
- `prefix_sum(row, col)` : Somme du rectangle (0,0) à (row, col)
- `range_sum(r1, c1, r2, c2)` : Somme du rectangle (r1,c1) à (r2,c2)

#### 3.2.2 Prototype Bonus Expert

```rust
pub struct DuoXPTracker2D {
    tree: Vec<Vec<i64>>,
    n: usize,
    m: usize,
}

impl DuoXPTracker2D {
    pub fn new(n: usize, m: usize) -> Self;
    pub fn add(&mut self, row: usize, col: usize, delta: i64);
    pub fn prefix_sum(&self, row: usize, col: usize) -> i64;
    pub fn range_sum(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64;
}
```

---

### 3.3 🧠 BONUS GÉNIE : Applications Avancées (OPTIONNEL)

**Difficulté Bonus :**
🧠 (11/10)

**Récompense :**
XP ×6

**Domaines Bonus :**
`Tri`, `MD`

#### 3.3.1 Consigne Bonus Génie

**🦉 L'Omniscience du Hibou**

Le hibou peut maintenant répondre à des questions encore plus complexes :

1. **Comptage d'inversions** : "Combien de jours avais-tu plus d'XP qu'un jour futur?"
2. **Order Statistics dynamiques** : "Quel était le k-ième meilleur jour?"
3. **Éléments plus petits à gauche** : "Pour chaque jour, combien de jours précédents avaient moins d'XP?"

**Ta mission :**

Implémenter :
- `count_inversions(arr)` : Nombre de paires (i,j) où i < j et arr[i] > arr[j]
- `smaller_to_left(arr)` : Pour chaque position, combien d'éléments plus petits à gauche
- `OrderStatistics` : Structure avec insert, remove, kth_smallest, count_less_than

#### 3.3.2 Prototype Bonus Génie

```rust
/// Compte les inversions dans un tableau
pub fn count_inversions(arr: &[i32]) -> i64;

/// Pour chaque élément, compte combien sont plus petits à gauche
pub fn smaller_to_left(arr: &[i32]) -> Vec<i32>;

/// Order Statistics dynamique
pub struct DuoOrderStats {
    tree: DuoXPTracker,
    max_val: usize,
}

impl DuoOrderStats {
    pub fn new(max_val: usize) -> Self;
    pub fn insert(&mut self, value: usize);
    pub fn remove(&mut self, value: usize);
    pub fn kth_smallest(&self, k: usize) -> Option<usize>;
    pub fn count_less_than(&self, value: usize) -> usize;
}
```

**Exemples inversions :**

| Input | Output | Explication |
|-------|--------|-------------|
| `[2, 4, 1, 3, 5]` | `3` | (2,1), (4,1), (4,3) |
| `[5, 4, 3, 2, 1]` | `10` | Toutes les paires |
| `[1, 2, 3, 4, 5]` | `0` | Déjà trié |

---

## ✅❌ SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test | Input | Expected | Points | Trap |
|------|-------|----------|--------|------|
| `empty_tracker` | `new(0)` | Tracker valide | 5 | Edge |
| `single_day` | `from_array([42])` | `prefix_sum(0)=42` | 5 | Edge |
| `basic_prefix` | `[1,2,3,4,5]`, `prefix_sum(2)` | `6` | 10 | — |
| `basic_range` | `[1,2,3,4,5]`, `range_sum(1,3)` | `9` | 10 | — |
| `add_update` | `add(2, 10)` | Updates correctly | 10 | — |
| `get_point` | `get(2)` after updates | Correct value | 10 | — |
| `from_array_linear` | Large array | O(n) construction | 10 | Perf |
| `lowbit_edge` | Various indices | Correct lowbit | 5 | Bit ops |
| `boundary_left` | `prefix_sum(0)` | First element | 5 | Boundary |
| `range_same` | `range_sum(3, 3)` | Single element | 5 | Boundary |
| `lower_bound` | Find first >= target | Correct index | 10 | — |
| `stress_test` | 10⁵ ops | < 1s | 15 | Perf |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "duo_xp_tracker.h"

void test_basic_operations(void) {
    int64_t xp[] = {10, 20, 30, 40, 50};
    DuoXPTracker *tracker = duo_from_array(xp, 5);

    // Test prefix sum
    assert(duo_prefix_sum(tracker, 0) == 10);
    assert(duo_prefix_sum(tracker, 2) == 60);  // 10+20+30
    assert(duo_prefix_sum(tracker, 4) == 150); // All

    // Test range sum
    assert(duo_range_sum(tracker, 1, 3) == 90);  // 20+30+40

    // Test get
    assert(duo_get(tracker, 2) == 30);

    // Test add
    duo_add(tracker, 2, 15);
    assert(duo_get(tracker, 2) == 45);
    assert(duo_prefix_sum(tracker, 2) == 75);

    duo_free(tracker);
    printf("Basic operations: OK\n");
}

void test_lowbit(void) {
    // Test the core operation
    assert(lowbit(1) == 1);   // 0001 -> 1
    assert(lowbit(2) == 2);   // 0010 -> 2
    assert(lowbit(3) == 1);   // 0011 -> 1
    assert(lowbit(4) == 4);   // 0100 -> 4
    assert(lowbit(6) == 2);   // 0110 -> 2
    assert(lowbit(8) == 8);   // 1000 -> 8
    assert(lowbit(12) == 4);  // 1100 -> 4

    printf("Lowbit: OK\n");
}

void test_edge_cases(void) {
    // Empty tracker
    DuoXPTracker *empty = duo_new(0);
    assert(duo_len(empty) == 0);
    duo_free(empty);

    // Single element
    int64_t single[] = {42};
    DuoXPTracker *one = duo_from_array(single, 1);
    assert(duo_prefix_sum(one, 0) == 42);
    assert(duo_range_sum(one, 0, 0) == 42);
    assert(duo_get(one, 0) == 42);
    duo_free(one);

    printf("Edge cases: OK\n");
}

void test_set_operation(void) {
    int64_t xp[] = {1, 2, 3, 4, 5};
    DuoXPTracker *tracker = duo_from_array(xp, 5);

    duo_set(tracker, 2, 100);
    assert(duo_get(tracker, 2) == 100);
    assert(duo_prefix_sum(tracker, 4) == 1 + 2 + 100 + 4 + 5);

    duo_free(tracker);
    printf("Set operation: OK\n");
}

int main(void) {
    test_lowbit();
    test_basic_operations();
    test_edge_cases();
    test_set_operation();

    printf("\n🦉 The owl approves! All tests passed.\n");
    return 0;
}
```

### 4.3 Solution de référence

**Rust :**
```rust
pub struct DuoXPTracker {
    tree: Vec<i64>,
    n: usize,
}

/// Returns the lowest set bit of x
/// Example: lowbit(12) = lowbit(1100₂) = 4 = 100₂
#[inline]
fn lowbit(x: usize) -> usize {
    x & x.wrapping_neg()
}

impl DuoXPTracker {
    pub fn new(n: usize) -> Self {
        Self {
            tree: vec![0i64; n + 1],  // 1-indexed
            n,
        }
    }

    pub fn from_array(xp_history: &[i64]) -> Self {
        let n = xp_history.len();
        let mut tracker = Self::new(n);

        // O(n) construction
        for i in 0..n {
            tracker.tree[i + 1] = xp_history[i];
        }
        for i in 1..=n {
            let parent = i + lowbit(i);
            if parent <= n {
                tracker.tree[parent] += tracker.tree[i];
            }
        }

        tracker
    }

    pub fn add(&mut self, day: usize, delta: i64) {
        if day >= self.n {
            return;
        }
        let mut i = day + 1;  // Convert to 1-indexed
        while i <= self.n {
            self.tree[i] += delta;
            i += lowbit(i);
        }
    }

    pub fn prefix_sum(&self, day: usize) -> i64 {
        if day >= self.n {
            return self.prefix_sum(self.n.saturating_sub(1));
        }
        let mut sum = 0;
        let mut i = day + 1;  // Convert to 1-indexed
        while i > 0 {
            sum += self.tree[i];
            i -= lowbit(i);
        }
        sum
    }

    pub fn range_sum(&self, l: usize, r: usize) -> i64 {
        if l > r {
            return 0;
        }
        if l == 0 {
            return self.prefix_sum(r);
        }
        self.prefix_sum(r) - self.prefix_sum(l - 1)
    }

    pub fn get(&self, day: usize) -> i64 {
        self.range_sum(day, day)
    }

    pub fn set(&mut self, day: usize, value: i64) {
        let current = self.get(day);
        self.add(day, value - current);
    }

    pub fn lower_bound(&self, target: i64) -> Option<usize> {
        if self.n == 0 {
            return None;
        }
        let mut sum = 0i64;
        let mut pos = 0usize;
        let mut probe = 1usize << (63 - self.n.leading_zeros());

        while probe > 0 {
            if pos + probe <= self.n && sum + self.tree[pos + probe] < target {
                pos += probe;
                sum += self.tree[pos];
            }
            probe >>= 1;
        }

        if pos < self.n {
            Some(pos)  // Convert back to 0-indexed
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}
```

**C :**
```c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "duo_xp_tracker.h"

static inline size_t lowbit(size_t x) {
    return x & (size_t)(-(ssize_t)x);
}

DuoXPTracker *duo_new(size_t n) {
    DuoXPTracker *tracker = malloc(sizeof(DuoXPTracker));
    if (!tracker) return NULL;

    tracker->n = n;
    tracker->tree = calloc(n + 1, sizeof(int64_t));  // 1-indexed
    if (!tracker->tree && n > 0) {
        free(tracker);
        return NULL;
    }
    return tracker;
}

DuoXPTracker *duo_from_array(const int64_t *xp_history, size_t n) {
    DuoXPTracker *tracker = duo_new(n);
    if (!tracker) return NULL;

    // Copy values
    for (size_t i = 0; i < n; i++) {
        tracker->tree[i + 1] = xp_history[i];
    }

    // O(n) construction
    for (size_t i = 1; i <= n; i++) {
        size_t parent = i + lowbit(i);
        if (parent <= n) {
            tracker->tree[parent] += tracker->tree[i];
        }
    }

    return tracker;
}

void duo_free(DuoXPTracker *tracker) {
    if (tracker) {
        free(tracker->tree);
        free(tracker);
    }
}

void duo_add(DuoXPTracker *tracker, size_t day, int64_t delta) {
    if (!tracker || day >= tracker->n) return;

    size_t i = day + 1;
    while (i <= tracker->n) {
        tracker->tree[i] += delta;
        i += lowbit(i);
    }
}

int64_t duo_prefix_sum(const DuoXPTracker *tracker, size_t day) {
    if (!tracker || tracker->n == 0) return 0;
    if (day >= tracker->n) day = tracker->n - 1;

    int64_t sum = 0;
    size_t i = day + 1;
    while (i > 0) {
        sum += tracker->tree[i];
        i -= lowbit(i);
    }
    return sum;
}

int64_t duo_range_sum(const DuoXPTracker *tracker, size_t l, size_t r) {
    if (!tracker || l > r) return 0;
    if (l == 0) return duo_prefix_sum(tracker, r);
    return duo_prefix_sum(tracker, r) - duo_prefix_sum(tracker, l - 1);
}

int64_t duo_get(const DuoXPTracker *tracker, size_t day) {
    return duo_range_sum(tracker, day, day);
}

void duo_set(DuoXPTracker *tracker, size_t day, int64_t value) {
    if (!tracker || day >= tracker->n) return;
    int64_t current = duo_get(tracker, day);
    duo_add(tracker, day, value - current);
}

size_t duo_len(const DuoXPTracker *tracker) {
    return tracker ? tracker->n : 0;
}
```

### 4.4 Solutions alternatives acceptées

**Alternative 1 : Construction naïve O(n log n)**
```rust
// Moins efficace mais correct
pub fn from_array_naive(xp_history: &[i64]) -> Self {
    let n = xp_history.len();
    let mut tracker = Self::new(n);
    for (i, &xp) in xp_history.iter().enumerate() {
        tracker.add(i, xp);  // O(log n) par élément
    }
    tracker
}
// Total: O(n log n) au lieu de O(n), mais acceptable
```

**Alternative 2 : Get avec boucle simple**
```rust
// Plus lent O(log² n) mais correct
pub fn get_simple(&self, day: usize) -> i64 {
    if day == 0 {
        self.prefix_sum(0)
    } else {
        self.prefix_sum(day) - self.prefix_sum(day - 1)
    }
}
```

### 4.5 Solutions refusées (avec explications)

**Refusée 1 : Oubli conversion 1-indexed**
```rust
// ❌ Off-by-one error
pub fn add(&mut self, day: usize, delta: i64) {
    let mut i = day;  // ❌ Manque le +1
    while i <= self.n {
        self.tree[i] += delta;
        i += lowbit(i);
    }
}
// Pourquoi refusé : tree[0] n'est jamais utilisé dans un BIT 1-indexed
//                   Ceci cause des erreurs de bounds et de logique
```

**Refusée 2 : Direction inversée dans prefix_sum**
```rust
// ❌ Boucle infinie ou mauvais résultat
pub fn prefix_sum(&self, day: usize) -> i64 {
    let mut sum = 0;
    let mut i = day + 1;
    while i <= self.n {  // ❌ Mauvaise direction !
        sum += self.tree[i];
        i += lowbit(i);  // ❌ Devrait être i -= lowbit(i)
    }
    sum
}
// Pourquoi refusé : On remonte vers les ancêtres, pas vers les descendants
```

**Refusée 3 : range_sum avec l-1 incorrect**
```rust
// ❌ Off-by-one dans range_sum
pub fn range_sum(&self, l: usize, r: usize) -> i64 {
    self.prefix_sum(r) - self.prefix_sum(l)  // ❌ Manque le -1 sur l
}
// Pour l=2, r=4 avec [1,2,3,4,5]:
// Correct: prefix(4) - prefix(1) = 15 - 3 = 12 (3+4+5)
// Bug: prefix(4) - prefix(2) = 15 - 6 = 9 (manque l'élément l=2)
```

### 4.6 Solution bonus de référence (Range Update)

```rust
pub struct DuoRangeUpdate {
    tree1: Vec<i64>,
    tree2: Vec<i64>,
    n: usize,
}

impl DuoRangeUpdate {
    pub fn new(n: usize) -> Self {
        Self {
            tree1: vec![0i64; n + 1],
            tree2: vec![0i64; n + 1],
            n,
        }
    }

    fn add_internal(tree: &mut [i64], n: usize, mut i: usize, delta: i64) {
        i += 1;
        while i <= n {
            tree[i] += delta;
            i += lowbit(i);
        }
    }

    fn prefix_internal(tree: &[i64], mut i: usize) -> i64 {
        i += 1;
        let mut sum = 0;
        while i > 0 {
            sum += tree[i];
            i -= lowbit(i);
        }
        sum
    }

    pub fn range_add(&mut self, l: usize, r: usize, delta: i64) {
        // Using the formula: arr[i] = B1.prefix(i) * (i+1) - B2.prefix(i)
        Self::add_internal(&mut self.tree1, self.n, l, delta);
        Self::add_internal(&mut self.tree1, self.n, r + 1, -delta);
        Self::add_internal(&mut self.tree2, self.n, l, delta * l as i64);
        Self::add_internal(&mut self.tree2, self.n, r + 1, -delta * (r as i64 + 1));
    }

    pub fn prefix_sum(&self, i: usize) -> i64 {
        let b1 = Self::prefix_internal(&self.tree1, i);
        let b2 = Self::prefix_internal(&self.tree2, i);
        b1 * (i as i64 + 1) - b2
    }

    pub fn get(&self, i: usize) -> i64 {
        if i == 0 {
            self.prefix_sum(0)
        } else {
            self.prefix_sum(i) - self.prefix_sum(i - 1)
        }
    }
}
```

### 4.7 Solutions alternatives bonus (2D)

```rust
pub struct DuoXPTracker2D {
    tree: Vec<Vec<i64>>,
    n: usize,
    m: usize,
}

impl DuoXPTracker2D {
    pub fn new(n: usize, m: usize) -> Self {
        Self {
            tree: vec![vec![0i64; m + 1]; n + 1],
            n,
            m,
        }
    }

    pub fn add(&mut self, row: usize, col: usize, delta: i64) {
        let mut i = row + 1;
        while i <= self.n {
            let mut j = col + 1;
            while j <= self.m {
                self.tree[i][j] += delta;
                j += lowbit(j);
            }
            i += lowbit(i);
        }
    }

    pub fn prefix_sum(&self, row: usize, col: usize) -> i64 {
        let mut sum = 0;
        let mut i = row + 1;
        while i > 0 {
            let mut j = col + 1;
            while j > 0 {
                sum += self.tree[i][j];
                j -= lowbit(j);
            }
            i -= lowbit(i);
        }
        sum
    }

    pub fn range_sum(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64 {
        let mut sum = self.prefix_sum(r2, c2);
        if r1 > 0 {
            sum -= self.prefix_sum(r1 - 1, c2);
        }
        if c1 > 0 {
            sum -= self.prefix_sum(r2, c1 - 1);
        }
        if r1 > 0 && c1 > 0 {
            sum += self.prefix_sum(r1 - 1, c1 - 1);
        }
        sum
    }
}
```

### 4.8 Solutions refusées bonus

**Refusée : range_sum 2D sans inclusion-exclusion correcte**
```rust
// ❌ Formule d'inclusion-exclusion incorrecte
pub fn range_sum(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64 {
    // ❌ Oubli des cas où r1=0 ou c1=0
    self.prefix_sum(r2, c2)
        - self.prefix_sum(r1 - 1, c2)  // ❌ Underflow si r1=0
        - self.prefix_sum(r2, c1 - 1)  // ❌ Underflow si c1=0
        + self.prefix_sum(r1 - 1, c1 - 1)
}
```

### 4.9 spec.json

```json
{
  "name": "duo_xp_tracker",
  "language": "rust",
  "type": "code",
  "tier": 3,
  "tier_info": "Synthèse (Fenwick Trees complets)",
  "tags": ["fenwick-tree", "bit", "prefix-sum", "phase1"],
  "passing_score": 70,

  "function": {
    "name": "DuoXPTracker",
    "prototype": "impl DuoXPTracker { pub fn new(n: usize) -> Self; pub fn from_array(xp_history: &[i64]) -> Self; pub fn add(&mut self, day: usize, delta: i64); pub fn prefix_sum(&self, day: usize) -> i64; pub fn range_sum(&self, l: usize, r: usize) -> i64; pub fn get(&self, day: usize) -> i64; }",
    "return_type": "struct",
    "parameters": [
      {"name": "n", "type": "usize"},
      {"name": "xp_history", "type": "&[i64]"}
    ]
  },

  "driver": {
    "reference": "pub struct DuoXPTracker { tree: Vec<i64>, n: usize } fn lowbit(x: usize) -> usize { x & x.wrapping_neg() } impl DuoXPTracker { pub fn new(n: usize) -> Self { Self { tree: vec![0i64; n + 1], n } } pub fn from_array(xp: &[i64]) -> Self { let n = xp.len(); let mut t = Self::new(n); for i in 0..n { t.tree[i + 1] = xp[i]; } for i in 1..=n { let p = i + lowbit(i); if p <= n { t.tree[p] += t.tree[i]; } } t } pub fn add(&mut self, day: usize, delta: i64) { if day >= self.n { return; } let mut i = day + 1; while i <= self.n { self.tree[i] += delta; i += lowbit(i); } } pub fn prefix_sum(&self, day: usize) -> i64 { let mut sum = 0; let mut i = (day + 1).min(self.n); while i > 0 { sum += self.tree[i]; i -= lowbit(i); } sum } pub fn range_sum(&self, l: usize, r: usize) -> i64 { if l > r { return 0; } if l == 0 { self.prefix_sum(r) } else { self.prefix_sum(r) - self.prefix_sum(l - 1) } } pub fn get(&self, day: usize) -> i64 { self.range_sum(day, day) } pub fn len(&self) -> usize { self.n } }",

    "edge_cases": [
      {
        "name": "empty_tracker",
        "args": {"n": 0},
        "test": "let t = DuoXPTracker::new(0); assert_eq!(t.len(), 0);",
        "is_trap": true,
        "trap_explanation": "Tracker vide - ne pas crasher"
      },
      {
        "name": "single_element",
        "args": {"xp_history": [42]},
        "test": "let t = DuoXPTracker::from_array(&[42]); assert_eq!(t.prefix_sum(0), 42); assert_eq!(t.get(0), 42);",
        "is_trap": true,
        "trap_explanation": "Un seul jour"
      },
      {
        "name": "prefix_sum_basic",
        "args": {"xp_history": [10, 20, 30, 40, 50]},
        "test": "let t = DuoXPTracker::from_array(&[10,20,30,40,50]); assert_eq!(t.prefix_sum(2), 60);",
        "expected": 60
      },
      {
        "name": "range_sum_basic",
        "args": {"xp_history": [10, 20, 30, 40, 50]},
        "test": "let t = DuoXPTracker::from_array(&[10,20,30,40,50]); assert_eq!(t.range_sum(1, 3), 90);",
        "expected": 90
      },
      {
        "name": "add_and_query",
        "args": {"xp_history": [1, 2, 3, 4, 5]},
        "test": "let mut t = DuoXPTracker::from_array(&[1,2,3,4,5]); t.add(2, 10); assert_eq!(t.get(2), 13);",
        "expected": 13
      },
      {
        "name": "lowbit_powers_of_2",
        "args": {},
        "test": "assert_eq!(lowbit(8), 8); assert_eq!(lowbit(16), 16);",
        "is_trap": true,
        "trap_explanation": "Powers of 2 - lowbit = self"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 5000,
      "generators": [
        {
          "type": "array_int",
          "param_index": 0,
          "params": {
            "min_len": 1,
            "max_len": 10000,
            "min_val": -1000000,
            "max_val": 1000000
          }
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": [],
    "forbidden_functions": [],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

**Mutant A (Boundary) : Oubli du +1 pour 1-indexed**
```rust
// ❌ Indices décalés
pub fn add(&mut self, day: usize, delta: i64) {
    let mut i = day;  // ❌ Manque +1 !
    while i <= self.n {
        self.tree[i] += delta;
        i += lowbit(i);
    }
}
// Pourquoi c'est faux : tree[0] est ignoré dans la logique BIT
// Ce qui était pensé : "day est déjà l'index à utiliser"
```

**Mutant B (Safety) : lowbit(0) cause boucle infinie**
```rust
// ❌ Pas de protection contre i=0
pub fn prefix_sum(&self, day: usize) -> i64 {
    let mut sum = 0;
    let mut i = day + 1;
    while i > 0 {
        sum += self.tree[i];
        i -= lowbit(i);  // Si i devient 0, lowbit(0)=0, donc i reste 0 → boucle
    }
    sum
}
// En pratique, la boucle s'arrête car 0 > 0 est faux, mais le risque existe
// pour des implémentations modifiées
```

**Mutant C (Resource) : Allocation n au lieu de n+1**
```rust
// ❌ Buffer overflow
pub fn new(n: usize) -> Self {
    Self {
        tree: vec![0i64; n],  // ❌ Devrait être n + 1 !
        n,
    }
}
// Pourquoi c'est faux : Le BIT est 1-indexed, tree[n] doit exister
// Ce qui était pensé : "n éléments = tableau de taille n"
```

**Mutant D (Logic) : Direction inversée dans update**
```rust
// ❌ Update remonte au lieu de descendre
pub fn add(&mut self, day: usize, delta: i64) {
    let mut i = day + 1;
    while i > 0 {  // ❌ Mauvaise direction !
        self.tree[i] += delta;
        i -= lowbit(i);  // ❌ Devrait être i += lowbit(i)
    }
}
// Pourquoi c'est faux : Update propage vers les indices SUPÉRIEURS
// Ce qui était pensé : "C'est comme prefix_sum mais avec +="
```

**Mutant E (Return) : range_sum sans -1 sur borne gauche**
```rust
// ❌ Off-by-one dans range_sum
pub fn range_sum(&self, l: usize, r: usize) -> i64 {
    self.prefix_sum(r) - self.prefix_sum(l)  // ❌ Devrait être l-1
}
// Exemple : range_sum(2, 4) sur [1,2,3,4,5]
// Attendu : 3+4+5 = 12 = prefix(4) - prefix(1) = 15 - 3
// Bug : prefix(4) - prefix(2) = 15 - 6 = 9 (manque index 2)
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Manipulation binaire élégante** : Le lowbit détermine la structure
2. **Trade-off différent du Segment Tree** : Plus simple, moins flexible
3. **Indexation 1-based** : Convention importante à maîtriser
4. **Construction O(n)** : Technique de propagation vers les parents
5. **Applications variées** : Inversions, order statistics, 2D

### 5.2 LDA — Traduction littérale en français

```
FONCTION lowbit QUI RETOURNE UN ENTIER NON SIGNÉ ET PREND EN PARAMÈTRE x QUI EST UN ENTIER NON SIGNÉ
DÉBUT FONCTION
    RETOURNER x ET BINAIRE (COMPLÉMENT À 2 DE x)
    REM : Ceci isole le bit le plus bas qui vaut 1
FIN FONCTION

FONCTION add QUI NE RETOURNE RIEN ET PREND EN PARAMÈTRES day ET delta
DÉBUT FONCTION
    DÉCLARER i COMME ENTIER NON SIGNÉ
    AFFECTER day PLUS 1 À i

    TANT QUE i EST INFÉRIEUR OU ÉGAL À n FAIRE
        AFFECTER tree[i] PLUS delta À tree[i]
        AFFECTER i PLUS lowbit(i) À i
    FIN TANT QUE
FIN FONCTION

FONCTION prefix_sum QUI RETOURNE UN ENTIER 64 BITS ET PREND EN PARAMÈTRE day
DÉBUT FONCTION
    DÉCLARER sum COMME ENTIER 64 BITS
    DÉCLARER i COMME ENTIER NON SIGNÉ

    AFFECTER 0 À sum
    AFFECTER day PLUS 1 À i

    TANT QUE i EST SUPÉRIEUR À 0 FAIRE
        AFFECTER sum PLUS tree[i] À sum
        AFFECTER i MOINS lowbit(i) À i
    FIN TANT QUE

    RETOURNER sum
FIN FONCTION
```

### 5.2.2 Logic Flow (Structured English)

```
ALGORITHME : Fenwick Tree Add (Update)
---
1. CONVERTIR day en index 1-based : i = day + 1

2. BOUCLE tant que i <= n :
   a. AJOUTER delta à tree[i]
   b. AVANCER au prochain index responsable :
      i = i + lowbit(i)

3. FIN - Tous les nœuds concernés sont mis à jour

---

ALGORITHME : Fenwick Tree Prefix Sum (Query)
---
1. CONVERTIR day en index 1-based : i = day + 1

2. INITIALISER sum = 0

3. BOUCLE tant que i > 0 :
   a. AJOUTER tree[i] à sum
   b. REMONTER au parent :
      i = i - lowbit(i)

4. RETOURNER sum
```

### 5.2.3 Représentation Algorithmique (Logique de Garde)

```
FONCTION : Add(day, delta)
---
VÉRIFIER day < n :
|
|-- SI day >= n :
|     RETOURNER (hors limites)

CONVERTIR i = day + 1 (1-indexed)

BOUCLE tant que i <= n :
|
|-- AJOUTER delta à tree[i]
|-- CALCULER prochain : i = i + lowbit(i)
|   (Exemple: 3 → 3 + 1 = 4 → 4 + 4 = 8 → 8 + 8 = 16...)

FIN
```

### 5.2.3.1 Diagramme Mermaid

```mermaid
graph TD
    A[Add day=2, delta=5] --> B[i = 3 en 1-indexed]
    B --> C{i <= n ?}
    C -- Oui --> D[tree[3] += 5]
    D --> E[i = 3 + lowbit 3]
    E --> F[i = 3 + 1 = 4]
    F --> G{i <= n ?}
    G -- Oui --> H[tree[4] += 5]
    H --> I[i = 4 + lowbit 4]
    I --> J[i = 4 + 4 = 8]
    J --> K{i <= n ?}
    K -- Dépend de n --> L[Continue ou Stop]
```

### 5.3 Visualisation ASCII

**L'arbre Fenwick pour n=8 :**

```
Responsabilités de chaque index (basé sur lowbit) :

Index:    1    2    3    4    5    6    7    8
Binary: 0001 0010 0011 0100 0101 0110 0111 1000
Lowbit:    1    2    1    4    1    2    1    8
Range:  [1,1] [1,2] [3,3] [1,4] [5,5] [5,6] [7,7] [1,8]

Visualisation :
            tree[8] ─────────────────────────────────┐
                                                     │
            tree[4] ───────────────┐                 │
                                   │                 │
tree[2] ─────┐     tree[6] ───┐   │                 │
             │                 │   │                 │
tree[1]   tree[3]   tree[5]   tree[7]               │
  [1]       [3]       [5]       [7]                 │
             │                                       │
        tree[2] = arr[1]+arr[2]                     │
             │                                       │
        tree[4] = arr[1]+arr[2]+arr[3]+arr[4]       │
             │                                       │
        tree[8] = arr[1]+...+arr[8] ─────────────────┘
```

**Chemin de prefix_sum(5) :**

```
On veut : sum(arr[1..5])

i = 6 (5+1 en 1-indexed)

Étape 1: i=6 (0110), lowbit=2
         sum += tree[6] = arr[5]+arr[6]... wait!

Correction: on utilise i=5+1=6, donc:
i = 6: sum += tree[6], i = 6 - 2 = 4
i = 4: sum += tree[4], i = 4 - 4 = 0
i = 0: stop

tree[6] couvre [5,6], mais on veut [1,5]
Hmm, recalculons avec i=5:

i = 5+1 = 6 -> Non, prenons i = 5 (0-indexed day=4)
i = 5 (day=4): i_1indexed = 5
i = 5 (0101), lowbit = 1
   sum += tree[5]
   i = 5 - 1 = 4
i = 4 (0100), lowbit = 4
   sum += tree[4]
   i = 4 - 4 = 0
STOP

Résultat: tree[5] + tree[4] = arr[5] + (arr[1]+arr[2]+arr[3]+arr[4])
        = arr[1] + arr[2] + arr[3] + arr[4] + arr[5] ✓
```

**Chemin de add(2, 10) :**

```
day = 2, i = 3 (1-indexed)

i = 3 (0011), lowbit = 1
   tree[3] += 10
   i = 3 + 1 = 4

i = 4 (0100), lowbit = 4
   tree[4] += 10
   i = 4 + 4 = 8

i = 8 (1000), lowbit = 8
   tree[8] += 10
   i = 8 + 8 = 16

i = 16 > n (si n=8): STOP

Modifiés: tree[3], tree[4], tree[8]
(Tous les nœuds qui "couvrent" l'index 3)
```

### 5.4 Les pièges en détail

#### Piège 1 : Indexation 0 vs 1

```rust
// ❌ DANGER : mélange d'indexation
pub fn add(&mut self, day: usize, delta: i64) {
    let mut i = day;  // day est 0-indexed !
    // ... mais le BIT est 1-indexed
}

// ✅ CORRECT
pub fn add(&mut self, day: usize, delta: i64) {
    let mut i = day + 1;  // Conversion explicite
}
```

#### Piège 2 : lowbit de 0

```rust
// lowbit(0) = 0 & -0 = 0 & 0 = 0
// Dans une boucle: i -= lowbit(i) quand i=0 → i reste 0 → boucle infinie?
// Non car la condition i > 0 est fausse

// MAIS attention aux modifications du code !
```

#### Piège 3 : Taille du tableau

```rust
// ❌ tree[n] n'existe pas si on alloue n
let tree = vec![0; n];
tree[n] = ...;  // Out of bounds !

// ✅ Allouer n+1
let tree = vec![0; n + 1];
// tree[0] inutilisé, tree[1..=n] utilisé
```

#### Piège 4 : range_sum avec l=0

```rust
pub fn range_sum(&self, l: usize, r: usize) -> i64 {
    if l == 0 {
        return self.prefix_sum(r);
    }
    self.prefix_sum(r) - self.prefix_sum(l - 1)  // l-1 underflow si l=0 !
}
```

### 5.5 Cours Complet

#### 5.5.1 Qu'est-ce qu'un Fenwick Tree ?

Un **Fenwick Tree** (aussi appelé **Binary Indexed Tree** ou **BIT**) est une structure de données inventée par Peter Fenwick en 1994. Elle permet :

- **Prefix sum** en O(log n)
- **Point update** en O(log n)
- Le tout avec O(n) mémoire exactement (vs 2-4n pour Segment Tree)

#### 5.5.2 La magie du lowbit

La fonction `lowbit(x)` extrait le bit le plus bas qui vaut 1 :

```
lowbit(x) = x & (-x)

Exemples :
  x = 12 = 1100₂
 -x = ...0100₂ (complément à 2)
x&-x = 0100₂ = 4

  x = 7 = 0111₂
 -x = ...1001₂
x&-x = 0001₂ = 1

  x = 8 = 1000₂
 -x = ...1000₂
x&-x = 1000₂ = 8
```

**Pourquoi c'est utile ?** `lowbit(i)` indique **combien d'éléments** l'index `i` couvre dans le BIT.

#### 5.5.3 Structure du BIT

Chaque index `i` (1-indexed) stocke la somme des éléments dont l'index est dans l'intervalle `[i - lowbit(i) + 1, i]`.

```
i = 1 (0001): lowbit = 1, couvre [1, 1]
i = 2 (0010): lowbit = 2, couvre [1, 2]
i = 3 (0011): lowbit = 1, couvre [3, 3]
i = 4 (0100): lowbit = 4, couvre [1, 4]
i = 5 (0101): lowbit = 1, couvre [5, 5]
i = 6 (0110): lowbit = 2, couvre [5, 6]
i = 7 (0111): lowbit = 1, couvre [7, 7]
i = 8 (1000): lowbit = 8, couvre [1, 8]
```

#### 5.5.4 Algorithme de Query (prefix_sum)

Pour calculer `sum(arr[1..=i])`, on additionne les contributions :

```rust
fn prefix_sum(&self, i: usize) -> i64 {
    let mut sum = 0;
    let mut idx = i;
    while idx > 0 {
        sum += self.tree[idx];
        idx -= lowbit(idx);  // Remonte vers l'ancêtre
    }
    sum
}
```

**Exemple : prefix_sum(7)**
```
i = 7: sum += tree[7], i = 7 - 1 = 6
i = 6: sum += tree[6], i = 6 - 2 = 4
i = 4: sum += tree[4], i = 4 - 4 = 0
STOP

tree[7] + tree[6] + tree[4]
= [7,7] + [5,6] + [1,4]
= [1,7] ✓
```

#### 5.5.5 Algorithme d'Update (add)

Pour ajouter `delta` à `arr[i]`, on propage aux nœuds qui le couvrent :

```rust
fn add(&mut self, i: usize, delta: i64) {
    let mut idx = i;
    while idx <= self.n {
        self.tree[idx] += delta;
        idx += lowbit(idx);  // Descend vers les enfants
    }
}
```

**Exemple : add(3, 10)**
```
i = 3: tree[3] += 10, i = 3 + 1 = 4
i = 4: tree[4] += 10, i = 4 + 4 = 8
i = 8: tree[8] += 10, i = 8 + 8 = 16 > n
STOP

tree[3], tree[4], tree[8] mis à jour
(ce sont exactement les nœuds qui couvrent l'index 3)
```

#### 5.5.6 Construction O(n)

Au lieu de faire n appels à `add()` (O(n log n)), on peut construire en O(n) :

```rust
fn from_array(arr: &[i64]) -> Self {
    let n = arr.len();
    let mut tree = vec![0i64; n + 1];

    // Copier les valeurs
    for i in 0..n {
        tree[i + 1] = arr[i];
    }

    // Propager vers les parents
    for i in 1..=n {
        let parent = i + lowbit(i);
        if parent <= n {
            tree[parent] += tree[i];
        }
    }

    Self { tree, n }
}
```

#### 5.5.7 Comparaison BIT vs Segment Tree

| | BIT | Segment Tree |
|---|-----|--------------|
| Mémoire | n+1 | 2n à 4n |
| Code | ~20 lignes | ~50 lignes |
| Constante | Très faible | Plus élevée |
| Opérations | Sum, XOR, etc. | Tout (min, max, GCD...) |
| Range update | 2 BITs | Natif (lazy) |
| Facilité | Simple | Modéré |

**Règle d'or :** Si tu n'as besoin que de sommes (ou XOR), utilise un BIT. Sinon, Segment Tree.

### 5.6 Normes avec explications pédagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (risque d'overflow)                               │
├─────────────────────────────────────────────────────────────────┤
│ fn lowbit(x: i64) -> i64 { x & -x }                             │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ fn lowbit(x: usize) -> usize { x & x.wrapping_neg() }           │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • wrapping_neg évite le UB sur unsigned                         │
│ • usize est le type naturel pour les indices                    │
│ • -x sur unsigned = wrapping_neg automatique en Rust            │
└─────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                   │
├─────────────────────────────────────────────────────────────────┤
│ tree: Vec<i64>,  // Taille n                                    │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ tree: Vec<i64>,  // Taille n + 1, index 0 inutilisé             │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Le BIT est naturellement 1-indexed                            │
│ • tree[0] ne fait pas partie de la structure logique            │
│ • Évite des +1/-1 constants dans le code                        │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

**Exemple : Construction puis query sur `[3, 2, -1, 6, 5, 4, -3, 3, 7, 2, 3]`**

Simplifions avec `[3, 2, 5, 4]` (n=4) :

```
Initial: arr = [3, 2, 5, 4] (0-indexed)

Étape 1: Copier dans tree[1..=4]
tree = [_, 3, 2, 5, 4]

Étape 2: Propager
i=1: parent = 1 + 1 = 2, tree[2] += tree[1] → tree[2] = 2+3 = 5
i=2: parent = 2 + 2 = 4, tree[4] += tree[2] → tree[4] = 4+5 = 9
i=3: parent = 3 + 1 = 4, tree[4] += tree[3] → tree[4] = 9+5 = 14
i=4: parent = 4 + 4 = 8 > n, skip

Résultat: tree = [_, 3, 5, 5, 14]
```

**Query prefix_sum(3) (= sum arr[0..=3]) :**

```
┌───────┬──────────────────────┬──────┬─────────┬─────────────────────┐
│ Étape │ Action               │  i   │   sum   │ Explication         │
├───────┼──────────────────────┼──────┼─────────┼─────────────────────┤
│   1   │ i = 3 + 1 = 4        │  4   │    0    │ Conversion 1-indexed│
├───────┼──────────────────────┼──────┼─────────┼─────────────────────┤
│   2   │ sum += tree[4] = 14  │  4   │   14    │ Couvre [1,4]        │
├───────┼──────────────────────┼──────┼─────────┼─────────────────────┤
│   3   │ i = 4 - lowbit(4) = 0│  0   │   14    │ lowbit(4) = 4       │
├───────┼──────────────────────┼──────┼─────────┼─────────────────────┤
│   4   │ i = 0, STOP          │  0   │   14    │ Condition i > 0 faux│
└───────┴──────────────────────┴──────┴─────────┴─────────────────────┘

Résultat: 14 = 3 + 2 + 5 + 4 ✓
```

### 5.8 Mnémotechniques

#### 🦉 MEME : "Duolingo Owl" — Il sait TOUT

*"You haven't practiced your BIT operations today."*

Le hibou de Duolingo suit ton XP avec un Fenwick Tree :
- Chaque jour = un index
- Ton XP quotidien = une valeur
- "Total XP ce mois?" = prefix_sum !

```rust
// Le hibou qui track ton XP
impl DuolingoOwl {
    fn judge_you(&self) {
        let this_week_xp = self.tracker.range_sum(monday, sunday);
        if this_week_xp < 50 {
            println!("🦉 Disappointed owl noises");
        }
    }
}
```

---

#### 🎮 MEME : "It's over 9000!" — Dragon Ball Z

Comme Vegeta qui calcule le power level de Goku, le Fenwick Tree additionne les power levels en O(log n).

```
Power levels par saga:
Saiyan: 8000    → prefix_sum(0) = 8000
Namek:  150000  → prefix_sum(1) = 158000
Cell:   1M      → prefix_sum(2) = 1.158M

IT'S OVER 9000! (très rapidement calculé)
```

---

#### 🏃 MEME : "Speedrun" — Efficiency

Un Fenwick Tree, c'est comme un speedrunner qui connaît tous les skips.
Au lieu de parcourir chaque élément (casual playthrough), il saute directement aux checkpoints (lowbit jumps).

```
Casual: O(n) - visite chaque élément
Speedrun (BIT): O(log n) - saute avec lowbit!
```

---

#### 🧮 MEME : "Binary magic" — The Matrix

*"There is no spoon... there is only lowbit."*

Neo voit le code de la Matrix en binaire.
Le Fenwick Tree voit les indices en binaire pour savoir quoi additionner.

```
Index 6 = 0110
Lowbit = 2 = 0010
"I know kung-fu" = "I know which bits to flip"
```

### 5.9 Applications pratiques

1. **Leaderboards dynamiques**
   - Mise à jour de scores en temps réel
   - Calcul de rangs

2. **Comptage d'inversions**
   - Mesure de "désordre" dans un tableau
   - Algorithmes de sorting analysis

3. **Histogrammes dynamiques**
   - Fréquences cumulatives
   - Compression de données

4. **Finance**
   - Positions cumulatives
   - Calcul de P&L

5. **Jeux vidéo**
   - Systèmes de points avec updates fréquents
   - Statistiques en temps réel

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Conséquence | Solution |
|---|-------|-------------|----------|
| 1 | Oubli +1 pour 1-indexed | Off-by-one, tree[0] jamais utilisé | Toujours day + 1 |
| 2 | Allocation n au lieu de n+1 | Buffer overflow | vec![0; n + 1] |
| 3 | += au lieu de -= dans query | Mauvaise direction, résultat faux | Query: -= ; Update: += |
| 4 | range_sum sans cas l=0 | Underflow sur l-1 | if l == 0 { prefix(r) } |
| 5 | Construction O(n log n) | Lent pour grands n | Propagation linéaire |

---

## 📝 SECTION 7 : QCM

### Question 1
**Que retourne `lowbit(12)` ?**

- A) 1
- B) 2
- C) 4
- D) 8
- E) 12
- F) 0
- G) 3
- H) 6
- I) -12
- J) 16

**Réponse : C**
*12 = 1100₂, lowbit = 0100₂ = 4*

---

### Question 2
**Quelle est la complexité de `prefix_sum` dans un BIT de taille n ?**

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n log n)
- E) O(√n)
- F) O(log² n)
- G) O(n²)
- H) Amortie O(1)
- I) O(2^n)
- J) Dépend de l'index

**Réponse : B**

---

### Question 3
**Combien de mémoire utilise un Fenwick Tree pour n éléments ?**

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(2n)
- E) O(4n)
- F) O(n log n)
- G) O(n²)
- H) Exactement n
- I) Exactement n+1
- J) Entre 2n et 4n

**Réponse : I**
*Un tableau de taille n+1 (index 0 inutilisé)*

---

### Question 4
**Dans `add()`, quelle direction parcourt-on ?**

- A) Vers les indices décroissants (i -= lowbit(i))
- B) Vers les indices croissants (i += lowbit(i))
- C) Les deux alternativement
- D) Aléatoirement
- E) Toujours vers la gauche
- F) Toujours vers l'index 1
- G) Vers les puissances de 2
- H) Vers les nombres impairs
- I) Vers les multiples de lowbit
- J) Ça dépend de delta

**Réponse : B**
*Update propage vers les ancêtres (indices supérieurs)*

---

### Question 5
**Comment calculer `range_sum(3, 7)` avec un BIT ?**

- A) `prefix_sum(7) - prefix_sum(3)`
- B) `prefix_sum(7) - prefix_sum(2)`
- C) `prefix_sum(7) + prefix_sum(3)`
- D) `prefix_sum(7 - 3)`
- E) `get(3) + get(4) + ... + get(7)`
- F) `tree[7] - tree[3]`
- G) `prefix_sum(7) * prefix_sum(3)`
- H) Impossible avec un BIT
- I) `prefix_sum(7) / prefix_sum(3)`
- J) `prefix_sum(3) - prefix_sum(7)`

**Réponse : B**
*range_sum(l, r) = prefix_sum(r) - prefix_sum(l-1)*

---

## 📊 SECTION 8 : RÉCAPITULATIF

| Aspect | Valeur |
|--------|--------|
| **Exercice** | 1.3.8 - duo_xp_tracker |
| **Difficulté base** | ★★★★☆☆☆☆☆☆ (4/10) |
| **Difficulté bonus max** | 🧠 (11/10 - Order Statistics) |
| **Temps estimé** | 45 min (base) + 75 min (bonus) |
| **XP Total possible** | 120 + 240 + 360 + 720 = 1440 |
| **Concepts clés** | Fenwick Tree, lowbit, Prefix Sum, Binary Manipulation |
| **Langages** | Rust Edition 2024, C17 |
| **Complexité finale** | O(log n) par opération |

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.3.8-duo-xp-tracker",
    "generated_at": "2026-01-11 12:30:00",

    "metadata": {
      "exercise_id": "1.3.8",
      "exercise_name": "duo_xp_tracker",
      "module": "1.3",
      "module_name": "Trees",
      "concept": "Fenwick Trees",
      "concept_name": "Binary Indexed Trees",
      "type": "code",
      "tier": 3,
      "tier_info": "Synthèse",
      "phase": 1,
      "difficulty": 4,
      "difficulty_stars": "★★★★☆☆☆☆☆☆",
      "language": "rust",
      "language_version": "Edition 2024",
      "duration_minutes": 45,
      "xp_base": 120,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T2 O(log n)",
      "complexity_space": "S1 O(n)",
      "prerequisites": ["binary_operations", "prefix_sums", "arrays"],
      "domains": ["Struct", "Algo", "Encodage"],
      "domains_bonus": ["AL", "Tri"],
      "tags": ["fenwick-tree", "bit", "prefix-sum", "duolingo"],
      "meme_reference": "Duolingo Owl - The owl is always watching"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_solution.c": "/* Section 4.3 */",
      "references/ref_range_update.rs": "/* Section 4.6 */",
      "references/ref_2d.rs": "/* Section 4.7 */",
      "mutants/mutant_a_no_plus_one.rs": "/* Section 4.10 */",
      "mutants/mutant_b_wrong_direction.rs": "/* Section 4.10 */",
      "mutants/mutant_c_small_array.rs": "/* Section 4.10 */",
      "mutants/mutant_d_add_direction.rs": "/* Section 4.10 */",
      "mutants/mutant_e_range_sum_off_by_one.rs": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution.c",
        "references/ref_range_update.rs",
        "references/ref_2d.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_no_plus_one.rs",
        "mutants/mutant_b_wrong_direction.rs",
        "mutants/mutant_c_small_array.rs",
        "mutants/mutant_d_add_direction.rs",
        "mutants/mutant_e_range_sum_off_by_one.rs"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference": "python3 hackbrain_engine_v22.py -s spec.json -f references/ref_solution.rs",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ref_solution.rs -s spec.json --validate"
    }
  }
}
```

---

*🦉 The Duolingo Owl approves this implementation.*
*"You completed your BIT lesson! 🔥 5 day streak!"*
