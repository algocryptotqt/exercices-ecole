<thinking>
## Analyse du Concept
- Concept : Segment Trees (arbres de segments)
- Phase demandée : 1 (Structures de données avancées)
- Adapté ? OUI - Les segment trees sont fondamentaux pour les requêtes de plage en O(log n)

## Combo Base + Bonus
- Exercice de base : Segment Tree basique avec sum query et point update
- Bonus Standard : Lazy propagation pour range updates
- Bonus Expert : Segment Tree 2D pour matrices
- Bonus Génie : Persistent Segment Tree avec time travel
- Palier bonus : ⚡ → 🔥 → 🧠
- Progression logique ? OUI - Du simple au persistant

## Prérequis & Difficulté
- Prérequis réels : Arbres binaires, récursivité, division intervalle
- Difficulté estimée : 5/10 (base), 7/10 (lazy), 9/10 (persistent)
- Cohérent avec phase ? OUI

## Aspect Fun/Culture
- Contexte choisi : "The Library of Wan Shi Tong" (Avatar: The Last Airbender)
- MEME mnémotechnique : "He who knows ten thousand things" - comme le Segment Tree qui peut répondre à toute requête de plage
- Pourquoi c'est fun : La bibliothèque organise les connaissances en segments, permet des recherches par range, a plusieurs étages (2D), et a une histoire (persistent). L'analogie est PARFAITE.

## Scénarios d'Échec (5 mutants concrets)
1. Mutant A (Boundary) : `mid = (start + end) / 2` avec overflow pour grands indices → `mid = start + (end - start) / 2`
2. Mutant B (Safety) : Oubli de push_down avant query dans lazy tree → résultats incorrects
3. Mutant C (Resource) : Allocation de 4*n au lieu de 2*n arrondi à puissance de 2 → dépassement mémoire
4. Mutant D (Logic) : Condition `if (right < start || left > end)` inversée → récursion infinie
5. Mutant E (Return) : Retourner 0 au lieu de identity pour range vide → faux résultat pour min/max

## Verdict
VALIDE - L'exercice est excellent avec une analogie parfaite entre la bibliothèque de Wan Shi Tong et les Segment Trees.
Note qualité: 97/100
</thinking>

---

# Exercice 1.3.7 : wan_shi_tong_library

**Module :**
1.3.7 — Segment Trees

**Concept :**
a-n — Construction, requêtes de plage, mises à jour paresseuses, 2D, persistance

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
3 — Synthèse (tous concepts des segment trees)

**Langage :**
Rust Edition 2024, C17

**Prérequis :**
- Arbres binaires (1.3.1)
- Récursivité
- Concepts de division d'intervalles

**Domaines :**
Struct, Algo, MD

**Durée estimée :**
60 min

**XP Base :**
150

**Complexité :**
T[2] O(n) construction, O(log n) query/update × S[2] O(n)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- Rust : `src/lib.rs`, `Cargo.toml`
- C : `wan_shi_tong.c`, `wan_shi_tong.h`

**Fonctions autorisées :**
- Rust : std uniquement
- C : `malloc`, `free`, `realloc`, `memset`, `memcpy`

**Fonctions interdites :**
- Bibliothèques externes de segment trees
- `qsort` (pour certains algorithmes associés)

---

### 1.2 Consigne

#### 🎮 Version Culture : "The Library of Wan Shi Tong"

**🦉 Avatar: The Last Airbender — L'esprit qui sait dix mille choses**

Dans les profondeurs du désert Si Wong, cachée sous les dunes, se trouve la bibliothèque de **Wan Shi Tong**, l'antique esprit-hibou qui a collecté des millénaires de savoir. Chaque aile de la bibliothèque contient des sections de parchemins, organisées par domaine de connaissance.

Wan Shi Tong te confie une tâche sacrée : créer un système de catalogage qui permette de :
1. **Interroger** instantanément le nombre de parchemins dans une section de la bibliothèque
2. **Mettre à jour** quand de nouveaux parchemins arrivent
3. **Modifier des sections entières** quand une branche du savoir évolue

*"You think you're the first person to believe their war was justified?"* — Wan Shi Tong

Ton système devra être aussi rapide que le vol d'un hibou : O(log n) pour chaque opération, pas un battement d'aile de plus.

---

#### 📖 Version Académique : Segment Tree pour requêtes de plage

**Ta mission :**

Implémenter une structure `WanShiTongLibrary` (Segment Tree) qui permet :
1. De construire l'arbre à partir d'un tableau de valeurs
2. D'effectuer des requêtes de somme sur un intervalle [left, right]
3. De mettre à jour une valeur à un index donné
4. De récupérer la valeur à un index spécifique

**Entrée :**
- `scrolls: &[i64]` : Tableau initial des quantités de parchemins par section
- `left: usize`, `right: usize` : Bornes de l'intervalle de requête (inclusives)
- `index: usize` : Position à mettre à jour ou consulter
- `value: i64` : Nouvelle valeur pour mise à jour

**Sortie :**
- `query(left, right) -> i64` : Somme des éléments dans l'intervalle
- `get(index) -> i64` : Valeur à l'index donné
- `update(index, value)` : Modifie la valeur à l'index

**Contraintes :**
- Construction en O(n)
- Requêtes et mises à jour en O(log n)
- L'arbre utilise un tableau de taille 4 * n pour stockage implicite
- Les indices sont 0-based (de 0 à n-1)

**Exemples :**

| Opération | Résultat | Explication |
|-----------|----------|-------------|
| `new([1, 3, 5, 7, 9, 11])` | Arbre construit | 6 sections |
| `query(0, 5)` | `36` | 1+3+5+7+9+11 |
| `query(1, 3)` | `15` | 3+5+7 |
| `get(2)` | `5` | Section index 2 |
| `update(2, 10)` | — | 5 → 10 |
| `query(0, 5)` | `41` | 1+3+10+7+9+11 |

---

### 1.3 Prototype

**Rust :**
```rust
pub struct WanShiTongLibrary {
    tree: Vec<i64>,
    n: usize,
}

impl WanShiTongLibrary {
    /// Construit la bibliothèque à partir des quantités de parchemins
    pub fn new(scrolls: &[i64]) -> Self;

    /// Requête de somme sur l'intervalle [left, right] inclus
    pub fn query(&self, left: usize, right: usize) -> i64;

    /// Met à jour la section à l'index avec une nouvelle valeur
    pub fn update(&mut self, index: usize, value: i64);

    /// Récupère la valeur à l'index donné
    pub fn get(&self, index: usize) -> i64;

    /// Nombre de sections dans la bibliothèque
    pub fn len(&self) -> usize;

    /// La bibliothèque est-elle vide ?
    pub fn is_empty(&self) -> bool;
}
```

**C :**
```c
typedef struct {
    int64_t *tree;
    size_t n;
    size_t tree_size;
} WanShiTongLibrary;

// Construction et destruction
WanShiTongLibrary *wst_library_new(const int64_t *scrolls, size_t n);
void wst_library_free(WanShiTongLibrary *lib);

// Requêtes
int64_t wst_query(const WanShiTongLibrary *lib, size_t left, size_t right);
int64_t wst_get(const WanShiTongLibrary *lib, size_t index);

// Mises à jour
void wst_update(WanShiTongLibrary *lib, size_t index, int64_t value);

// Utilitaires
size_t wst_len(const WanShiTongLibrary *lib);
int wst_is_empty(const WanShiTongLibrary *lib);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'origine des Segment Trees

Les Segment Trees ont été développés dans les années 1970 pour résoudre des problèmes de géométrie computationnelle. Ils sont devenus un outil fondamental dans :

- **Les jeux vidéo** : Détection de collisions, visibilité
- **Les bases de données** : Requêtes de plage (range queries)
- **La finance** : Analyse de séries temporelles
- **Les concours de programmation** : Structure incontournable

### 2.2 Pourquoi pas un simple tableau ?

| Opération | Tableau naïf | Segment Tree |
|-----------|--------------|--------------|
| Construction | O(n) | O(n) |
| Requête de plage | O(n) | **O(log n)** |
| Mise à jour ponctuelle | O(1) | O(log n) |
| Mise à jour de plage | O(n) | **O(log n)** (lazy) |

Quand on a beaucoup de requêtes de plage, le Segment Tree est imbattable !

### 2.5 DANS LA VRAIE VIE

**Data Engineers / Backend Developers :**
- Agrégation de métriques en temps réel (CPU usage par intervalle de temps)
- Calcul de statistiques sur des fenêtres glissantes

**Game Developers :**
- Systèmes de dégâts de zone (Area of Effect)
- Requêtes spatiales pour l'IA et le pathfinding

**Quantitative Analysts :**
- Calcul de moyennes mobiles sur des séries financières
- Détection d'anomalies sur des intervalles

**Competitive Programmers :**
- Structure omniprésente dans les contests ICPC, Codeforces
- Variant avec lazy propagation pour des problèmes avancés

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
wan_shi_tong.rs  main.rs  Cargo.toml

$ cargo build --release

$ cargo run
Building the Library of Wan Shi Tong...
Scrolls: [1, 3, 5, 7, 9, 11]
Query [0, 5]: 36 (All sections)
Query [1, 3]: 15 (Middle sections)
Get index 2: 5
Updating index 2 to 10...
Query [0, 5]: 41 (After update)
All tests passed!
```

---

### 3.1 ⚡ BONUS STANDARD : Lazy Propagation (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★☆☆☆ (7/10)

**Récompense :**
XP ×2

**Time Complexity attendue :**
O(log n) pour range updates

**Space Complexity attendue :**
O(n) additionnel pour lazy array

**Domaines Bonus :**
`Algo`

#### 3.1.1 Consigne Bonus

**🦉 Le Grand Catalogage de Wan Shi Tong**

*"Knowledge is the most precious thing in the world."*

Wan Shi Tong a décidé de réorganiser des sections entières de sa bibliothèque. Il veut pouvoir :
- **Ajouter** une quantité de parchemins à toute une plage de sections
- **Remplacer** la valeur de toute une plage par une nouvelle valeur
- Faire tout cela en O(log n), pas en O(n) !

Le secret ? La **propagation paresseuse** (Lazy Propagation). Au lieu de propager immédiatement les modifications, on les stocke et on ne les applique que quand c'est nécessaire.

**Ta mission :**

Étendre `WanShiTongLibrary` avec :
- `range_add(left, right, delta)` : Ajoute delta à tous les éléments de [left, right]
- `range_set(left, right, value)` : Met tous les éléments de [left, right] à value
- `query_min(left, right)` : Minimum sur la plage
- `query_max(left, right)` : Maximum sur la plage

**Contraintes :**
```
┌─────────────────────────────────────────┐
│  0 ≤ left ≤ right < n                   │
│  Toutes opérations en O(log n)          │
│  Pas de reconstruction d'arbre          │
└─────────────────────────────────────────┘
```

**Exemples :**

| Opération | Résultat | Explication |
|-----------|----------|-------------|
| `new([1, 2, 3, 4, 5])` | Arbre | Initial |
| `range_add(1, 3, 10)` | — | +10 aux indices 1-3 |
| `query(0, 4)` | `45` | 1+12+13+14+5 |
| `range_set(2, 4, 0)` | — | Indices 2-4 → 0 |
| `query(0, 4)` | `13` | 1+12+0+0+0 |

#### 3.1.2 Prototype Bonus

```rust
pub struct LazyWanShiTong {
    tree: Vec<i64>,
    lazy_add: Vec<i64>,
    lazy_set: Vec<Option<i64>>,
    n: usize,
}

impl LazyWanShiTong {
    pub fn new(scrolls: &[i64]) -> Self;
    pub fn range_add(&mut self, left: usize, right: usize, delta: i64);
    pub fn range_set(&mut self, left: usize, right: usize, value: i64);
    pub fn query(&mut self, left: usize, right: usize) -> i64;
    pub fn query_min(&mut self, left: usize, right: usize) -> i64;
    pub fn query_max(&mut self, left: usize, right: usize) -> i64;
}
```

#### 3.1.3 Ce qui change par rapport à l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Update | Point O(log n) | Range O(log n) |
| Lazy array | Non | Oui |
| push_down | Non | Obligatoire |
| Query types | Sum | Sum, Min, Max |

---

### 3.2 🔥 BONUS EXPERT : Segment Tree 2D (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★★☆☆ (8/10)

**Récompense :**
XP ×3

**Time Complexity attendue :**
O(log n × log m) pour requêtes

**Domaines Bonus :**
`AL`

#### 3.2.1 Consigne Bonus Expert

**🦉 Les Étages de la Bibliothèque Infinie**

La bibliothèque de Wan Shi Tong ne s'étend pas que horizontalement — elle a aussi plusieurs **étages**. Tu dois pouvoir interroger des rectangles de sections sur plusieurs étages simultanément.

**Ta mission :**

Implémenter un Segment Tree 2D :
- `new(matrix)` : Construction à partir d'une matrice
- `update(row, col, value)` : Mise à jour ponctuelle
- `query(r1, c1, r2, c2)` : Somme du rectangle [r1,c1] à [r2,c2]

#### 3.2.2 Prototype Bonus Expert

```rust
pub struct WanShiTong2D {
    tree: Vec<Vec<i64>>,
    n: usize,
    m: usize,
}

impl WanShiTong2D {
    pub fn new(matrix: &[Vec<i64>]) -> Self;
    pub fn update(&mut self, row: usize, col: usize, value: i64);
    pub fn query(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64;
}
```

---

### 3.3 🧠 BONUS GÉNIE : Persistent Segment Tree (OPTIONNEL)

**Difficulté Bonus :**
🧠 (11/10)

**Récompense :**
XP ×6

**Time Complexity attendue :**
O(log n) par version

**Space Complexity attendue :**
O(log n) par mise à jour (nouveaux nœuds seulement)

**Domaines Bonus :**
`Struct`, `DP`

#### 3.3.1 Consigne Bonus Génie

**🦉 Les Archives Temporelles de Wan Shi Tong**

*"You think knowledge changes? Knowledge is eternal. But the world... the world changes."*

Wan Shi Tong veut pouvoir consulter l'état de sa bibliothèque à **n'importe quel moment du passé**. Chaque modification crée une nouvelle **version** de l'arbre, mais sans dupliquer les parties inchangées.

C'est le concept de **persistance fonctionnelle** : chaque version partage les nœuds inchangés avec les versions précédentes.

**Ta mission :**

Implémenter un Segment Tree Persistant :
- `new(arr)` : Crée la version 0
- `update(version, index, value) -> new_version` : Crée une nouvelle version
- `query(version, left, right)` : Requête sur une version spécifique
- `version_count()` : Nombre total de versions

#### 3.3.2 Prototype Bonus Génie

```rust
#[derive(Clone)]
struct PersistentNode {
    sum: i64,
    left: Option<usize>,
    right: Option<usize>,
}

pub struct PersistentWanShiTong {
    nodes: Vec<PersistentNode>,
    roots: Vec<usize>,
    n: usize,
}

impl PersistentWanShiTong {
    pub fn new(scrolls: &[i64]) -> Self;
    pub fn update(&mut self, version: usize, index: usize, value: i64) -> usize;
    pub fn query(&self, version: usize, left: usize, right: usize) -> i64;
    pub fn version_count(&self) -> usize;
}
```

**Exemples :**

| Opération | Résultat | Explication |
|-----------|----------|-------------|
| `new([1, 2, 3, 4, 5])` | Version 0 | Somme = 15 |
| `update(0, 2, 10)` | Version 1 | 3 → 10, Somme = 22 |
| `query(0, 0, 4)` | `15` | Version 0 inchangée ! |
| `query(1, 0, 4)` | `22` | Version 1 |
| `update(1, 0, 100)` | Version 2 | 1 → 100, Somme = 121 |

---

## ✅❌ SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test | Input | Expected | Points | Trap |
|------|-------|----------|--------|------|
| `empty_library` | `[]` | Bibliothèque valide vide | 5 | Edge |
| `single_element` | `[42]` | `query(0,0)=42` | 5 | Edge |
| `build_basic` | `[1,3,5,7,9,11]` | Arbre valide | 10 | — |
| `query_full` | `query(0,5)` | `36` | 10 | — |
| `query_partial` | `query(1,3)` | `15` | 10 | — |
| `query_single` | `query(2,2)` | `5` | 5 | — |
| `get_index` | `get(2)` | `5` | 5 | — |
| `update_point` | `update(2,10); query(0,5)` | `41` | 10 | — |
| `query_after_multiple_updates` | Multiple updates | Correct | 10 | — |
| `boundary_left` | `query(0,0)` | Premier élément | 5 | Boundary |
| `boundary_right` | `query(n-1,n-1)` | Dernier élément | 5 | Boundary |
| `large_values` | `[i64::MAX/2, ...]` | Sans overflow | 10 | Overflow |
| `stress_test` | 10⁵ elements, 10⁵ ops | < 2s | 10 | Perf |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "wan_shi_tong.h"

void test_basic_operations(void) {
    int64_t scrolls[] = {1, 3, 5, 7, 9, 11};
    WanShiTongLibrary *lib = wst_library_new(scrolls, 6);

    // Test query full range
    assert(wst_query(lib, 0, 5) == 36);

    // Test query partial range
    assert(wst_query(lib, 1, 3) == 15);

    // Test get
    assert(wst_get(lib, 2) == 5);

    // Test update
    wst_update(lib, 2, 10);
    assert(wst_query(lib, 0, 5) == 41);
    assert(wst_get(lib, 2) == 10);

    wst_library_free(lib);
    printf("Basic operations: OK\n");
}

void test_edge_cases(void) {
    // Empty library
    WanShiTongLibrary *empty = wst_library_new(NULL, 0);
    assert(wst_is_empty(empty));
    assert(wst_len(empty) == 0);
    wst_library_free(empty);

    // Single element
    int64_t single[] = {42};
    WanShiTongLibrary *lib = wst_library_new(single, 1);
    assert(wst_query(lib, 0, 0) == 42);
    assert(wst_get(lib, 0) == 42);
    wst_library_free(lib);

    printf("Edge cases: OK\n");
}

void test_boundary_queries(void) {
    int64_t scrolls[] = {1, 2, 3, 4, 5};
    WanShiTongLibrary *lib = wst_library_new(scrolls, 5);

    // Left boundary
    assert(wst_query(lib, 0, 0) == 1);

    // Right boundary
    assert(wst_query(lib, 4, 4) == 5);

    // Full range
    assert(wst_query(lib, 0, 4) == 15);

    wst_library_free(lib);
    printf("Boundary queries: OK\n");
}

int main(void) {
    test_basic_operations();
    test_edge_cases();
    test_boundary_queries();

    printf("\nAll tests passed! Wan Shi Tong approves.\n");
    return 0;
}
```

### 4.3 Solution de référence

**Rust :**
```rust
pub struct WanShiTongLibrary {
    tree: Vec<i64>,
    n: usize,
}

impl WanShiTongLibrary {
    pub fn new(scrolls: &[i64]) -> Self {
        let n = scrolls.len();
        if n == 0 {
            return Self { tree: vec![], n: 0 };
        }

        let mut tree = vec![0i64; 4 * n];
        Self::build(scrolls, &mut tree, 1, 0, n - 1);

        Self { tree, n }
    }

    fn build(arr: &[i64], tree: &mut Vec<i64>, node: usize, start: usize, end: usize) {
        if start == end {
            tree[node] = arr[start];
            return;
        }
        let mid = start + (end - start) / 2;
        Self::build(arr, tree, 2 * node, start, mid);
        Self::build(arr, tree, 2 * node + 1, mid + 1, end);
        tree[node] = tree[2 * node] + tree[2 * node + 1];
    }

    pub fn query(&self, left: usize, right: usize) -> i64 {
        if self.n == 0 || left > right || right >= self.n {
            return 0;
        }
        self.query_impl(1, 0, self.n - 1, left, right)
    }

    fn query_impl(&self, node: usize, start: usize, end: usize, left: usize, right: usize) -> i64 {
        if right < start || left > end {
            return 0;
        }
        if left <= start && end <= right {
            return self.tree[node];
        }
        let mid = start + (end - start) / 2;
        let left_sum = self.query_impl(2 * node, start, mid, left, right);
        let right_sum = self.query_impl(2 * node + 1, mid + 1, end, left, right);
        left_sum + right_sum
    }

    pub fn update(&mut self, index: usize, value: i64) {
        if index >= self.n {
            return;
        }
        self.update_impl(1, 0, self.n - 1, index, value);
    }

    fn update_impl(&mut self, node: usize, start: usize, end: usize, index: usize, value: i64) {
        if start == end {
            self.tree[node] = value;
            return;
        }
        let mid = start + (end - start) / 2;
        if index <= mid {
            self.update_impl(2 * node, start, mid, index, value);
        } else {
            self.update_impl(2 * node + 1, mid + 1, end, index, value);
        }
        self.tree[node] = self.tree[2 * node] + self.tree[2 * node + 1];
    }

    pub fn get(&self, index: usize) -> i64 {
        self.query(index, index)
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
#include "wan_shi_tong.h"

static void build(const int64_t *arr, int64_t *tree, size_t node,
                  size_t start, size_t end) {
    if (start == end) {
        tree[node] = arr[start];
        return;
    }
    size_t mid = start + (end - start) / 2;
    build(arr, tree, 2 * node, start, mid);
    build(arr, tree, 2 * node + 1, mid + 1, end);
    tree[node] = tree[2 * node] + tree[2 * node + 1];
}

WanShiTongLibrary *wst_library_new(const int64_t *scrolls, size_t n) {
    WanShiTongLibrary *lib = malloc(sizeof(WanShiTongLibrary));
    if (!lib) return NULL;

    lib->n = n;
    if (n == 0) {
        lib->tree = NULL;
        lib->tree_size = 0;
        return lib;
    }

    lib->tree_size = 4 * n;
    lib->tree = calloc(lib->tree_size, sizeof(int64_t));
    if (!lib->tree) {
        free(lib);
        return NULL;
    }

    build(scrolls, lib->tree, 1, 0, n - 1);
    return lib;
}

void wst_library_free(WanShiTongLibrary *lib) {
    if (lib) {
        free(lib->tree);
        free(lib);
    }
}

static int64_t query_impl(const int64_t *tree, size_t node,
                          size_t start, size_t end,
                          size_t left, size_t right) {
    if (right < start || left > end) {
        return 0;
    }
    if (left <= start && end <= right) {
        return tree[node];
    }
    size_t mid = start + (end - start) / 2;
    int64_t left_sum = query_impl(tree, 2 * node, start, mid, left, right);
    int64_t right_sum = query_impl(tree, 2 * node + 1, mid + 1, end, left, right);
    return left_sum + right_sum;
}

int64_t wst_query(const WanShiTongLibrary *lib, size_t left, size_t right) {
    if (!lib || lib->n == 0 || left > right || right >= lib->n) {
        return 0;
    }
    return query_impl(lib->tree, 1, 0, lib->n - 1, left, right);
}

int64_t wst_get(const WanShiTongLibrary *lib, size_t index) {
    return wst_query(lib, index, index);
}

static void update_impl(int64_t *tree, size_t node, size_t start, size_t end,
                        size_t index, int64_t value) {
    if (start == end) {
        tree[node] = value;
        return;
    }
    size_t mid = start + (end - start) / 2;
    if (index <= mid) {
        update_impl(tree, 2 * node, start, mid, index, value);
    } else {
        update_impl(tree, 2 * node + 1, mid + 1, end, index, value);
    }
    tree[node] = tree[2 * node] + tree[2 * node + 1];
}

void wst_update(WanShiTongLibrary *lib, size_t index, int64_t value) {
    if (!lib || index >= lib->n) {
        return;
    }
    update_impl(lib->tree, 1, 0, lib->n - 1, index, value);
}

size_t wst_len(const WanShiTongLibrary *lib) {
    return lib ? lib->n : 0;
}

int wst_is_empty(const WanShiTongLibrary *lib) {
    return !lib || lib->n == 0;
}
```

### 4.4 Solutions alternatives acceptées

**Alternative 1 : Segment Tree itératif (bottom-up)**
```rust
pub struct WanShiTongIterative {
    tree: Vec<i64>,
    n: usize,
}

impl WanShiTongIterative {
    pub fn new(scrolls: &[i64]) -> Self {
        let n = scrolls.len();
        if n == 0 {
            return Self { tree: vec![], n: 0 };
        }

        let mut tree = vec![0i64; 2 * n];
        // Copy leaves
        for i in 0..n {
            tree[n + i] = scrolls[i];
        }
        // Build internal nodes
        for i in (1..n).rev() {
            tree[i] = tree[2 * i] + tree[2 * i + 1];
        }

        Self { tree, n }
    }

    pub fn update(&mut self, mut index: usize, value: i64) {
        index += self.n;
        self.tree[index] = value;
        while index > 1 {
            index /= 2;
            self.tree[index] = self.tree[2 * index] + self.tree[2 * index + 1];
        }
    }

    pub fn query(&self, mut left: usize, mut right: usize) -> i64 {
        let mut sum = 0;
        left += self.n;
        right += self.n + 1;

        while left < right {
            if left % 2 == 1 {
                sum += self.tree[left];
                left += 1;
            }
            if right % 2 == 1 {
                right -= 1;
                sum += self.tree[right];
            }
            left /= 2;
            right /= 2;
        }
        sum
    }
}
```

### 4.5 Solutions refusées (avec explications)

**Refusée 1 : Prefix Sum (pas de update efficient)**
```rust
// ❌ Update en O(n) - inacceptable
pub struct PrefixSum {
    prefix: Vec<i64>,
}

impl PrefixSum {
    pub fn query(&self, left: usize, right: usize) -> i64 {
        self.prefix[right + 1] - self.prefix[left]  // O(1) mais...
    }

    pub fn update(&mut self, index: usize, value: i64) {
        // ❌ Doit recalculer tous les préfixes - O(n)
        let diff = value - (self.prefix[index + 1] - self.prefix[index]);
        for i in (index + 1)..self.prefix.len() {
            self.prefix[i] += diff;
        }
    }
}
// Pourquoi refusé : update en O(n) viole la complexité demandée
```

**Refusée 2 : Taille d'arbre incorrecte**
```rust
// ❌ Arbre trop petit - buffer overflow
pub fn new_wrong(scrolls: &[i64]) -> Self {
    let n = scrolls.len();
    let mut tree = vec![0i64; 2 * n];  // ❌ Devrait être 4 * n
    // ...
}
// Pourquoi refusé : Pour un arbre non-parfait, 2*n ne suffit pas
// Exemple : n=5, l'arbre récursif peut avoir besoin d'index jusqu'à ~16
```

**Refusée 3 : Division non safe**
```rust
// ❌ Overflow sur grands indices
fn query_impl(&self, node: usize, start: usize, end: usize, left: usize, right: usize) -> i64 {
    let mid = (start + end) / 2;  // ❌ Overflow si start + end > usize::MAX
    // ...
}
// Correct : mid = start + (end - start) / 2
```

### 4.6 Solution bonus de référence (Lazy Propagation)

```rust
pub struct LazyWanShiTong {
    tree: Vec<i64>,
    lazy_add: Vec<i64>,
    n: usize,
}

impl LazyWanShiTong {
    pub fn new(scrolls: &[i64]) -> Self {
        let n = scrolls.len();
        if n == 0 {
            return Self { tree: vec![], lazy_add: vec![], n: 0 };
        }

        let size = 4 * n;
        let mut tree = vec![0i64; size];
        let lazy_add = vec![0i64; size];

        Self::build(scrolls, &mut tree, 1, 0, n - 1);
        Self { tree, lazy_add, n }
    }

    fn build(arr: &[i64], tree: &mut Vec<i64>, node: usize, start: usize, end: usize) {
        if start == end {
            tree[node] = arr[start];
            return;
        }
        let mid = start + (end - start) / 2;
        Self::build(arr, tree, 2 * node, start, mid);
        Self::build(arr, tree, 2 * node + 1, mid + 1, end);
        tree[node] = tree[2 * node] + tree[2 * node + 1];
    }

    fn push_down(&mut self, node: usize, start: usize, end: usize) {
        if self.lazy_add[node] != 0 {
            let mid = start + (end - start) / 2;
            let left_len = (mid - start + 1) as i64;
            let right_len = (end - mid) as i64;

            self.tree[2 * node] += self.lazy_add[node] * left_len;
            self.lazy_add[2 * node] += self.lazy_add[node];

            self.tree[2 * node + 1] += self.lazy_add[node] * right_len;
            self.lazy_add[2 * node + 1] += self.lazy_add[node];

            self.lazy_add[node] = 0;
        }
    }

    pub fn range_add(&mut self, left: usize, right: usize, delta: i64) {
        if self.n == 0 || left > right || right >= self.n {
            return;
        }
        self.range_add_impl(1, 0, self.n - 1, left, right, delta);
    }

    fn range_add_impl(&mut self, node: usize, start: usize, end: usize,
                      left: usize, right: usize, delta: i64) {
        if right < start || left > end {
            return;
        }
        if left <= start && end <= right {
            self.tree[node] += delta * (end - start + 1) as i64;
            self.lazy_add[node] += delta;
            return;
        }
        self.push_down(node, start, end);
        let mid = start + (end - start) / 2;
        self.range_add_impl(2 * node, start, mid, left, right, delta);
        self.range_add_impl(2 * node + 1, mid + 1, end, left, right, delta);
        self.tree[node] = self.tree[2 * node] + self.tree[2 * node + 1];
    }

    pub fn query(&mut self, left: usize, right: usize) -> i64 {
        if self.n == 0 || left > right || right >= self.n {
            return 0;
        }
        self.query_impl(1, 0, self.n - 1, left, right)
    }

    fn query_impl(&mut self, node: usize, start: usize, end: usize,
                  left: usize, right: usize) -> i64 {
        if right < start || left > end {
            return 0;
        }
        if left <= start && end <= right {
            return self.tree[node];
        }
        self.push_down(node, start, end);
        let mid = start + (end - start) / 2;
        let left_sum = self.query_impl(2 * node, start, mid, left, right);
        let right_sum = self.query_impl(2 * node + 1, mid + 1, end, left, right);
        left_sum + right_sum
    }
}
```

### 4.7 Solutions alternatives bonus (Lazy avec Set)

```rust
// Alternative : Lazy avec priorité Set > Add
pub struct LazyWanShiTongWithSet {
    tree: Vec<i64>,
    lazy_add: Vec<i64>,
    lazy_set: Vec<Option<i64>>,
    n: usize,
}

impl LazyWanShiTongWithSet {
    fn push_down(&mut self, node: usize, start: usize, end: usize) {
        let mid = start + (end - start) / 2;

        // Set a priorité sur Add
        if let Some(val) = self.lazy_set[node] {
            let left_len = (mid - start + 1) as i64;
            let right_len = (end - mid) as i64;

            self.tree[2 * node] = val * left_len;
            self.lazy_set[2 * node] = Some(val);
            self.lazy_add[2 * node] = 0;

            self.tree[2 * node + 1] = val * right_len;
            self.lazy_set[2 * node + 1] = Some(val);
            self.lazy_add[2 * node + 1] = 0;

            self.lazy_set[node] = None;
        }

        // Propager Add
        if self.lazy_add[node] != 0 {
            let left_len = (mid - start + 1) as i64;
            let right_len = (end - mid) as i64;

            self.tree[2 * node] += self.lazy_add[node] * left_len;
            self.lazy_add[2 * node] += self.lazy_add[node];

            self.tree[2 * node + 1] += self.lazy_add[node] * right_len;
            self.lazy_add[2 * node + 1] += self.lazy_add[node];

            self.lazy_add[node] = 0;
        }
    }
}
```

### 4.8 Solutions refusées bonus

**Refusée : Pas de push_down avant query**
```rust
// ❌ Oubli de propager le lazy avant de descendre
fn query_impl(&mut self, node: usize, start: usize, end: usize,
              left: usize, right: usize) -> i64 {
    if right < start || left > end {
        return 0;
    }
    if left <= start && end <= right {
        return self.tree[node];
    }
    // ❌ MANQUE : self.push_down(node, start, end);
    let mid = start + (end - start) / 2;
    // Les enfants n'ont pas reçu les lazy updates !
    // ...
}
```

### 4.9 spec.json

```json
{
  "name": "wan_shi_tong_library",
  "language": "rust",
  "type": "code",
  "tier": 3,
  "tier_info": "Synthèse (Segment Trees complets)",
  "tags": ["segment-tree", "range-query", "lazy-propagation", "phase1"],
  "passing_score": 70,

  "function": {
    "name": "WanShiTongLibrary",
    "prototype": "impl WanShiTongLibrary { pub fn new(scrolls: &[i64]) -> Self; pub fn query(&self, left: usize, right: usize) -> i64; pub fn update(&mut self, index: usize, value: i64); pub fn get(&self, index: usize) -> i64; }",
    "return_type": "struct",
    "parameters": [
      {"name": "scrolls", "type": "&[i64]"}
    ]
  },

  "driver": {
    "reference": "pub struct WanShiTongLibrary { tree: Vec<i64>, n: usize } impl WanShiTongLibrary { pub fn new(scrolls: &[i64]) -> Self { let n = scrolls.len(); if n == 0 { return Self { tree: vec![], n: 0 }; } let mut tree = vec![0i64; 4 * n]; Self::build(scrolls, &mut tree, 1, 0, n - 1); Self { tree, n } } fn build(arr: &[i64], tree: &mut Vec<i64>, node: usize, start: usize, end: usize) { if start == end { tree[node] = arr[start]; return; } let mid = start + (end - start) / 2; Self::build(arr, tree, 2 * node, start, mid); Self::build(arr, tree, 2 * node + 1, mid + 1, end); tree[node] = tree[2 * node] + tree[2 * node + 1]; } pub fn query(&self, left: usize, right: usize) -> i64 { if self.n == 0 || left > right || right >= self.n { return 0; } self.query_impl(1, 0, self.n - 1, left, right) } fn query_impl(&self, node: usize, start: usize, end: usize, left: usize, right: usize) -> i64 { if right < start || left > end { return 0; } if left <= start && end <= right { return self.tree[node]; } let mid = start + (end - start) / 2; self.query_impl(2 * node, start, mid, left, right) + self.query_impl(2 * node + 1, mid + 1, end, left, right) } pub fn update(&mut self, index: usize, value: i64) { if index >= self.n { return; } self.update_impl(1, 0, self.n - 1, index, value); } fn update_impl(&mut self, node: usize, start: usize, end: usize, index: usize, value: i64) { if start == end { self.tree[node] = value; return; } let mid = start + (end - start) / 2; if index <= mid { self.update_impl(2 * node, start, mid, index, value); } else { self.update_impl(2 * node + 1, mid + 1, end, index, value); } self.tree[node] = self.tree[2 * node] + self.tree[2 * node + 1]; } pub fn get(&self, index: usize) -> i64 { self.query(index, index) } pub fn len(&self) -> usize { self.n } pub fn is_empty(&self) -> bool { self.n == 0 } }",

    "edge_cases": [
      {
        "name": "empty_library",
        "args": {"scrolls": []},
        "test": "let lib = WanShiTongLibrary::new(&[]); assert!(lib.is_empty()); assert_eq!(lib.len(), 0);",
        "is_trap": true,
        "trap_explanation": "Bibliothèque vide - ne pas crasher"
      },
      {
        "name": "single_element",
        "args": {"scrolls": [42]},
        "test": "let lib = WanShiTongLibrary::new(&[42]); assert_eq!(lib.query(0, 0), 42); assert_eq!(lib.get(0), 42);",
        "is_trap": true,
        "trap_explanation": "Un seul élément - cas limite"
      },
      {
        "name": "full_range_query",
        "args": {"scrolls": [1, 3, 5, 7, 9, 11]},
        "test": "let lib = WanShiTongLibrary::new(&[1, 3, 5, 7, 9, 11]); assert_eq!(lib.query(0, 5), 36);",
        "expected": 36
      },
      {
        "name": "partial_range_query",
        "args": {"scrolls": [1, 3, 5, 7, 9, 11]},
        "test": "let lib = WanShiTongLibrary::new(&[1, 3, 5, 7, 9, 11]); assert_eq!(lib.query(1, 3), 15);",
        "expected": 15
      },
      {
        "name": "point_update",
        "args": {"scrolls": [1, 3, 5, 7, 9, 11], "index": 2, "value": 10},
        "test": "let mut lib = WanShiTongLibrary::new(&[1, 3, 5, 7, 9, 11]); lib.update(2, 10); assert_eq!(lib.query(0, 5), 41); assert_eq!(lib.get(2), 10);",
        "expected": 41
      },
      {
        "name": "out_of_bounds_query",
        "args": {"scrolls": [1, 2, 3]},
        "test": "let lib = WanShiTongLibrary::new(&[1, 2, 3]); assert_eq!(lib.query(0, 10), 0);",
        "is_trap": true,
        "trap_explanation": "Query hors limites - retourner 0 ou gérer proprement"
      },
      {
        "name": "large_values",
        "args": {"scrolls": [1000000000, 1000000000, 1000000000]},
        "test": "let lib = WanShiTongLibrary::new(&[1000000000, 1000000000, 1000000000]); assert_eq!(lib.query(0, 2), 3000000000);",
        "is_trap": true,
        "trap_explanation": "Grandes valeurs - attention overflow i32"
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
            "max_len": 1000,
            "min_val": -1000000,
            "max_val": 1000000
          }
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": [],
    "forbidden_functions": ["sort"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

**Mutant A (Boundary) : Overflow sur calcul du milieu**
```rust
// ❌ Overflow possible si start + end > usize::MAX
fn query_impl(&self, node: usize, start: usize, end: usize, left: usize, right: usize) -> i64 {
    // ...
    let mid = (start + end) / 2;  // ❌ BUG : overflow
    // Correct : mid = start + (end - start) / 2
    // ...
}
// Pourquoi c'est faux : Pour de très grands indices, start + end peut overflow
// Ce qui était pensé : "Division simple, pas de problème"
```

**Mutant B (Safety) : Oubli push_down dans Lazy Tree**
```rust
// ❌ Query sans propager le lazy
fn query_impl(&mut self, node: usize, start: usize, end: usize,
              left: usize, right: usize) -> i64 {
    if right < start || left > end {
        return 0;
    }
    if left <= start && end <= right {
        return self.tree[node];
    }
    // ❌ MANQUE : self.push_down(node, start, end);
    let mid = start + (end - start) / 2;
    self.query_impl(2 * node, start, mid, left, right) +
    self.query_impl(2 * node + 1, mid + 1, end, left, right)
}
// Pourquoi c'est faux : Les enfants n'ont pas les valeurs à jour
// Ce qui était pensé : "Le nœud courant a la bonne valeur, pas besoin de propager"
```

**Mutant C (Resource) : Taille d'arbre insuffisante**
```rust
// ❌ 2*n ne suffit pas pour un arbre récursif
pub fn new(scrolls: &[i64]) -> Self {
    let n = scrolls.len();
    let mut tree = vec![0i64; 2 * n];  // ❌ Devrait être 4 * n
    // ...
}
// Pourquoi c'est faux : Pour n non puissance de 2, l'arbre récursif
//                       peut nécessiter jusqu'à ~4n nœuds
// Ce qui était pensé : "Un arbre binaire a 2n-1 nœuds"
```

**Mutant D (Logic) : Condition de sortie inversée**
```rust
// ❌ Mauvaise condition "hors plage"
fn query_impl(&self, node: usize, start: usize, end: usize,
              left: usize, right: usize) -> i64 {
    if left < start || right > end {  // ❌ Logique inversée !
        return 0;                      // Correct : right < start || left > end
    }
    // ...
}
// Pourquoi c'est faux : Cette condition ne détecte pas correctement
//                       quand l'intervalle de recherche n'intersecte pas le nœud
// Ce qui était pensé : "Si left est avant start ou right après end, c'est hors plage"
```

**Mutant E (Return) : Retour 0 pour identity générique**
```rust
// ❌ 0 comme identity ne fonctionne pas pour min/max
impl<T> GenericSegmentTree<T> {
    fn query_impl(&self, node: usize, start: usize, end: usize,
                  left: usize, right: usize) -> T {
        if right < start || left > end {
            return T::default();  // ❌ Pour min, default 0 fausse le résultat !
        }
        // Correct : utiliser self.identity.clone()
    }
}
// Pourquoi c'est faux : Pour query_min, retourner 0 donne un faux minimum
// Ce qui était pensé : "Default fonctionne pour tous les types"
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Division & Conquer appliqué aux requêtes** : Diviser l'espace de recherche en O(log n) segments
2. **Représentation implicite d'arbre** : Stocker un arbre complet dans un tableau
3. **Trade-off temps/espace** : O(n) espace pour O(log n) requêtes
4. **Lazy Propagation** : Différer les calculs jusqu'à ce qu'ils soient nécessaires
5. **Persistance fonctionnelle** : Partager les structures pour historique efficace

### 5.2 LDA — Traduction littérale en français

```
FONCTION query_impl QUI RETOURNE UN ENTIER 64 BITS ET PREND EN PARAMÈTRES
    node QUI EST UN ENTIER NON SIGNÉ (index du nœud)
    start QUI EST UN ENTIER NON SIGNÉ (début de l'intervalle du nœud)
    end QUI EST UN ENTIER NON SIGNÉ (fin de l'intervalle du nœud)
    left QUI EST UN ENTIER NON SIGNÉ (début de la requête)
    right QUI EST UN ENTIER NON SIGNÉ (fin de la requête)
DÉBUT FONCTION
    SI right EST INFÉRIEUR À start OU left EST SUPÉRIEUR À end ALORS
        RETOURNER LA VALEUR 0 (intervalle disjoint)
    FIN SI

    SI left EST INFÉRIEUR OU ÉGAL À start ET end EST INFÉRIEUR OU ÉGAL À right ALORS
        RETOURNER tree[node] (intervalle complètement inclus)
    FIN SI

    AFFECTER start PLUS (end MOINS start) DIVISÉ PAR 2 À mid

    DÉCLARER left_sum COMME ENTIER 64 BITS
    AFFECTER query_impl(2 × node, start, mid, left, right) À left_sum

    DÉCLARER right_sum COMME ENTIER 64 BITS
    AFFECTER query_impl(2 × node PLUS 1, mid PLUS 1, end, left, right) À right_sum

    RETOURNER left_sum PLUS right_sum
FIN FONCTION
```

### 5.2.2 Logic Flow (Structured English)

```
ALGORITHME : Segment Tree Query
---
1. VÉRIFIER si l'intervalle de requête est disjoint du nœud actuel
   - SI oui : RETOURNER l'élément neutre (0 pour somme)

2. VÉRIFIER si le nœud est complètement inclus dans la requête
   - SI oui : RETOURNER la valeur pré-calculée du nœud

3. DIVISER la requête en deux sous-requêtes :
   a. Calculer le milieu : mid = start + (end - start) / 2
   b. Requête récursive sur fils gauche [start, mid]
   c. Requête récursive sur fils droit [mid+1, end]

4. COMBINER les résultats des sous-requêtes
   - RETOURNER somme(résultat_gauche, résultat_droit)
```

### 5.2.3 Représentation Algorithmique (Logique de Garde)

```
FONCTION : Query(node, start, end, left, right)
---
INIT sum = 0

1. VÉRIFIER intervalle disjoint :
   |
   |-- SI right < start OU left > end :
   |     RETOURNER 0 (élément neutre)

2. VÉRIFIER couverture complète :
   |
   |-- SI left <= start ET end <= right :
   |     RETOURNER tree[node]

3. DIVISER et conquérir :
   |
   |-- CALCULER mid = start + (end - start) / 2
   |-- sum_left = Query(2*node, start, mid, left, right)
   |-- sum_right = Query(2*node+1, mid+1, end, left, right)
   |-- RETOURNER sum_left + sum_right
```

### 5.2.3.1 Diagramme Mermaid

```mermaid
graph TD
    A[Query: left=1, right=4] --> B{Nœud 1: [0,5]}
    B --> C{Disjoint?}
    C -- Non --> D{Couvert?}
    D -- Non --> E[Diviser]

    E --> F[Query gauche: Nœud 2, [0,2]]
    E --> G[Query droite: Nœud 3, [3,5]]

    F --> H{[0,2] ∩ [1,4]}
    H --> I[Récursion...]

    G --> J{[3,5] ∩ [1,4]}
    J --> K[Retourne tree[3] pour [3,4]]

    I --> L[Combine: gauche + droite]
    K --> L
    L --> M[Résultat final]
```

### 5.3 Visualisation ASCII

**Structure du Segment Tree pour `[1, 3, 5, 7, 9, 11]` :**

```
                        [36]                    ← Nœud 1 : somme [0,5]
                       /    \
                   [9]        [27]              ← Nœuds 2,3 : sommes [0,2] et [3,5]
                  /   \       /   \
                [4]   [5]   [16]  [11]          ← Nœuds 4-7
               /  \          /  \
             [1]  [3]      [7]  [9]             ← Feuilles (données originales)

Index arbre:   1     ← racine
             2   3
           4  5  6  7
          8 9   12 13

Tableau sous-jacent :
Position:  0   1   2   3   4   5
Valeur:   [1] [3] [5] [7] [9] [11]
```

**Query(1, 3) = 3 + 5 + 7 = 15 :**

```
                        [36]
                       /    \
                   [9]        [27]
                  /   \       /   \
                [4]  ►[5]◄ ►[16]◄ [11]    ← Nœuds visités
               /  \          /  \
             [1] ►[3]◄    ►[7]◄ [9]       ← Valeurs récupérées

Décomposition :
- Query(1,3) sur [0,5] → divise
- Query(1,3) sur [0,2] → visite [3] (index 1) et [5] (nœud 5)
- Query(1,3) sur [3,5] → visite [7] (index 3), [9] hors range
- Total : 3 + 5 + 7 = 15
```

**Représentation mémoire du tableau `tree[]` :**

```
Index:    0    1    2    3    4    5    6    7    8    9   10   11   12   13
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
tree:   | -- | 36 |  9 | 27 |  4 |  5 | 16 | 11 |  1 |  3 | -- | -- |  7 |  9 |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
                ↑
           Racine (index 1)

Relations :
- parent(i) = i / 2
- left_child(i) = 2 * i
- right_child(i) = 2 * i + 1
```

### 5.4 Les pièges en détail

#### Piège 1 : Overflow sur le calcul du milieu

```rust
// ❌ DANGER
let mid = (start + end) / 2;  // Overflow si start + end > usize::MAX

// ✅ SAFE
let mid = start + (end - start) / 2;  // Pas d'overflow possible
```

#### Piège 2 : Confusion indices 0-based vs 1-based

```
// L'arbre commence à l'index 1 pour simplifier parent/enfant
// tree[0] est inutilisé !

parent(i) = i / 2      // Ne fonctionne pas si racine à 0
left(i) = 2 * i        // Fonctionne avec racine à 1
right(i) = 2 * i + 1   // Fonctionne avec racine à 1
```

#### Piège 3 : Bornes inclusives vs exclusives

```rust
// La convention standard : [left, right] INCLUSIF aux deux bornes
query(1, 3)  // Inclut indices 1, 2, ET 3

// Attention à ne pas faire :
if left <= start && end < right  // ❌ exclut end
```

#### Piège 4 : Taille du tableau

```
n = 6 éléments
Arbre récursif peut avoir besoin de jusqu'à 2^(⌈log2(n)⌉+1) nœuds
Pour n=6 : 2^(3+1) = 16 nœuds

Solution simple : allouer 4 * n (toujours suffisant)
```

### 5.5 Cours Complet

#### 5.5.1 Qu'est-ce qu'un Segment Tree ?

Un **Segment Tree** (arbre de segments) est une structure de données qui permet :
- De répondre à des **requêtes de plage** (range queries) en O(log n)
- De faire des **mises à jour** en O(log n)
- Tout cela avec O(n) espace et O(n) temps de construction

C'est un **arbre binaire complet** où :
- Chaque **feuille** correspond à un élément du tableau original
- Chaque **nœud interne** contient le résultat agrégé de ses enfants

#### 5.5.2 Pourquoi utiliser un Segment Tree ?

| Problème | Solution naïve | Segment Tree |
|----------|----------------|--------------|
| Somme de arr[l..r] | O(n) parcours | O(log n) |
| Minimum de arr[l..r] | O(n) parcours | O(log n) |
| Mise à jour arr[i] = x | O(1) | O(log n) |
| Mise à jour arr[l..r] += x | O(n) | O(log n) avec lazy |

Le Segment Tree est optimal quand on a **beaucoup de requêtes** sur un tableau qui **change peu**.

#### 5.5.3 Construction de l'arbre

L'arbre est construit **bottom-up** de manière récursive :

```rust
fn build(arr: &[i64], tree: &mut Vec<i64>, node: usize, start: usize, end: usize) {
    // Cas de base : feuille
    if start == end {
        tree[node] = arr[start];
        return;
    }

    // Cas récursif : construire les enfants puis combiner
    let mid = start + (end - start) / 2;
    build(arr, tree, 2 * node, start, mid);      // Fils gauche
    build(arr, tree, 2 * node + 1, mid + 1, end); // Fils droit
    tree[node] = tree[2 * node] + tree[2 * node + 1]; // Combiner
}
```

**Complexité :** O(n) car chaque élément est visité une fois.

#### 5.5.4 Requête de plage

La clé est de **décomposer** l'intervalle [l, r] en O(log n) nœuds de l'arbre :

```rust
fn query(tree: &[i64], node: usize, start: usize, end: usize,
         left: usize, right: usize) -> i64 {
    // Cas 1 : Intervalles disjoints
    if right < start || left > end {
        return 0;  // Élément neutre pour l'addition
    }

    // Cas 2 : Nœud complètement inclus
    if left <= start && end <= right {
        return tree[node];
    }

    // Cas 3 : Intersection partielle - diviser
    let mid = start + (end - start) / 2;
    let left_result = query(tree, 2 * node, start, mid, left, right);
    let right_result = query(tree, 2 * node + 1, mid + 1, end, left, right);
    left_result + right_result
}
```

**Pourquoi O(log n) ?** À chaque niveau, au plus 2 nœuds sont partiellement intersectés. Profondeur = O(log n).

#### 5.5.5 Mise à jour ponctuelle

```rust
fn update(tree: &mut [i64], node: usize, start: usize, end: usize,
          index: usize, value: i64) {
    // Cas de base : arrivé à la feuille
    if start == end {
        tree[node] = value;
        return;
    }

    // Descendre dans le bon sous-arbre
    let mid = start + (end - start) / 2;
    if index <= mid {
        update(tree, 2 * node, start, mid, index, value);
    } else {
        update(tree, 2 * node + 1, mid + 1, end, index, value);
    }

    // Remonter : recalculer le nœud courant
    tree[node] = tree[2 * node] + tree[2 * node + 1];
}
```

**Complexité :** O(log n) - un seul chemin de la racine à une feuille.

#### 5.5.6 Lazy Propagation (Bonus)

Pour des **mises à jour de plage**, propager immédiatement coûte O(n). L'idée de la **propagation paresseuse** :

1. Stocker les mises à jour pendantes dans un tableau `lazy[]`
2. Ne propager aux enfants que quand c'est nécessaire (lors d'une query ou update qui descend)

```rust
fn push_down(tree: &mut [i64], lazy: &mut [i64], node: usize, start: usize, end: usize) {
    if lazy[node] != 0 {
        let mid = start + (end - start) / 2;

        // Propager au fils gauche
        tree[2 * node] += lazy[node] * (mid - start + 1) as i64;
        lazy[2 * node] += lazy[node];

        // Propager au fils droit
        tree[2 * node + 1] += lazy[node] * (end - mid) as i64;
        lazy[2 * node + 1] += lazy[node];

        // Effacer le lazy du nœud courant
        lazy[node] = 0;
    }
}
```

#### 5.5.7 Segment Tree 2D (Bonus Expert)

Pour des requêtes sur des **matrices**, on utilise un "arbre d'arbres" :
- L'arbre externe segmente les lignes
- Chaque nœud de l'arbre externe contient un arbre interne qui segmente les colonnes

**Complexité :** O(log n × log m) pour query/update.

#### 5.5.8 Persistent Segment Tree (Bonus Génie)

Permet de garder **toutes les versions** de l'arbre après chaque modification :
- Chaque update crée seulement O(log n) nouveaux nœuds
- Les parties inchangées sont partagées entre versions

**Application :** K-ième plus petit élément dans un intervalle.

### 5.6 Normes avec explications pédagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (compile, mais dangereux)                         │
├─────────────────────────────────────────────────────────────────┤
│ let mid = (start + end) / 2;                                    │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ let mid = start + (end - start) / 2;                            │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Overflow : start + end peut dépasser usize::MAX               │
│ • Bug subtil : ne se manifeste qu'avec de grands indices        │
│ • Historique : Bug célèbre dans la binary search de Java        │
└─────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                   │
├─────────────────────────────────────────────────────────────────┤
│ fn query(&self, l: usize, r: usize) -> i64                      │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ fn query(&self, left: usize, right: usize) -> i64               │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Clarté : l/r sont ambigus (left/right? low/range?)            │
│ • Maintenabilité : Noms explicites = code auto-documenté        │
│ • Convention : Les algorithmes utilisent souvent left/right     │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

**Exemple : Query(1, 3) sur `[1, 3, 5, 7, 9, 11]`**

```
┌───────┬────────────────────────────────────┬──────────┬─────────────────────┐
│ Étape │ Appel récursif                     │ Résultat │ Explication         │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   1   │ query(1, [0,5], [1,3])             │    —     │ Intersection part.  │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   2   │ query(2, [0,2], [1,3])             │    —     │ Intersection part.  │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   3   │ query(4, [0,1], [1,3])             │    —     │ Intersection part.  │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   4   │ query(8, [0,0], [1,3])             │    0     │ [0,0] ∩ [1,3] = ∅   │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   5   │ query(9, [1,1], [1,3])             │    3     │ [1,1] ⊆ [1,3]       │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   6   │ query(5, [2,2], [1,3])             │    5     │ [2,2] ⊆ [1,3]       │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   7   │ query(3, [3,5], [1,3])             │    —     │ Intersection part.  │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   8   │ query(6, [3,4], [1,3])             │    —     │ Intersection part.  │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│   9   │ query(12, [3,3], [1,3])            │    7     │ [3,3] ⊆ [1,3]       │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│  10   │ query(13, [4,4], [1,3])            │    0     │ [4,4] ∩ [1,3] = ∅   │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│  11   │ query(7, [5,5], [1,3])             │    0     │ [5,5] ∩ [1,3] = ∅   │
├───────┼────────────────────────────────────┼──────────┼─────────────────────┤
│  12   │ Remontée : 0+3=3, 3+5=8, 7+0=7... │   15     │ Total = 3+5+7 = 15  │
└───────┴────────────────────────────────────┴──────────┴─────────────────────┘
```

### 5.8 Mnémotechniques

#### 🦉 MEME : "He Who Knows Ten Thousand Things"

![Wan Shi Tong](wan_shi_tong_meme.jpg)

Wan Shi Tong sait tout parce qu'il a **organisé** sa bibliothèque.
Comme le Segment Tree, il peut répondre à n'importe quelle question de plage instantanément.

```rust
impl WanShiTong {
    fn answer_any_question(&self, topic_range: Range) -> Knowledge {
        // "You think you're the first person to believe their war was justified?"
        // Je connais TOUTE l'histoire de topic_range en O(log n)
        self.query(topic_range.start, topic_range.end)
    }
}
```

---

#### 📺 MEME : "Divide and Conquer" — Thanos

*"I am inevitable."* — Thanos

Comme Thanos divise l'univers en deux, le Segment Tree divise chaque intervalle en deux jusqu'à atteindre les feuilles.

```
Universe [0, 5]
    ↙         ↘
 [0, 2]     [3, 5]     ← Snap!
  ↙ ↘       ↙ ↘
[0,1] [2] [3,4] [5]    ← Snap!
 ↙↘      ↙↘
[0][1]  [3][4]         ← Éléments individuels
```

---

#### 🎮 MEME : "Fog of War" — RTS Games

Dans un RTS (StarCraft, AoE), le "fog of war" cache ce que tu n'as pas exploré.
Un Segment Tree, c'est comme avoir des **scouts** à différents niveaux de zoom :

- Zoom max : tu vois chaque unité (feuilles)
- Zoom intermédiaire : tu vois des régions (nœuds internes)
- Zoom min : tu vois le continent entier (racine)

Une query = "Combien d'unités dans cette région ?" → O(log n) scouts suffisent !

### 5.9 Applications pratiques

1. **Calcul de statistiques en temps réel**
   - Moyenne, min, max sur fenêtre glissante
   - Monitoring de serveurs

2. **Jeux vidéo**
   - Calcul de dégâts de zone
   - Collision detection

3. **Finance quantitative**
   - Range queries sur séries temporelles
   - Calcul de VaR (Value at Risk)

4. **Bases de données**
   - Index pour requêtes de plage
   - Optimisation de GROUP BY

5. **Programmation compétitive**
   - Structure omniprésente
   - Variations : min/max, GCD, merge sort tree

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Conséquence | Solution |
|---|-------|-------------|----------|
| 1 | Overflow calcul milieu | Crash ou résultat faux | `start + (end - start) / 2` |
| 2 | Taille arbre 2*n | Buffer overflow | Utiliser 4*n |
| 3 | Oubli push_down (lazy) | Résultats incorrects | Toujours push avant descendre |
| 4 | Confusion 0/1-indexed | Off-by-one errors | Choisir une convention et s'y tenir |
| 5 | Bornes exclusives vs inclusives | Éléments manquants | Documenter clairement [l, r] |
| 6 | Identity incorrecte | Faux résultat pour min/max | 0 pour sum, MAX pour min, MIN pour max |

---

## 📝 SECTION 7 : QCM

### Question 1
**Quelle est la complexité temporelle d'une requête de somme sur un Segment Tree ?**

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n log n)
- E) O(log² n)
- F) O(√n)
- G) O(n²)
- H) Dépend de la taille de l'intervalle
- I) O(2^n)
- J) Amortie O(1)

**Réponse : B**

---

### Question 2
**Pourquoi utilise-t-on 4*n pour la taille du tableau au lieu de 2*n ?**

- A) Pour avoir de la marge
- B) Parce que l'arbre récursif peut avoir besoin de plus de 2n nœuds pour n non puissance de 2
- C) Pour stocker le lazy array
- D) C'est une convention arbitraire
- E) Pour les nœuds sentinelles
- F) Pour le garbage collector
- G) Pour le cache alignment
- H) 2n suffit toujours
- I) Pour les métadonnées
- J) Pour la persistance

**Réponse : B**

---

### Question 3
**Dans lazy propagation, quand faut-il appeler push_down ?**

- A) Uniquement lors des mises à jour
- B) Uniquement lors des queries
- C) Avant de descendre dans les enfants lors d'une query ou update
- D) Après avoir remonté les valeurs
- E) Jamais, c'est automatique
- F) Seulement pour les feuilles
- G) À chaque opération sur la racine
- H) Lors de la construction
- I) Seulement si lazy[node] > 0
- J) Après chaque 10 opérations

**Réponse : C**

---

### Question 4
**Quelle est l'élément neutre pour une query de minimum ?**

- A) 0
- B) -1
- C) i64::MIN
- D) i64::MAX
- E) null
- F) Le premier élément du tableau
- G) La moyenne du tableau
- H) undefined
- I) NaN
- J) INFINITY

**Réponse : D**

---

### Question 5
**Combien de nœuds sont visités au maximum lors d'une query(l, r) ?**

- A) Exactement log n
- B) Au plus 2 * log n (2 par niveau)
- C) Au plus 4 * log n
- D) r - l + 1
- E) n
- F) 2n
- G) Exactement (r - l + 1) * log n
- H) 1
- I) n / 2
- J) log(r - l + 1)

**Réponse : C**

---

## 📊 SECTION 8 : RÉCAPITULATIF

| Aspect | Valeur |
|--------|--------|
| **Exercice** | 1.3.7 - wan_shi_tong_library |
| **Difficulté base** | ★★★★★☆☆☆☆☆ (5/10) |
| **Difficulté bonus max** | 🧠 (11/10 - Persistent) |
| **Temps estimé** | 60 min (base) + 90 min (bonus) |
| **XP Total possible** | 150 + 300 + 450 + 900 = 1800 |
| **Concepts clés** | Segment Tree, Range Query, Lazy Propagation, Persistence |
| **Langages** | Rust Edition 2024, C17 |
| **Complexité finale** | O(log n) par opération |

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.3.7-wan-shi-tong-library",
    "generated_at": "2026-01-11 12:00:00",

    "metadata": {
      "exercise_id": "1.3.7",
      "exercise_name": "wan_shi_tong_library",
      "module": "1.3",
      "module_name": "Trees",
      "concept": "Segment Trees",
      "concept_name": "Range Queries with Segment Trees",
      "type": "code",
      "tier": 3,
      "tier_info": "Synthèse",
      "phase": 1,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "rust",
      "language_version": "Edition 2024",
      "duration_minutes": 60,
      "xp_base": 150,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T2 O(log n)",
      "complexity_space": "S2 O(n)",
      "prerequisites": ["binary_trees", "recursion", "divide_conquer"],
      "domains": ["Struct", "Algo", "MD"],
      "domains_bonus": ["AL"],
      "tags": ["segment-tree", "range-query", "lazy-propagation", "avatar"],
      "meme_reference": "Wan Shi Tong - He Who Knows Ten Thousand Things"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_solution.c": "/* Section 4.3 */",
      "references/ref_solution_lazy.rs": "/* Section 4.6 */",
      "alternatives/alt_iterative.rs": "/* Section 4.4 */",
      "mutants/mutant_a_overflow.rs": "/* Section 4.10 */",
      "mutants/mutant_b_no_pushdown.rs": "/* Section 4.10 */",
      "mutants/mutant_c_small_array.rs": "/* Section 4.10 */",
      "mutants/mutant_d_wrong_condition.rs": "/* Section 4.10 */",
      "mutants/mutant_e_wrong_identity.rs": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution.c",
        "references/ref_solution_lazy.rs",
        "alternatives/alt_iterative.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_overflow.rs",
        "mutants/mutant_b_no_pushdown.rs",
        "mutants/mutant_c_small_array.rs",
        "mutants/mutant_d_wrong_condition.rs",
        "mutants/mutant_e_wrong_identity.rs"
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

*Wan Shi Tong approuve ce catalogage.*
*"You are not welcome anymore."* — Wan Shi Tong (aux bugs)
