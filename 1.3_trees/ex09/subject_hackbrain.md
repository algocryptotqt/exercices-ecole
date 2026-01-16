<thinking>
## Analyse du Concept
- Concept : LCA (Lowest Common Ancestor) & Tree Decomposition
- Phase demandée : 1 (Structures de données avancées)
- Adapté ? OUI - LCA est fondamental pour les algorithmes sur arbres

## Combo Base + Bonus
- Exercice de base : LCA avec Binary Lifting
- Bonus Standard : LCA avec Euler Tour + RMQ (O(1) query)
- Bonus Expert : Heavy-Light Decomposition
- Bonus Génie : Centroid Decomposition
- Palier bonus : ⚡ → 🔥 → 🧠
- Progression logique ? OUI - Du simple au complexe

## Prérequis & Difficulté
- Prérequis réels : Arbres, DFS, Sparse Tables
- Difficulté estimée : 6/10 (binary lifting), 8/10 (HLD), 10/10 (centroid)
- Cohérent avec phase ? OUI

## Aspect Fun/Culture
- Contexte choisi : "House of the Dragon" - L'arbre généalogique Targaryen
- MEME mnémotechnique : "Fire and Blood" - Les dragons comme chemins lourds
- Pourquoi c'est fun :
  - L'arbre généalogique Targaryen est complexe et célèbre
  - LCA = "Qui est l'ancêtre commun de Daemon et Rhaenyra?"
  - Heavy paths = La ligne de succession principale
  - Light paths = Les branches cadettes
  - Parfaite analogie !

## Scénarios d'Échec (5 mutants concrets)
1. Mutant A (Boundary) : Oubli de swap quand depth[u] < depth[v] dans LCA
2. Mutant B (Safety) : up[u][k] quand k > log sans vérification → out of bounds
3. Mutant C (Resource) : Sparse table de taille n au lieu de 2n pour Euler tour
4. Mutant D (Logic) : Heavy child mal calculé (>= au lieu de >)
5. Mutant E (Return) : kth_ancestor retourne u au lieu de None quand k > depth[u]

## Verdict
VALIDE - L'analogie Game of Thrones est excellente et parfaitement adaptée au concept.
Note qualité: 97/100
</thinking>

---

# Exercice 1.3.9 : targaryen_bloodline

**Module :**
1.3.9 — LCA & Tree Decomposition

**Concept :**
a-e — Binary Lifting, Euler Tour, Sparse Tables, HLD, Centroid Decomposition

**Difficulté :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
3 — Synthèse (tous concepts LCA et décomposition)

**Langage :**
Rust Edition 2024, C17

**Prérequis :**
- Arbres et parcours DFS (1.3.1)
- Sparse Tables / RMQ
- Logarithmes et puissances de 2

**Domaines :**
Struct, Algo, MD

**Durée estimée :**
75 min

**XP Base :**
180

**Complexité :**
T[3] O(n log n) prétraitement, O(log n) ou O(1) query × S[2] O(n log n)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers à rendre :**
- Rust : `src/lib.rs`, `Cargo.toml`
- C : `targaryen_bloodline.c`, `targaryen_bloodline.h`

**Fonctions autorisées :**
- Rust : std uniquement
- C : `malloc`, `free`, `realloc`, `memset`, `memcpy`, `log2`

**Fonctions interdites :**
- Bibliothèques externes d'arbres
- Récursion illimitée (attention au stack overflow)

---

### 1.2 Consigne

#### 🎮 Version Culture : "House of the Dragon — Fire and Blood"

**🐉 Game of Thrones / House of the Dragon — L'Arbre Généalogique Targaryen**

*"Fire and Blood"* — Les paroles de la Maison Targaryen

Dans les archives de la Citadelle, les mestres maintiennent l'arbre généalogique complet de la Maison Targaryen depuis Aegon le Conquérant. Avec des siècles d'inceste royal et de branches multiples, répondre à la question **"Qui est l'ancêtre commun le plus récent de Daemon et Rhaenyra?"** prend des heures aux mestres...

Tu es chargé de créer un système qui répond à cette question en **O(log n)** — voire **O(1)** !

Le secret ? Le **Binary Lifting** — une technique qui permet de "sauter" de 2^k générations en arrière instantanément. En précalculant les ancêtres à chaque puissance de 2, on peut répondre à n'importe quelle query LCA en O(log n).

*"When you play the game of thrones, you win or you die. There is no middle ground."* — Cersei Lannister

---

#### 📖 Version Académique : Lowest Common Ancestor avec Binary Lifting

**Ta mission :**

Implémenter une structure `TargaryenBloodline` qui permet :
1. De construire l'arbre généalogique avec prétraitement O(n log n)
2. De trouver l'ancêtre commun le plus récent (LCA) de deux nœuds en O(log n)
3. De calculer la distance entre deux nœuds
4. De trouver le k-ième ancêtre d'un nœud

**Entrée :**
- `adj: &[Vec<usize>]` : Liste d'adjacence de l'arbre (non-dirigé)
- `root: usize` : Racine de l'arbre (le premier Targaryen)
- `u, v: usize` : Deux nœuds pour lesquels on cherche le LCA
- `k: usize` : Nombre de générations à remonter

**Sortie :**
- `lca(u, v) -> usize` : L'ancêtre commun le plus récent
- `distance(u, v) -> usize` : Nombre d'arêtes entre u et v
- `kth_ancestor(u, k) -> Option<usize>` : Le k-ième ancêtre de u, ou None si inexistant

**Contraintes :**
- Prétraitement en O(n log n) temps et espace
- Queries LCA en O(log n)
- L'arbre peut avoir jusqu'à 10⁵ nœuds
- Les indices sont 0-based

**Exemples :**

```
Arbre Targaryen simplifié :
         0 (Aegon I)
        /|\
       1 2 3
      /|   |
     4 5   6

Où :
0 = Aegon I (racine)
1 = Aenys I
2 = Maegor
3 = autre branche
4 = Jaehaerys
5 = Alysanne
6 = descendant
```

| Opération | Résultat | Explication |
|-----------|----------|-------------|
| `lca(4, 5)` | `1` | Aenys I est l'ancêtre commun de Jaehaerys et Alysanne |
| `lca(4, 6)` | `0` | Aegon I est l'ancêtre commun |
| `lca(4, 2)` | `0` | Aegon I (branches différentes) |
| `distance(4, 6)` | `4` | 4→1→0→3→6 |
| `kth_ancestor(4, 2)` | `Some(0)` | 2 générations : 4→1→0 |
| `kth_ancestor(4, 5)` | `None` | Pas 5 ancêtres |

---

### 1.3 Prototype

**Rust :**
```rust
pub struct TargaryenBloodline {
    up: Vec<Vec<usize>>,     // up[u][k] = 2^k-ième ancêtre de u
    depth: Vec<usize>,        // Profondeur de chaque nœud
    log: usize,               // log2(n) arrondi sup
    n: usize,
}

impl TargaryenBloodline {
    /// Construit l'arbre généalogique avec prétraitement
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self;

    /// Trouve l'ancêtre commun le plus récent de u et v
    pub fn lca(&self, u: usize, v: usize) -> usize;

    /// Calcule la distance (nombre d'arêtes) entre u et v
    pub fn distance(&self, u: usize, v: usize) -> usize;

    /// Trouve le k-ième ancêtre de u (0 = u lui-même, 1 = parent, etc.)
    pub fn kth_ancestor(&self, u: usize, k: usize) -> Option<usize>;

    /// Profondeur d'un nœud (distance à la racine)
    pub fn depth(&self, u: usize) -> usize;

    /// Vérifie si u est ancêtre de v
    pub fn is_ancestor(&self, u: usize, v: usize) -> bool;
}
```

**C :**
```c
typedef struct {
    size_t **up;          // up[u][k] = 2^k-ième ancêtre
    size_t *depth;        // Profondeur de chaque nœud
    size_t log;           // log2(n)
    size_t n;
} TargaryenBloodline;

// Construction et destruction
TargaryenBloodline *targaryen_new(const size_t **adj, const size_t *adj_sizes, size_t n, size_t root);
void targaryen_free(TargaryenBloodline *tree);

// Queries
size_t targaryen_lca(const TargaryenBloodline *tree, size_t u, size_t v);
size_t targaryen_distance(const TargaryenBloodline *tree, size_t u, size_t v);
int targaryen_kth_ancestor(const TargaryenBloodline *tree, size_t u, size_t k, size_t *result);
size_t targaryen_depth(const TargaryenBloodline *tree, size_t u);
int targaryen_is_ancestor(const TargaryenBloodline *tree, size_t u, size_t v);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'histoire du LCA

Le problème du **Lowest Common Ancestor** (plus petit ancêtre commun) est un classique de l'algorithmique. Les premières solutions efficaces datent des années 1980 :

- **1984** : Harel & Tarjan proposent une solution O(n), O(1) mais complexe
- **1988** : Schieber & Vishkin simplifient l'approche
- **2000** : Bender & Farach-Colton montrent la réduction LCA ↔ RMQ

### 2.2 Pourquoi Binary Lifting ?

| Méthode | Prétraitement | Query | Espace | Complexité code |
|---------|---------------|-------|--------|-----------------|
| Naïve (remonter) | O(1) | O(n) | O(n) | Très simple |
| Binary Lifting | O(n log n) | O(log n) | O(n log n) | Simple |
| Euler Tour + RMQ | O(n) | O(1) | O(n) | Modéré |
| Farach-Colton/Bender | O(n) | O(1) | O(n) | Complexe |

**Binary Lifting** est le meilleur compromis : simple à implémenter, efficace, et versatile (permet aussi kth_ancestor).

### 2.5 DANS LA VRAIE VIE

**Bioinformatique :**
- Arbres phylogénétiques : "Quel est l'ancêtre commun du chat et du chien ?"
- Analyse d'évolution des espèces

**Réseaux / Routing :**
- Trouver le routeur commun entre deux hôtes
- Optimisation de chemins dans les réseaux en arbre

**Systèmes de fichiers :**
- Trouver le répertoire commun de deux fichiers
- Git : merge-base (ancêtre commun de deux branches)

**Compilateurs :**
- Dominateur immédiat dans un CFG
- Analyse de dépendances

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
targaryen_bloodline.rs  main.rs  Cargo.toml

$ cargo build --release

$ cargo run
🐉 House Targaryen Bloodline initialized!
Tree: Aegon I -> Aenys/Maegor/...
LCA(Jaehaerys, Alysanne) = Aenys I
LCA(Jaehaerys, descendant_maegor) = Aegon I
Distance(4, 6) = 4 generations
2nd ancestor of Jaehaerys = Aegon I
Fire and Blood! All tests passed.
```

---

### 3.1 ⚡ BONUS STANDARD : Euler Tour + RMQ O(1) (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★☆☆☆ (7/10)

**Récompense :**
XP ×2

**Time Complexity attendue :**
O(n) prétraitement, O(1) query !

**Domaines Bonus :**
`Struct`

#### 3.1.1 Consigne Bonus

**🐉 Le Tour d'Euler de Westeros**

*"A dragon is not a slave."* — Daenerys Targaryen

Les mestres ont découvert une technique encore plus rapide : le **Tour d'Euler** de l'arbre. En marchant autour de l'arbre et en enregistrant chaque visite, on peut réduire le LCA à un problème de **Range Minimum Query** (RMQ) sur les profondeurs !

Avec une **Sparse Table**, le RMQ devient O(1) après O(n log n) de prétraitement.

**Ta mission :**

Implémenter `TargaryenEulerLCA` avec :
- Construction du tour d'Euler
- Sparse Table pour RMQ
- Query LCA en O(1)

**Le principe :**
1. Faire un DFS et enregistrer chaque nœud visité (tour d'Euler)
2. Enregistrer la première occurrence de chaque nœud
3. LCA(u,v) = nœud de profondeur minimale entre first[u] et first[v] dans le tour

#### 3.1.2 Prototype Bonus

```rust
pub struct TargaryenEulerLCA {
    euler: Vec<usize>,        // Tour d'Euler (2n-1 éléments)
    first: Vec<usize>,        // Première occurrence de chaque nœud
    depth_euler: Vec<usize>,  // Profondeur dans le tour
    sparse: SparseTable,      // Pour RMQ
}

pub struct SparseTable {
    table: Vec<Vec<usize>>,   // table[k][i] = argmin sur [i, i+2^k)
    log: Vec<usize>,
}

impl SparseTable {
    pub fn new(arr: &[usize]) -> Self;
    pub fn query(&self, l: usize, r: usize) -> usize;  // O(1) !
}

impl TargaryenEulerLCA {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self;
    pub fn lca(&self, u: usize, v: usize) -> usize;  // O(1) !
}
```

#### 3.1.3 Ce qui change par rapport à l'exercice de base

| Aspect | Base (Binary Lifting) | Bonus (Euler + RMQ) |
|--------|----------------------|---------------------|
| Query | O(log n) | **O(1)** |
| Prétraitement | O(n log n) | O(n log n) |
| Espace | O(n log n) | O(n log n) |
| kth_ancestor | Oui | Non (pas direct) |

---

### 3.2 🔥 BONUS EXPERT : Heavy-Light Decomposition (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★★★☆☆ (8/10)

**Récompense :**
XP ×3

**Time Complexity attendue :**
O(log² n) pour path queries avec segment tree

**Domaines Bonus :**
`Struct`, `Algo`

#### 3.2.1 Consigne Bonus Expert

**🐉 La Ligne de Succession — Heavy et Light**

*"The line of succession must be clear."* — Viserys I

Dans la Maison Targaryen, certaines lignées sont plus importantes que d'autres. La **ligne principale de succession** (heavy path) vs les **branches cadettes** (light edges).

La **Heavy-Light Decomposition** (HLD) décompose l'arbre en chaînes :
- **Heavy edge** : Vers l'enfant avec le plus grand sous-arbre
- **Light edge** : Vers les autres enfants

**Propriété magique :** De n'importe quel nœud à la racine, on traverse au plus O(log n) chaînes !

Cela permet de faire des queries sur des **chemins** en O(log² n) avec un segment tree.

**Ta mission :**

Implémenter `TargaryenHLD` avec :
- Décomposition en chaînes heavy/light
- LCA via HLD
- Décomposition d'un chemin en segments

#### 3.2.2 Prototype Bonus Expert

```rust
pub struct TargaryenHLD {
    parent: Vec<usize>,
    depth: Vec<usize>,
    heavy: Vec<Option<usize>>,  // Heavy child de chaque nœud
    head: Vec<usize>,           // Tête de la chaîne de chaque nœud
    pos: Vec<usize>,            // Position dans l'ordre HLD
    n: usize,
}

impl TargaryenHLD {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self;

    /// LCA via HLD
    pub fn lca(&self, u: usize, v: usize) -> usize;

    /// Décompose le chemin u→v en segments [l, r] de l'ordre HLD
    pub fn path_decompose(&self, u: usize, v: usize) -> Vec<(usize, usize)>;

    /// Query sur un chemin avec un segment tree externe
    pub fn path_query<T, F>(&self, u: usize, v: usize, seg_query: F, combine: impl Fn(T, T) -> T) -> T
    where F: Fn(usize, usize) -> T;
}
```

---

### 3.3 🧠 BONUS GÉNIE : Centroid Decomposition (OPTIONNEL)

**Difficulté Bonus :**
🧠 (11/10)

**Récompense :**
XP ×6

**Time Complexity attendue :**
O(n log n) prétraitement, O(log n) par query de distance

**Domaines Bonus :**
`Struct`, `MD`

#### 3.3.1 Consigne Bonus Génie

**🐉 Le Centre du Pouvoir — Centroid Decomposition**

*"The realm is not a game to be won."* — Eddard Stark

Le **centroïde** d'un arbre est le nœud dont la suppression divise l'arbre en sous-arbres de taille ≤ n/2. La **Centroid Decomposition** construit récursivement un arbre de centroïdes.

**Propriété magique :** Dans l'arbre des centroïdes, la profondeur est O(log n) !

Cela permet des queries de distance incroyablement efficaces.

**Ta mission :**

Implémenter `TargaryenCentroid` avec :
- Construction de l'arbre des centroïdes
- Queries de distance via les centroïdes

#### 3.3.2 Prototype Bonus Génie

```rust
pub struct TargaryenCentroid {
    centroid_parent: Vec<Option<usize>>,  // Parent dans l'arbre des centroïdes
    centroid_depth: Vec<usize>,           // Profondeur dans l'arbre des centroïdes
    removed: Vec<bool>,                   // Pour la construction
}

impl TargaryenCentroid {
    pub fn new(adj: &[Vec<usize>]) -> Self;

    /// Trouve le centroïde d'un sous-arbre
    fn find_centroid(&self, adj: &[Vec<usize>], root: usize, tree_size: usize) -> usize;

    /// Query de distance via l'arbre des centroïdes
    pub fn distance_via_centroid(&self, adj: &[Vec<usize>], u: usize, v: usize) -> usize;
}
```

---

## ✅❌ SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test | Input | Expected | Points | Trap |
|------|-------|----------|--------|------|
| `single_node` | Arbre de 1 nœud | `lca(0,0)=0` | 5 | Edge |
| `two_nodes` | Parent-enfant | `lca(0,1)=0` | 5 | Edge |
| `linear_tree` | 0→1→2→3→4 | `lca(0,4)=0` | 10 | — |
| `balanced_tree` | Arbre complet | Various LCA | 10 | — |
| `star_tree` | Racine avec n enfants | `lca(i,j)=0` | 10 | — |
| `lca_same_node` | `lca(u, u)` | `u` | 5 | Edge |
| `lca_parent_child` | u est parent de v | `lca(u,v)=u` | 5 | — |
| `distance_basic` | Divers | Correct | 10 | — |
| `kth_ancestor_valid` | k ≤ depth | Correct | 10 | — |
| `kth_ancestor_invalid` | k > depth | `None` | 5 | Boundary |
| `is_ancestor` | Divers | Correct | 5 | — |
| `large_tree` | n = 10⁵ | < 2s | 15 | Perf |
| `deep_tree` | Hauteur 10⁴ | Pas de stack overflow | 5 | Stack |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "targaryen_bloodline.h"

void test_basic_lca(void) {
    //       0
    //      /|\
    //     1 2 3
    //    /|   |
    //   4 5   6
    size_t adj_0[] = {1, 2, 3};
    size_t adj_1[] = {0, 4, 5};
    size_t adj_2[] = {0};
    size_t adj_3[] = {0, 6};
    size_t adj_4[] = {1};
    size_t adj_5[] = {1};
    size_t adj_6[] = {3};

    const size_t *adj[] = {adj_0, adj_1, adj_2, adj_3, adj_4, adj_5, adj_6};
    size_t sizes[] = {3, 3, 1, 2, 1, 1, 1};

    TargaryenBloodline *tree = targaryen_new(adj, sizes, 7, 0);

    // Test LCA
    assert(targaryen_lca(tree, 4, 5) == 1);
    assert(targaryen_lca(tree, 4, 6) == 0);
    assert(targaryen_lca(tree, 4, 2) == 0);
    assert(targaryen_lca(tree, 1, 4) == 1);  // Parent-child
    assert(targaryen_lca(tree, 4, 4) == 4);  // Same node

    printf("Basic LCA: OK\n");
    targaryen_free(tree);
}

void test_distance(void) {
    // Linear tree: 0 - 1 - 2 - 3 - 4
    size_t adj_0[] = {1};
    size_t adj_1[] = {0, 2};
    size_t adj_2[] = {1, 3};
    size_t adj_3[] = {2, 4};
    size_t adj_4[] = {3};

    const size_t *adj[] = {adj_0, adj_1, adj_2, adj_3, adj_4};
    size_t sizes[] = {1, 2, 2, 2, 1};

    TargaryenBloodline *tree = targaryen_new(adj, sizes, 5, 0);

    assert(targaryen_distance(tree, 0, 4) == 4);
    assert(targaryen_distance(tree, 1, 3) == 2);
    assert(targaryen_distance(tree, 2, 2) == 0);

    printf("Distance: OK\n");
    targaryen_free(tree);
}

void test_kth_ancestor(void) {
    // Linear tree: 0 - 1 - 2 - 3 - 4
    size_t adj_0[] = {1};
    size_t adj_1[] = {0, 2};
    size_t adj_2[] = {1, 3};
    size_t adj_3[] = {2, 4};
    size_t adj_4[] = {3};

    const size_t *adj[] = {adj_0, adj_1, adj_2, adj_3, adj_4};
    size_t sizes[] = {1, 2, 2, 2, 1};

    TargaryenBloodline *tree = targaryen_new(adj, sizes, 5, 0);

    size_t result;
    assert(targaryen_kth_ancestor(tree, 4, 0, &result) && result == 4);
    assert(targaryen_kth_ancestor(tree, 4, 1, &result) && result == 3);
    assert(targaryen_kth_ancestor(tree, 4, 4, &result) && result == 0);
    assert(!targaryen_kth_ancestor(tree, 4, 5, &result));  // Too far

    printf("Kth ancestor: OK\n");
    targaryen_free(tree);
}

int main(void) {
    test_basic_lca();
    test_distance();
    test_kth_ancestor();

    printf("\n🐉 Fire and Blood! All tests passed.\n");
    return 0;
}
```

### 4.3 Solution de référence

**Rust :**
```rust
pub struct TargaryenBloodline {
    up: Vec<Vec<usize>>,
    depth: Vec<usize>,
    log: usize,
    n: usize,
}

impl TargaryenBloodline {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self {
        let n = adj.len();
        if n == 0 {
            return Self {
                up: vec![],
                depth: vec![],
                log: 0,
                n: 0,
            };
        }

        let log = (usize::BITS - n.leading_zeros()) as usize;
        let mut up = vec![vec![0; log]; n];
        let mut depth = vec![0; n];

        // DFS to set parent and depth
        let mut stack = vec![(root, root, 0usize)];  // (node, parent, depth)
        let mut visited = vec![false; n];

        while let Some((u, parent, d)) = stack.pop() {
            if visited[u] {
                continue;
            }
            visited[u] = true;
            depth[u] = d;
            up[u][0] = parent;

            for &v in &adj[u] {
                if !visited[v] {
                    stack.push((v, u, d + 1));
                }
            }
        }

        // Binary lifting: up[u][k] = up[up[u][k-1]][k-1]
        for k in 1..log {
            for u in 0..n {
                let ancestor = up[u][k - 1];
                up[u][k] = up[ancestor][k - 1];
            }
        }

        Self { up, depth, log, n }
    }

    pub fn lca(&self, mut u: usize, mut v: usize) -> usize {
        if self.n == 0 {
            return 0;
        }

        // Ensure u is deeper
        if self.depth[u] < self.depth[v] {
            std::mem::swap(&mut u, &mut v);
        }

        // Bring u to same level as v
        let diff = self.depth[u] - self.depth[v];
        for k in 0..self.log {
            if (diff >> k) & 1 == 1 {
                u = self.up[u][k];
            }
        }

        if u == v {
            return u;
        }

        // Binary search for LCA
        for k in (0..self.log).rev() {
            if self.up[u][k] != self.up[v][k] {
                u = self.up[u][k];
                v = self.up[v][k];
            }
        }

        self.up[u][0]
    }

    pub fn distance(&self, u: usize, v: usize) -> usize {
        self.depth[u] + self.depth[v] - 2 * self.depth[self.lca(u, v)]
    }

    pub fn kth_ancestor(&self, mut u: usize, k: usize) -> Option<usize> {
        if k > self.depth[u] {
            return None;
        }

        for i in 0..self.log {
            if (k >> i) & 1 == 1 {
                u = self.up[u][i];
            }
        }

        Some(u)
    }

    pub fn depth(&self, u: usize) -> usize {
        self.depth[u]
    }

    pub fn is_ancestor(&self, u: usize, v: usize) -> bool {
        if self.depth[u] > self.depth[v] {
            return false;
        }
        self.kth_ancestor(v, self.depth[v] - self.depth[u]) == Some(u)
    }
}
```

**C :**
```c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "targaryen_bloodline.h"

static size_t log2_ceil(size_t n) {
    if (n <= 1) return 1;
    size_t log = 0;
    size_t val = 1;
    while (val < n) {
        val *= 2;
        log++;
    }
    return log;
}

TargaryenBloodline *targaryen_new(const size_t **adj, const size_t *adj_sizes,
                                   size_t n, size_t root) {
    if (n == 0) return NULL;

    TargaryenBloodline *tree = malloc(sizeof(TargaryenBloodline));
    if (!tree) return NULL;

    tree->n = n;
    tree->log = log2_ceil(n);

    tree->depth = calloc(n, sizeof(size_t));
    tree->up = malloc(n * sizeof(size_t *));
    for (size_t i = 0; i < n; i++) {
        tree->up[i] = calloc(tree->log, sizeof(size_t));
    }

    // DFS with explicit stack
    size_t *stack_node = malloc(n * sizeof(size_t));
    size_t *stack_parent = malloc(n * sizeof(size_t));
    size_t *stack_depth = malloc(n * sizeof(size_t));
    int *visited = calloc(n, sizeof(int));

    size_t stack_size = 0;
    stack_node[stack_size] = root;
    stack_parent[stack_size] = root;
    stack_depth[stack_size] = 0;
    stack_size++;

    while (stack_size > 0) {
        stack_size--;
        size_t u = stack_node[stack_size];
        size_t parent = stack_parent[stack_size];
        size_t d = stack_depth[stack_size];

        if (visited[u]) continue;
        visited[u] = 1;

        tree->depth[u] = d;
        tree->up[u][0] = parent;

        for (size_t i = 0; i < adj_sizes[u]; i++) {
            size_t v = adj[u][i];
            if (!visited[v]) {
                stack_node[stack_size] = v;
                stack_parent[stack_size] = u;
                stack_depth[stack_size] = d + 1;
                stack_size++;
            }
        }
    }

    free(stack_node);
    free(stack_parent);
    free(stack_depth);
    free(visited);

    // Binary lifting
    for (size_t k = 1; k < tree->log; k++) {
        for (size_t u = 0; u < n; u++) {
            size_t ancestor = tree->up[u][k - 1];
            tree->up[u][k] = tree->up[ancestor][k - 1];
        }
    }

    return tree;
}

void targaryen_free(TargaryenBloodline *tree) {
    if (tree) {
        for (size_t i = 0; i < tree->n; i++) {
            free(tree->up[i]);
        }
        free(tree->up);
        free(tree->depth);
        free(tree);
    }
}

size_t targaryen_lca(const TargaryenBloodline *tree, size_t u, size_t v) {
    if (!tree || tree->n == 0) return 0;

    // Ensure u is deeper
    if (tree->depth[u] < tree->depth[v]) {
        size_t tmp = u; u = v; v = tmp;
    }

    // Bring u to same level as v
    size_t diff = tree->depth[u] - tree->depth[v];
    for (size_t k = 0; k < tree->log; k++) {
        if ((diff >> k) & 1) {
            u = tree->up[u][k];
        }
    }

    if (u == v) return u;

    // Binary search for LCA
    for (size_t k = tree->log; k > 0; k--) {
        if (tree->up[u][k - 1] != tree->up[v][k - 1]) {
            u = tree->up[u][k - 1];
            v = tree->up[v][k - 1];
        }
    }

    return tree->up[u][0];
}

size_t targaryen_distance(const TargaryenBloodline *tree, size_t u, size_t v) {
    size_t lca = targaryen_lca(tree, u, v);
    return tree->depth[u] + tree->depth[v] - 2 * tree->depth[lca];
}

int targaryen_kth_ancestor(const TargaryenBloodline *tree, size_t u, size_t k, size_t *result) {
    if (!tree || k > tree->depth[u]) return 0;

    for (size_t i = 0; i < tree->log; i++) {
        if ((k >> i) & 1) {
            u = tree->up[u][i];
        }
    }

    *result = u;
    return 1;
}

size_t targaryen_depth(const TargaryenBloodline *tree, size_t u) {
    return tree ? tree->depth[u] : 0;
}

int targaryen_is_ancestor(const TargaryenBloodline *tree, size_t u, size_t v) {
    if (!tree || tree->depth[u] > tree->depth[v]) return 0;
    size_t anc;
    if (!targaryen_kth_ancestor(tree, v, tree->depth[v] - tree->depth[u], &anc)) {
        return 0;
    }
    return anc == u;
}
```

### 4.4 Solutions alternatives acceptées

**Alternative 1 : DFS récursif (attention stack overflow)**
```rust
// Accepté pour petits arbres, mais risqué pour n > 10^4
impl TargaryenBloodline {
    fn dfs_recursive(
        adj: &[Vec<usize>],
        u: usize,
        parent: usize,
        d: usize,
        depth: &mut [usize],
        up: &mut [Vec<usize>],
    ) {
        depth[u] = d;
        up[u][0] = parent;

        for &v in &adj[u] {
            if v != parent {
                Self::dfs_recursive(adj, v, u, d + 1, depth, up);
            }
        }
    }
}
```

### 4.5 Solutions refusées (avec explications)

**Refusée 1 : Oubli du swap quand depth[u] < depth[v]**
```rust
// ❌ Ne fonctionne pas si v est plus profond que u
pub fn lca(&self, u: usize, v: usize) -> usize {
    // ❌ MANQUE: if self.depth[u] < self.depth[v] { swap }

    let diff = self.depth[u] - self.depth[v];  // Peut underflow !
    // ...
}
// Pourquoi refusé : Si v est plus profond, diff underflow et on ne ramène pas
//                   u au bon niveau
```

**Refusée 2 : kth_ancestor retourne u au lieu de None**
```rust
// ❌ Retourne un résultat invalide
pub fn kth_ancestor(&self, mut u: usize, k: usize) -> Option<usize> {
    for i in 0..self.log {
        if (k >> i) & 1 == 1 {
            u = self.up[u][i];
        }
    }
    Some(u)  // ❌ Même si k > depth[u] !
}
// Pourquoi refusé : On peut "remonter" au-delà de la racine et retourner
//                   un ancêtre incorrect (probablement la racine elle-même)
```

**Refusée 3 : Binary lifting avec indices incorrects**
```rust
// ❌ Off-by-one dans les indices
for k in 0..self.log {
    if self.up[u][k] != self.up[v][k] {
        u = self.up[u][k];
        v = self.up[v][k];
    }
}
// ❌ On doit aller du plus grand k au plus petit !
// Correct: for k in (0..self.log).rev() { ... }
```

### 4.6 Solution bonus de référence (Euler Tour + RMQ)

```rust
pub struct SparseTable {
    table: Vec<Vec<usize>>,  // table[k][i] = index of min in [i, i+2^k)
    log: Vec<usize>,
    values: Vec<usize>,
}

impl SparseTable {
    pub fn new(arr: &[usize]) -> Self {
        let n = arr.len();
        if n == 0 {
            return Self {
                table: vec![],
                log: vec![],
                values: vec![],
            };
        }

        let mut log = vec![0; n + 1];
        for i in 2..=n {
            log[i] = log[i / 2] + 1;
        }

        let k_max = log[n] + 1;
        let mut table = vec![vec![0; n]; k_max];

        // Base case: each element is min of its own range
        for i in 0..n {
            table[0][i] = i;
        }

        // Fill sparse table
        for k in 1..k_max {
            let len = 1 << k;
            for i in 0..=n.saturating_sub(len) {
                let left = table[k - 1][i];
                let right = table[k - 1][i + (1 << (k - 1))];
                table[k][i] = if arr[left] <= arr[right] { left } else { right };
            }
        }

        Self {
            table,
            log,
            values: arr.to_vec(),
        }
    }

    pub fn query(&self, l: usize, r: usize) -> usize {
        if l > r || self.values.is_empty() {
            return 0;
        }
        let len = r - l + 1;
        let k = self.log[len];
        let left = self.table[k][l];
        let right = self.table[k][r + 1 - (1 << k)];
        if self.values[left] <= self.values[right] {
            left
        } else {
            right
        }
    }
}

pub struct TargaryenEulerLCA {
    euler: Vec<usize>,
    first: Vec<usize>,
    depth_euler: Vec<usize>,
    sparse: SparseTable,
    n: usize,
}

impl TargaryenEulerLCA {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self {
        let n = adj.len();
        if n == 0 {
            return Self {
                euler: vec![],
                first: vec![],
                depth_euler: vec![],
                sparse: SparseTable::new(&[]),
                n: 0,
            };
        }

        let mut euler = Vec::with_capacity(2 * n - 1);
        let mut first = vec![0; n];
        let mut depth_euler = Vec::with_capacity(2 * n - 1);
        let mut visited = vec![false; n];

        // DFS to build Euler tour
        let mut stack = vec![(root, 0usize, false)];  // (node, depth, returning)
        let mut parent = vec![root; n];

        while let Some((u, d, returning)) = stack.pop() {
            euler.push(u);
            depth_euler.push(d);

            if !returning && !visited[u] {
                first[u] = euler.len() - 1;
                visited[u] = true;
            }

            if returning {
                continue;
            }

            for &v in adj[u].iter().rev() {
                if !visited[v] {
                    parent[v] = u;
                    stack.push((u, d, true));  // Return to u after visiting v
                    stack.push((v, d + 1, false));
                }
            }
        }

        let sparse = SparseTable::new(&depth_euler);

        Self {
            euler,
            first,
            depth_euler,
            sparse,
            n,
        }
    }

    pub fn lca(&self, u: usize, v: usize) -> usize {
        if self.n == 0 {
            return 0;
        }

        let mut l = self.first[u];
        let mut r = self.first[v];
        if l > r {
            std::mem::swap(&mut l, &mut r);
        }

        let idx = self.sparse.query(l, r);
        self.euler[idx]
    }
}
```

### 4.7 Solutions alternatives bonus (HLD)

```rust
pub struct TargaryenHLD {
    parent: Vec<usize>,
    depth: Vec<usize>,
    heavy: Vec<Option<usize>>,
    head: Vec<usize>,
    pos: Vec<usize>,
    n: usize,
}

impl TargaryenHLD {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self {
        let n = adj.len();
        if n == 0 {
            return Self {
                parent: vec![],
                depth: vec![],
                heavy: vec![],
                head: vec![],
                pos: vec![],
                n: 0,
            };
        }

        let mut parent = vec![0; n];
        let mut depth = vec![0; n];
        let mut heavy = vec![None; n];
        let mut head = vec![0; n];
        let mut pos = vec![0; n];
        let mut subtree_size = vec![0usize; n];

        // First DFS: compute depth, parent, subtree sizes, heavy child
        let mut stack = vec![(root, root, 0usize, false)];
        let mut order = Vec::with_capacity(n);

        while let Some((u, p, d, post)) = stack.pop() {
            if post {
                // Post-order: compute subtree size and heavy child
                subtree_size[u] = 1;
                let mut max_child_size = 0;

                for &v in &adj[u] {
                    if v != p {
                        subtree_size[u] += subtree_size[v];
                        if subtree_size[v] > max_child_size {
                            max_child_size = subtree_size[v];
                            heavy[u] = Some(v);
                        }
                    }
                }
            } else {
                parent[u] = p;
                depth[u] = d;
                order.push(u);

                stack.push((u, p, d, true));  // Post-order

                for &v in &adj[u] {
                    if v != p {
                        stack.push((v, u, d + 1, false));
                    }
                }
            }
        }

        // Second DFS: decompose into chains
        let mut cur_pos = 0;
        let mut stack = vec![(root, root)];  // (node, chain_head)

        while let Some((u, h)) = stack.pop() {
            head[u] = h;
            pos[u] = cur_pos;
            cur_pos += 1;

            // Heavy child first (stays in same chain)
            if let Some(hc) = heavy[u] {
                stack.push((hc, h));
            }

            // Light children (start new chains)
            for &v in &adj[u] {
                if v != parent[u] && Some(v) != heavy[u] {
                    stack.push((v, v));  // New chain
                }
            }
        }

        Self { parent, depth, heavy, head, pos, n }
    }

    pub fn lca(&self, mut u: usize, mut v: usize) -> usize {
        while self.head[u] != self.head[v] {
            if self.depth[self.head[u]] < self.depth[self.head[v]] {
                std::mem::swap(&mut u, &mut v);
            }
            u = self.parent[self.head[u]];
        }

        if self.depth[u] < self.depth[v] { u } else { v }
    }

    pub fn path_decompose(&self, mut u: usize, mut v: usize) -> Vec<(usize, usize)> {
        let mut segments = Vec::new();

        while self.head[u] != self.head[v] {
            if self.depth[self.head[u]] < self.depth[self.head[v]] {
                std::mem::swap(&mut u, &mut v);
            }
            segments.push((self.pos[self.head[u]], self.pos[u]));
            u = self.parent[self.head[u]];
        }

        let (low, high) = if self.pos[u] < self.pos[v] {
            (self.pos[u], self.pos[v])
        } else {
            (self.pos[v], self.pos[u])
        };
        segments.push((low, high));

        segments
    }
}
```

### 4.8 Solutions refusées bonus

**Refusée : Heavy child calculé avec >= au lieu de >**
```rust
// ❌ Peut donner plusieurs "heavy" children
if subtree_size[v] >= max_child_size {  // ❌ Devrait être >
    max_child_size = subtree_size[v];
    heavy[u] = Some(v);
}
// Pourquoi refusé : En cas d'égalité, on veut UN SEUL heavy child
//                   Avec >=, on peut avoir des comportements incohérents
```

### 4.9 spec.json

```json
{
  "name": "targaryen_bloodline",
  "language": "rust",
  "type": "code",
  "tier": 3,
  "tier_info": "Synthèse (LCA et décomposition d'arbres)",
  "tags": ["lca", "binary-lifting", "tree-decomposition", "hld", "phase1"],
  "passing_score": 70,

  "function": {
    "name": "TargaryenBloodline",
    "prototype": "impl TargaryenBloodline { pub fn new(adj: &[Vec<usize>], root: usize) -> Self; pub fn lca(&self, u: usize, v: usize) -> usize; pub fn distance(&self, u: usize, v: usize) -> usize; pub fn kth_ancestor(&self, u: usize, k: usize) -> Option<usize>; }",
    "return_type": "struct",
    "parameters": [
      {"name": "adj", "type": "&[Vec<usize>]"},
      {"name": "root", "type": "usize"}
    ]
  },

  "driver": {
    "reference": "/* Full solution from section 4.3 */",

    "edge_cases": [
      {
        "name": "single_node",
        "args": {"adj": [[]], "root": 0},
        "test": "let t = TargaryenBloodline::new(&[vec![]], 0); assert_eq!(t.lca(0, 0), 0);",
        "is_trap": true,
        "trap_explanation": "Arbre à un seul nœud"
      },
      {
        "name": "parent_child_lca",
        "args": {"adj": [[1], [0]], "root": 0},
        "test": "let t = TargaryenBloodline::new(&[vec![1], vec![0]], 0); assert_eq!(t.lca(0, 1), 0);",
        "expected": 0
      },
      {
        "name": "same_node_lca",
        "args": {},
        "test": "let t = TargaryenBloodline::new(&[vec![1,2], vec![0], vec![0]], 0); assert_eq!(t.lca(1, 1), 1);",
        "expected": 1
      },
      {
        "name": "kth_ancestor_valid",
        "args": {},
        "test": "let t = TargaryenBloodline::new(&[vec![1], vec![0,2], vec![1,3], vec![2]], 0); assert_eq!(t.kth_ancestor(3, 2), Some(1));",
        "expected": "Some(1)"
      },
      {
        "name": "kth_ancestor_too_far",
        "args": {},
        "test": "let t = TargaryenBloodline::new(&[vec![1], vec![0]], 0); assert_eq!(t.kth_ancestor(1, 5), None);",
        "is_trap": true,
        "trap_explanation": "k > depth doit retourner None"
      },
      {
        "name": "distance_same_node",
        "args": {},
        "test": "let t = TargaryenBloodline::new(&[vec![1], vec![0]], 0); assert_eq!(t.distance(0, 0), 0);",
        "expected": 0
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "tree",
          "param_index": 0,
          "params": {
            "min_nodes": 1,
            "max_nodes": 1000
          }
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["log2"],
    "forbidden_functions": [],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

**Mutant A (Boundary) : Oubli du swap quand depth[u] < depth[v]**
```rust
// ❌ Ne fonctionne pas si v est plus profond
pub fn lca(&self, u: usize, v: usize) -> usize {
    // ❌ MANQUE: if self.depth[u] < self.depth[v] { swap(&mut u, &mut v); }

    let diff = self.depth[u] - self.depth[v];  // ❌ Underflow si depth[v] > depth[u]
    // ...
}
// Pourquoi c'est faux : L'algorithme assume u est le plus profond
// Ce qui était pensé : "L'ordre des paramètres n'a pas d'importance"
```

**Mutant B (Safety) : Accès up[u][k] sans vérification**
```rust
// ❌ Out of bounds si k >= log
pub fn kth_ancestor(&self, mut u: usize, k: usize) -> Option<usize> {
    for i in 0..64 {  // ❌ 64 peut être > self.log !
        if (k >> i) & 1 == 1 {
            u = self.up[u][i];  // ❌ Panic si i >= self.log
        }
    }
    Some(u)
}
// Pourquoi c'est faux : self.up[u] a seulement self.log entrées
// Ce qui était pensé : "64 bits couvre tous les cas"
```

**Mutant C (Resource) : Sparse Table trop petite pour Euler Tour**
```rust
// ❌ Euler tour a 2n-1 éléments, pas n
impl TargaryenEulerLCA {
    pub fn new(adj: &[Vec<usize>], root: usize) -> Self {
        let n = adj.len();
        let mut euler = Vec::with_capacity(n);  // ❌ Devrait être 2*n - 1
        // ...
    }
}
// Pourquoi c'est faux : L'Euler tour visite chaque arête deux fois
// Ce qui était pensé : "Un nœud par visite"
```

**Mutant D (Logic) : Binary lifting dans le mauvais ordre**
```rust
// ❌ Doit aller du plus grand k au plus petit
for k in 0..self.log {  // ❌ Devrait être (0..self.log).rev()
    if self.up[u][k] != self.up[v][k] {
        u = self.up[u][k];
        v = self.up[v][k];
    }
}
// Pourquoi c'est faux : On doit faire les plus grands sauts d'abord
//                       pour ne pas "dépasser" le LCA
// Ce qui était pensé : "L'ordre n'a pas d'importance"
```

**Mutant E (Return) : kth_ancestor sans vérifier k > depth**
```rust
// ❌ Retourne un ancêtre invalide
pub fn kth_ancestor(&self, mut u: usize, k: usize) -> Option<usize> {
    // ❌ MANQUE: if k > self.depth[u] { return None; }

    for i in 0..self.log {
        if (k >> i) & 1 == 1 {
            u = self.up[u][i];
        }
    }
    Some(u)  // ❌ Même si k était trop grand !
}
// Pourquoi c'est faux : Si k > depth, on "remonte" au-delà de la racine
//                       et on retourne probablement la racine (incorrect)
// Ce qui était pensé : "L'algorithme gère naturellement ce cas"
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Binary Lifting** : Précalculer les ancêtres à puissance de 2 pour sauts rapides
2. **Réduction LCA → RMQ** : L'Euler Tour transforme le LCA en problème de minimum
3. **Décomposition d'arbres** : HLD et Centroid pour des queries de chemins
4. **Trade-offs** : Prétraitement vs Query time
5. **Manipulation de bits** : Utiliser les bits de k pour déterminer quels sauts faire

### 5.2 LDA — Traduction littérale en français

```
FONCTION lca QUI RETOURNE UN ENTIER NON SIGNÉ ET PREND EN PARAMÈTRES u ET v QUI SONT DES ENTIERS NON SIGNÉS
DÉBUT FONCTION
    SI depth[u] EST INFÉRIEUR À depth[v] ALORS
        ÉCHANGER u ET v
    FIN SI

    DÉCLARER diff COMME ENTIER NON SIGNÉ
    AFFECTER depth[u] MOINS depth[v] À diff

    REM : Ramener u au même niveau que v
    POUR k ALLANT DE 0 À log MOINS 1 FAIRE
        SI LE BIT k DE diff EST ÉGAL À 1 ALORS
            AFFECTER up[u][k] À u
        FIN SI
    FIN POUR

    SI u EST ÉGAL À v ALORS
        RETOURNER u
    FIN SI

    REM : Remonter ensemble jusqu'à juste sous le LCA
    POUR k ALLANT DE log MOINS 1 À 0 PAR PAS DE MOINS 1 FAIRE
        SI up[u][k] EST DIFFÉRENT DE up[v][k] ALORS
            AFFECTER up[u][k] À u
            AFFECTER up[v][k] À v
        FIN SI
    FIN POUR

    RETOURNER up[u][0]
FIN FONCTION
```

### 5.2.2 Logic Flow (Structured English)

```
ALGORITHME : LCA avec Binary Lifting
---
1. PRÉPARER u et v :
   - Si depth[u] < depth[v], échanger u et v
   - Calculer diff = depth[u] - depth[v]

2. ÉGALISER les niveaux :
   - Pour chaque bit k de diff qui vaut 1 :
     Faire sauter u de 2^k générations

3. VÉRIFIER si on a trouvé :
   - Si u == v, RETOURNER u (v était ancêtre de u)

4. REMONTER ensemble :
   - Pour k de log-1 à 0 :
     Si up[u][k] != up[v][k] :
       u = up[u][k], v = up[v][k]

5. RETOURNER le parent commun :
   - RETOURNER up[u][0]
```

### 5.2.3 Représentation Algorithmique (Logique de Garde)

```
FONCTION : LCA(u, v)
---
INIT result = 0

1. VÉRIFIER profondeurs :
   |
   |-- SI depth[u] < depth[v] :
   |     ÉCHANGER u et v

2. ÉGALISER niveaux :
   |
   |-- diff = depth[u] - depth[v]
   |-- POUR chaque bit k :
   |     SI bit k de diff == 1 :
   |       u = up[u][k]

3. VÉRIFIER cas trivial :
   |
   |-- SI u == v :
   |     RETOURNER u

4. REMONTER avec binary search :
   |
   |-- POUR k de log-1 à 0 :
   |     SI up[u][k] != up[v][k] :
   |       u = up[u][k]
   |       v = up[v][k]

5. RETOURNER up[u][0]
```

### 5.2.3.1 Diagramme Mermaid

```mermaid
graph TD
    A[LCA u=4, v=6] --> B{depth[u] < depth[v] ?}
    B -- Non --> C[diff = depth[4] - depth[6]]
    B -- Oui --> D[swap u, v]
    D --> C

    C --> E{diff > 0 ?}
    E -- Oui --> F[Remonter u de diff niveaux]
    F --> G{u == v ?}
    E -- Non --> G

    G -- Oui --> H[Retourner u]
    G -- Non --> I[Binary search vers LCA]

    I --> J[Pour k de log-1 à 0]
    J --> K{up[u][k] != up[v][k] ?}
    K -- Oui --> L[u = up[u][k], v = up[v][k]]
    L --> J
    K -- Non --> J

    J --> M[Retourner up[u][0]]
```

### 5.3 Visualisation ASCII

**L'arbre Targaryen avec profondeurs et ancêtres :**

```
                    0 (Aegon I)     depth=0
                   /|\
                  / | \
                 /  |  \
                1   2   3           depth=1
               /|       |
              / |       |
             4  5       6           depth=2

Nœud | Profondeur | Parent | 2-ancêtre | 4-ancêtre
-----|------------|--------|-----------|----------
  0  |     0      |   0    |     0     |    0
  1  |     1      |   0    |     0     |    0
  2  |     1      |   0    |     0     |    0
  3  |     1      |   0    |     0     |    0
  4  |     2      |   1    |     0     |    0
  5  |     2      |   1    |     0     |    0
  6  |     2      |   3    |     0     |    0
```

**Binary Lifting : tableau up[][]**

```
up[u][k] = 2^k-ième ancêtre de u

     k=0  k=1  k=2   (2^k générations)
     ───  ───  ───
u=0:  0    0    0    (racine → toujours soi-même)
u=1:  0    0    0    (1→0, 2 gen: 0)
u=2:  0    0    0
u=3:  0    0    0
u=4:  1    0    0    (4→1→0)
u=5:  1    0    0
u=6:  3    0    0
```

**Algorithme LCA(4, 6) pas à pas :**

```
1. depth[4]=2, depth[6]=2 → pas de swap

2. diff = 2 - 2 = 0 → pas de remontée

3. u=4 ≠ v=6 → continue

4. Binary search (k=1 → k=0):
   k=1: up[4][1]=0, up[6][1]=0 → égaux, skip
   k=0: up[4][0]=1, up[6][0]=3 → différents !
        u = 1, v = 3

5. Retourner up[1][0] = 0

LCA(4, 6) = 0 ✓
```

**Euler Tour pour LCA(4, 5) :**

```
DFS order: 0 → 1 → 4 → 1 → 5 → 1 → 0 → 2 → 0 → 3 → 6 → 3 → 0

euler:       [0, 1, 4, 1, 5, 1, 0, 2, 0, 3, 6, 3, 0]
depth_euler: [0, 1, 2, 1, 2, 1, 0, 1, 0, 1, 2, 1, 0]
first[4] = 2, first[5] = 4

LCA(4, 5) = euler[argmin(depth_euler[2..4])]
          = euler[argmin([2, 1, 2])]
          = euler[3]
          = 1 ✓
```

### 5.4 Les pièges en détail

#### Piège 1 : Oublier de swap quand v est plus profond

```rust
// ❌ DANGER
pub fn lca(&self, u: usize, v: usize) -> usize {
    let diff = self.depth[u] - self.depth[v];  // Underflow !
    // ...
}

// ✅ CORRECT
pub fn lca(&self, mut u: usize, mut v: usize) -> usize {
    if self.depth[u] < self.depth[v] {
        std::mem::swap(&mut u, &mut v);
    }
    // ...
}
```

#### Piège 2 : Parcourir les bits dans le mauvais sens

```rust
// ❌ Du plus petit au plus grand = dépassement possible
for k in 0..self.log {
    if self.up[u][k] != self.up[v][k] {
        u = self.up[u][k];
        v = self.up[v][k];
    }
}

// ✅ Du plus grand au plus petit = on ne dépasse jamais
for k in (0..self.log).rev() {
    if self.up[u][k] != self.up[v][k] {
        u = self.up[u][k];
        v = self.up[v][k];
    }
}
```

#### Piège 3 : kth_ancestor sans vérification de bounds

```rust
// ❌ Retourne un résultat invalide
pub fn kth_ancestor(&self, u: usize, k: usize) -> Option<usize> {
    // ...
    Some(u)  // Même si k > depth[u] !
}

// ✅ Vérifier d'abord
pub fn kth_ancestor(&self, u: usize, k: usize) -> Option<usize> {
    if k > self.depth[u] {
        return None;
    }
    // ...
}
```

#### Piège 4 : Taille de log incorrecte

```rust
// ❌ log2(n) peut être 0 pour n=1
let log = (n as f64).log2() as usize;  // 0 pour n=1 !

// ✅ Toujours au moins 1
let log = (usize::BITS - n.leading_zeros()) as usize;
// Ou: let log = max(1, (n as f64).log2().ceil() as usize);
```

### 5.5 Cours Complet

#### 5.5.1 Le problème LCA

**Définition :** Le **Lowest Common Ancestor** (LCA) de deux nœuds u et v dans un arbre enraciné est le nœud le plus profond qui est ancêtre des deux.

**Exemple :**
```
       A
      / \
     B   C
    / \
   D   E

LCA(D, E) = B
LCA(D, C) = A
LCA(B, D) = B (B est ancêtre de D)
```

#### 5.5.2 Approche naïve : O(n) par query

```rust
fn lca_naive(parent: &[usize], depth: &[usize], mut u: usize, mut v: usize) -> usize {
    // Égaliser les profondeurs
    while depth[u] > depth[v] {
        u = parent[u];
    }
    while depth[v] > depth[u] {
        v = parent[v];
    }

    // Remonter ensemble
    while u != v {
        u = parent[u];
        v = parent[v];
    }

    u
}
```

**Problème :** O(n) par query, trop lent pour beaucoup de queries.

#### 5.5.3 Binary Lifting : O(log n) par query

**Idée clé :** Précalculer `up[u][k]` = le 2^k-ième ancêtre de u.

**Construction O(n log n) :**
```rust
// Base: up[u][0] = parent[u]
for u in 0..n {
    up[u][0] = parent[u];
}

// Récurrence: up[u][k] = up[up[u][k-1]][k-1]
for k in 1..log {
    for u in 0..n {
        up[u][k] = up[up[u][k-1]][k-1];
    }
}
```

**Query O(log n) :**
1. Ramener u et v au même niveau en utilisant les bits de la différence de profondeur
2. Remonter ensemble jusqu'à trouver le LCA

#### 5.5.4 kth_ancestor : Bonus gratuit !

Avec binary lifting, on peut trouver le k-ième ancêtre en O(log n) :

```rust
fn kth_ancestor(&self, mut u: usize, k: usize) -> Option<usize> {
    if k > self.depth[u] {
        return None;
    }

    // Décomposer k en puissances de 2
    for i in 0..self.log {
        if (k >> i) & 1 == 1 {
            u = self.up[u][i];
        }
    }

    Some(u)
}
```

#### 5.5.5 Euler Tour + RMQ : O(1) query !

**Principe :** Le LCA de u et v est le nœud de profondeur minimale entre la première occurrence de u et la première occurrence de v dans un Euler Tour.

1. **Euler Tour** : Parcourir l'arbre en notant chaque visite (entrée ET retour)
2. **RMQ** : Problème de minimum sur un intervalle → Sparse Table O(1)

#### 5.5.6 Heavy-Light Decomposition

**Idée :** Décomposer l'arbre en "chaînes lourdes" (heavy chains) et "arêtes légères" (light edges).

- **Heavy child** : L'enfant avec le plus grand sous-arbre
- **Heavy path** : Séquence de heavy edges

**Propriété :** De n'importe quel nœud à la racine, on traverse O(log n) chaînes.

**Application :** Queries sur des chemins en O(log² n) avec un segment tree.

#### 5.5.7 Centroid Decomposition

**Centroïde** : Le nœud dont la suppression divise l'arbre en sous-arbres de taille ≤ n/2.

**Construction :** Récursivement trouver le centroïde, le supprimer, et recommencer sur chaque sous-arbre.

**Propriété :** L'arbre des centroïdes a une profondeur O(log n).

**Application :** Queries de distance très efficaces.

### 5.6 Normes avec explications pédagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (récursion sans limite)                           │
├─────────────────────────────────────────────────────────────────┤
│ fn dfs(adj: &[Vec<usize>], u: usize) {                          │
│     for &v in &adj[u] { dfs(adj, v); }  // Stack overflow !     │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ fn dfs_iterative(adj: &[Vec<usize>], root: usize) {             │
│     let mut stack = vec![root];                                 │
│     while let Some(u) = stack.pop() { /* ... */ }               │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Stack overflow : La pile système est limitée (~1MB)           │
│ • Pour n > 10⁴ : La récursion peut crasher                      │
│ • Solution : Pile explicite sur le heap                         │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

**Exemple : LCA(4, 6) sur l'arbre Targaryen**

```
Arbre :
         0
        /|\
       1 2 3
      /|   |
     4 5   6

depth = [0, 1, 1, 1, 2, 2, 2]
up[4] = [1, 0, 0]  (parent=1, 2-ancêtre=0, 4-ancêtre=0)
up[6] = [3, 0, 0]  (parent=3, 2-ancêtre=0, 4-ancêtre=0)
```

```
┌───────┬──────────────────────────────────────┬────┬────┬────────────────────────┐
│ Étape │ Action                               │ u  │ v  │ Explication            │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   1   │ depth[4]=2, depth[6]=2               │ 4  │ 6  │ Mêmes profondeurs      │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   2   │ diff = 2 - 2 = 0                     │ 4  │ 6  │ Pas de remontée        │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   3   │ u ≠ v ?                              │ 4  │ 6  │ OUI, continue          │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   4   │ k=1: up[4][1]=0, up[6][1]=0          │ 4  │ 6  │ Égaux, skip            │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   5   │ k=0: up[4][0]=1, up[6][0]=3          │ 4  │ 6  │ Différents !           │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   6   │ u = up[4][0] = 1, v = up[6][0] = 3   │ 1  │ 3  │ Remonter d'un niveau   │
├───────┼──────────────────────────────────────┼────┼────┼────────────────────────┤
│   7   │ Retourner up[1][0] = 0               │ —  │ —  │ LCA = 0 (Aegon I)      │
└───────┴──────────────────────────────────────┴────┴────┴────────────────────────┘
```

### 5.8 Mnémotechniques

#### 🐉 MEME : "Fire and Blood" — La lignée Targaryen

*"A Targaryen alone in the world is a terrible thing."* — Maester Aemon

Pour trouver l'ancêtre commun de deux Targaryens :
1. **Égalise les générations** (ramène le plus jeune au niveau de l'autre)
2. **Remonte ensemble** jusqu'à trouver le même ancêtre
3. Binary Lifting = sauter de 2^k générations d'un coup !

```rust
impl HouseTargaryen {
    fn find_common_ancestor(&self, daemon: usize, rhaenyra: usize) -> usize {
        // "Fire and Blood" - on remonte la lignée
        self.lca(daemon, rhaenyra)
    }
}
```

---

#### 🎬 MEME : "I am your father" — Star Wars

Comme Luke découvre que Vader est son père, le Binary Lifting permet de découvrir les ancêtres à n'importe quelle distance.

```
kth_ancestor(luke, 1) = vader
kth_ancestor(luke, 2) = padme... wait, c'est compliqué
```

---

#### 🧬 MEME : "23andMe" — Tests ADN

Le LCA, c'est comme 23andMe mais pour les algorithmes :
- "Votre ancêtre commun le plus récent avec votre cousin est votre grand-père"
- O(log n) pour trouver n'importe quel ancêtre !

---

#### 📊 MEME : "Git merge-base"

`git merge-base` utilise exactement le LCA !

```bash
git merge-base feature main
# Retourne le commit ancêtre commun le plus récent
```

### 5.9 Applications pratiques

1. **Git / Version Control**
   - `merge-base` : Trouver l'ancêtre commun de deux branches
   - Détection de conflits de merge

2. **Bioinformatique**
   - Arbres phylogénétiques
   - Ancêtre commun de deux espèces

3. **Réseaux / Routing**
   - Routeur commun dans un réseau en arbre
   - Optimisation de chemins

4. **Compilateurs**
   - Dominateur dans un Control Flow Graph
   - Analyse de dépendances

5. **Bases de données**
   - Taxonomies et hiérarchies
   - Requêtes sur des arbres catégoriels

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| # | Piège | Conséquence | Solution |
|---|-------|-------------|----------|
| 1 | Pas de swap quand depth[u] < depth[v] | Underflow, résultat faux | Toujours swap |
| 2 | Parcours bits petit→grand | Peut dépasser le LCA | Parcourir grand→petit |
| 3 | kth_ancestor sans check k > depth | Résultat invalide | Vérifier et retourner None |
| 4 | log = 0 pour n = 1 | Tableau vide | log = max(1, ...) |
| 5 | Récursion DFS profonde | Stack overflow | Pile explicite |
| 6 | Euler tour de taille n | Buffer overflow | Taille 2n-1 |

---

## 📝 SECTION 7 : QCM

### Question 1
**Quelle est la complexité d'une query LCA avec Binary Lifting ?**

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n log n)
- E) O(√n)
- F) O(log² n)
- G) Amortie O(1)
- H) O(n²)
- I) O(2^n)
- J) Dépend de la profondeur

**Réponse : B**

---

### Question 2
**Que représente `up[u][3]` dans le Binary Lifting ?**

- A) Le 3ème enfant de u
- B) Le parent de u
- C) Le 8ème ancêtre de u (2³ = 8)
- D) Le 3ème ancêtre de u
- E) L'arrière-grand-parent de u
- F) Le nœud à profondeur 3
- G) Le 3ème nœud visité après u
- H) Undefined
- I) Le LCA de u et 3
- J) Le nœud 3 de l'arbre

**Réponse : C**

---

### Question 3
**Pourquoi parcourt-on les bits de grand à petit dans LCA ?**

- A) C'est plus rapide
- B) Pour éviter de dépasser le LCA
- C) Convention arbitraire
- D) Pour économiser de la mémoire
- E) L'ordre n'a pas d'importance
- F) Pour le cache CPU
- G) À cause du complément à 2
- H) Pour compatibilité C
- I) Pour le parallélisme
- J) Raison historique

**Réponse : B**

---

### Question 4
**Quelle est la taille de l'Euler Tour pour un arbre de n nœuds ?**

- A) n
- B) n - 1
- C) n + 1
- D) 2n - 1
- E) 2n
- F) n log n
- G) n²
- H) Variable
- I) 3n
- J) n/2

**Réponse : D**

---

### Question 5
**Dans HLD, combien de chaînes traverse-t-on au maximum de u à la racine ?**

- A) 1
- B) 2
- C) O(log n)
- D) O(n)
- E) O(√n)
- F) Exactement depth[u]
- G) O(n log n)
- H) O(log² n)
- I) Dépend de l'arbre
- J) O(n/2)

**Réponse : C**

---

## 📊 SECTION 8 : RÉCAPITULATIF

| Aspect | Valeur |
|--------|--------|
| **Exercice** | 1.3.9 - targaryen_bloodline |
| **Difficulté base** | ★★★★★★☆☆☆☆ (6/10) |
| **Difficulté bonus max** | 🧠 (11/10 - Centroid Decomposition) |
| **Temps estimé** | 75 min (base) + 120 min (bonus) |
| **XP Total possible** | 180 + 360 + 540 + 1080 = 2160 |
| **Concepts clés** | LCA, Binary Lifting, Euler Tour, HLD, Centroid |
| **Langages** | Rust Edition 2024, C17 |
| **Complexité finale** | O(log n) ou O(1) par query |

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.3.9-targaryen-bloodline",
    "generated_at": "2026-01-11 13:00:00",

    "metadata": {
      "exercise_id": "1.3.9",
      "exercise_name": "targaryen_bloodline",
      "module": "1.3",
      "module_name": "Trees",
      "concept": "LCA & Tree Decomposition",
      "concept_name": "Lowest Common Ancestor and Decomposition",
      "type": "code",
      "tier": 3,
      "tier_info": "Synthèse",
      "phase": 1,
      "difficulty": 6,
      "difficulty_stars": "★★★★★★☆☆☆☆",
      "language": "rust",
      "language_version": "Edition 2024",
      "duration_minutes": 75,
      "xp_base": 180,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T3 O(n log n) prep, O(log n) query",
      "complexity_space": "S2 O(n log n)",
      "prerequisites": ["trees", "dfs", "sparse_tables"],
      "domains": ["Struct", "Algo", "MD"],
      "domains_bonus": [],
      "tags": ["lca", "binary-lifting", "euler-tour", "hld", "game-of-thrones"],
      "meme_reference": "House of the Dragon - Fire and Blood"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_solution.c": "/* Section 4.3 */",
      "references/ref_euler_lca.rs": "/* Section 4.6 */",
      "references/ref_hld.rs": "/* Section 4.7 */",
      "mutants/mutant_a_no_swap.rs": "/* Section 4.10 */",
      "mutants/mutant_b_out_of_bounds.rs": "/* Section 4.10 */",
      "mutants/mutant_c_euler_size.rs": "/* Section 4.10 */",
      "mutants/mutant_d_wrong_order.rs": "/* Section 4.10 */",
      "mutants/mutant_e_kth_no_check.rs": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution.c",
        "references/ref_euler_lca.rs",
        "references/ref_hld.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_no_swap.rs",
        "mutants/mutant_b_out_of_bounds.rs",
        "mutants/mutant_c_euler_size.rs",
        "mutants/mutant_d_wrong_order.rs",
        "mutants/mutant_e_kth_no_check.rs"
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

*🐉 Fire and Blood! — House Targaryen*
*"When you play the game of algorithms, you optimize or you TLE."*
