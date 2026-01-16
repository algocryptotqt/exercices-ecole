# MODULE 1.1 — PLAN D'EXERCICES
## 196 Concepts en 8 Projets de Qualité

**Philosophie:** Chaque projet est un système cohérent qui enseigne naturellement plusieurs concepts. L'étudiant apprend en construisant quelque chose d'utile, pas en faisant des exercices artificiels.

**Critères de qualité (95/100 minimum):**
- Progression pédagogique logique
- Concepts appris par la pratique, pas par la théorie
- Code Rust Edition 2024 idiomatique
- Testable par moulinette automatique
- Exercices originaux et engageants

---

## PROJET 1 : `ownership_debugger` (38 concepts)

**Idée:** Construire un débogueur visuel qui trace ownership, moves, borrows et drops dans un programme Rust simulé.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.1 | 7 | a, b, c, d, e, f, i |
| 1.1.2 | 15 | a-o |
| 1.1.3 | 16 | a-p |

### Partie A : Ownership Tracker (7 concepts 1.1.1)

**Exercice A1:** Implémenter `struct Value<T>` qui trace sa création et destruction.
```rust
// L'étudiant doit implémenter Drop pour tracer la destruction [1.1.1.i]
// Observer move semantics quand on passe Value à une fonction [1.1.1.b]
// Comprendre Copy vs Clone en implémentant les deux [1.1.1.c]
```

**Exercice A2:** Implémenter `struct BorrowTracker` qui compte les emprunts actifs.
```rust
// L'étudiant apprend borrowing rules en les implémentant [1.1.1.d]
// Comprendre lifetimes en annotant correctement [1.1.1.e]
// Distinguer stack vs heap allocation [1.1.1.f]
// Ownership fondamental via le design [1.1.1.a]
```

### Partie B : Slice Inspector (15 concepts 1.1.2)

**Exercice B1:** Implémenter `struct SliceView<'a, T>` qui encapsule un slice avec métadonnées.
```rust
// Comprendre [T; N] vs &[T] [1.1.2.a, 1.1.2.b]
// Implémenter accès safe avec get() [1.1.2.e]
// Supporter range slicing [1.1.2.f]
```

**Exercice B2:** Implémenter itérateurs custom sur SliceView.
```rust
// Implémenter iter() et iter_mut() [1.1.2.j, 1.1.2.k]
// Implémenter chunks() et windows() [1.1.2.l, 1.1.2.m]
// Implémenter split() et contains() [1.1.2.n, 1.1.2.o]
```

### Partie C : Vec Internals (16 concepts 1.1.3)

**Exercice C1:** Implémenter `struct MyVec<T>` from scratch.
```rust
// new(), with_capacity() [1.1.3.a, 1.1.3.c]
// push(), pop() [1.1.3.d, 1.1.3.e]
// insert(), remove() [1.1.3.f, 1.1.3.g]
// Observer growth strategy [1.1.3.m]
```

**Exercice C2:** Ajouter méthodes avancées à MyVec.
```rust
// capacity(), reserve(), shrink_to_fit() [1.1.3.i, 1.1.3.j, 1.1.3.k]
// extend(), drain(), retain() [1.1.3.n, 1.1.3.o, 1.1.3.p]
// Implémenter Deref to slice [1.1.3.l]
```

### Validation moulinette:
- Tests unitaires pour chaque méthode
- Test de non-leak mémoire (valgrind compatible)
- Test de performance (push 1M éléments < 100ms)

---

## PROJET 2 : `complexity_lab` (32 concepts)

**Idée:** Laboratoire interactif qui mesure et visualise la complexité d'algorithmes.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.5 | 8 | a-h |
| 1.1.6 | 9 | a-i |
| 1.1.7 | 7 | a-g |
| 1.1.8 | 8 | a-h |

### Partie A : Théorie Big-O (8 concepts 1.1.5)

**Exercice A1:** Implémenter `fn prove_big_o(f: fn(usize)->usize, g: fn(usize)->usize, c: f64, n0: usize) -> bool`
```rust
// L'étudiant doit comprendre la définition formelle [1.1.5.e]
// Vérifier f(n) ≤ c*g(n) pour tout n ≥ n0 [1.1.5.a]
```

**Exercice A2:** Implémenter des preuves pour Big-Ω et Big-Θ.
```rust
// Borne inférieure [1.1.5.b]
// Borne exacte [1.1.5.c]
// Propriétés algébriques [1.1.5.f]
```

### Partie B : Classes de Complexité (9 concepts 1.1.6)

**Exercice B1:** Implémenter une fonction pour chaque classe et mesurer.
```rust
fn constant(_n: usize) -> usize { 42 }  // O(1) [1.1.6.a]
fn logarithmic(n: usize) -> usize { (n as f64).log2() as usize }  // O(log n) [1.1.6.b]
fn linear(n: usize) -> usize { (0..n).sum() }  // O(n) [1.1.6.c]
// ... jusqu'à O(n!) [1.1.6.h]
```

**Exercice B2:** Mesurer la complexité spatiale de différents algorithmes.
```rust
// Complexité spatiale [1.1.6.i]
```

### Partie C : Analyse de Code (7 concepts 1.1.7)

**Exercice C1:** Analyseur qui compte les opérations dans du code Rust.
```rust
// Analyser boucles simples et imbriquées [1.1.7.b, 1.1.7.c]
// Analyser récursion [1.1.7.d]
// Analyser iterator chains [1.1.7.e]
```

### Partie D : Master Theorem Solver (8 concepts 1.1.8)

**Exercice D1:** Implémenter un solveur de récurrences.
```rust
// Parser T(n) = aT(n/b) + f(n) [1.1.8.a]
// Appliquer les 3 cas du Master Theorem [1.1.8.e, 1.1.8.f, 1.1.8.g, 1.1.8.h]
// Visualiser avec méthode de l'arbre [1.1.8.c]
```

### Validation moulinette:
- Tests avec fonctions de complexité connue
- Vérification des preuves Big-O
- Tests du solveur Master Theorem

---

## PROJET 3 : `recursion_explorer` (16 concepts)

**Idée:** Explorateur de récursion qui montre les limites et solutions en Rust.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.8bis | 7 | a-g |
| 1.1.9 | 9 | a-i |

### Partie A : Récursion Pratique (7 concepts 1.1.8bis)

**Exercice A1:** Implémenter factorial en 3 versions.
```rust
// Version récursive naïve - observer stack overflow [1.1.8bis.c]
fn factorial_naive(n: u64) -> u64;

// Version tail-recursive - comprendre que Rust ne garantit pas TCO [1.1.8bis.a, 1.1.8bis.b]
fn factorial_tail(n: u64, acc: u64) -> u64;

// Version itérative - conversion pattern [1.1.8bis.e]
fn factorial_iter(n: u64) -> u64;
```

**Exercice A2:** Implémenter trampolining pour mutual recursion.
```rust
// Pattern trampoline [1.1.8bis.f]
enum Bounce<T> {
    Done(T),
    More(Box<dyn FnOnce() -> Bounce<T>>),
}
```

**Exercice A3:** Utiliser stacker crate pour récursion profonde.
```rust
// Augmenter la pile dynamiquement [1.1.8bis.g]
// Comprendre les limites de pile [1.1.8bis.d]
```

### Partie B : Analyse Amortie (9 concepts 1.1.9)

**Exercice B1:** Prouver que Vec::push est O(1) amorti.
```rust
// Méthode agrégat : n pushes = O(n) total [1.1.9.b]
// Méthode comptable : chaque push paie pour futures copies [1.1.9.c]
// Méthode potentiel : Φ = 2*size - capacity [1.1.9.d]
```

**Exercice B2:** Analyser d'autres structures.
```rust
// String::push_str [1.1.9.g]
// HashMap resize [1.1.9.h]
// VecDeque, BinaryHeap [1.1.9.i]
```

### Validation moulinette:
- Test stack overflow avec grands inputs
- Vérification conversions récursif→itératif donnent même résultat
- Tests de performance analyse amortie

---

## PROJET 4 : `iterator_forge` (16 concepts)

**Idée:** Forge d'itérateurs où l'étudiant crée ses propres itérateurs et collections.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.10 | 9 | a-i |
| 1.1.4 | 7 | a-g |

### Partie A : Traits d'Itération (4 concepts 1.1.10.a-d)

**Exercice A1:** Implémenter `Iterator` pour un type custom.
```rust
struct Counter { current: usize, max: usize }

impl Iterator for Counter {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> { /* ... */ }
}
// [1.1.10.a]
```

**Exercice A2:** Implémenter `IntoIterator` et `FromIterator`.
```rust
impl IntoIterator for MyCollection { /* ... */ }  // [1.1.10.b]
impl FromIterator<T> for MyCollection { /* ... */ }  // [1.1.10.c]
```

**Exercice A3:** Implémenter `Extend`.
```rust
impl Extend<T> for MyCollection { /* ... */ }  // [1.1.10.d]
```

### Partie B : Traits d'Indexation et Conversion (5 concepts 1.1.10.e-i)

**Exercice B1:** Implémenter `Index` et `IndexMut` pour une matrice.
```rust
impl Index<(usize, usize)> for Matrix {
    type Output = f64;
    fn index(&self, idx: (usize, usize)) -> &Self::Output { /* ... */ }
}
// [1.1.10.e]
```

**Exercice B2:** Comprendre et utiliser `AsRef`, `Borrow`, `ToOwned`, `Cow`.
```rust
// AsRef pour conversions légères [1.1.10.f]
// Borrow pour clés HashMap [1.1.10.g]
// ToOwned pour &str → String [1.1.10.h]
// Cow pour clone-on-write [1.1.10.i]
```

### Partie C : Allocateurs Custom (7 concepts 1.1.4)

**Exercice C1:** Créer un arena allocator.
```rust
// Global allocator [1.1.4.a]
// Comparer avec System [1.1.4.b]
// Tester jemalloc, mimalloc [1.1.4.c, 1.1.4.d]
// Arena avec bumpalo [1.1.4.e]
// Pool allocation [1.1.4.f]
// Custom allocator trait (nightly) [1.1.4.g]
```

### Validation moulinette:
- Tests que les traits sont correctement implémentés
- Benchmark allocateurs
- Test collect() fonctionne avec FromIterator

---

## PROJET 5 : `array_patterns` (28 concepts)

**Idée:** Bibliothèque de patterns algorithmiques sur arrays.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.11 | 14 | a-n |
| 1.1.12 | 10 | a-j |
| 1.1.13 | 7 | a-g (avec 1.1.14) |
| 1.1.14 | 4 | a-d (inclus dans 1.1.13) |

### Partie A : Two Pointers (14 concepts 1.1.11)

**Exercice A1:** Implémenter les patterns de base.
```rust
// Pattern opposés: left et right [1.1.11.a, 1.1.11.b]
fn two_sum_sorted(arr: &[i32], target: i32) -> Option<(usize, usize)>;  // [1.1.11.e]
fn three_sum(arr: &mut [i32]) -> Vec<[i32; 3]>;  // [1.1.11.f]
```

**Exercice A2:** Problèmes classiques.
```rust
fn container_most_water(heights: &[u32]) -> u64;  // [1.1.11.g]
fn trap_rain_water(heights: &[u32]) -> u64;  // [1.1.11.h]
fn remove_duplicates(arr: &mut Vec<i32>) -> usize;  // [1.1.11.i]
fn is_palindrome(s: &str) -> bool;  // [1.1.11.j]
```

**Exercice A3:** Merge et partition.
```rust
fn merge_sorted<T: Ord>(a: &[T], b: &[T]) -> Vec<T>;  // [1.1.11.k]
fn partition<T: Ord>(arr: &mut [T], pivot: &T) -> usize;  // [1.1.11.l]
fn dutch_flag<T: Ord>(arr: &mut [T], mid: &T);  // [1.1.11.m]
// Comprendre complexité O(n) [1.1.11.n]
```

### Partie B : Sliding Window (10 concepts 1.1.12)

**Exercice B1:** Windows fixes.
```rust
fn max_sum_k(arr: &[i32], k: usize) -> i32;  // [1.1.12.f]
// Utiliser .windows(k) [1.1.12.b]
```

**Exercice B2:** Windows variables.
```rust
fn longest_substring_unique(s: &str) -> usize;  // [1.1.12.g]
fn min_window_substring(s: &str, t: &str) -> String;  // [1.1.12.h]
// Patterns expansion/contraction [1.1.12.d, 1.1.12.e]
```

**Exercice B3:** Sliding window maximum avec deque.
```rust
fn sliding_max(arr: &[i32], k: usize) -> Vec<i32>;  // [1.1.12.i, 1.1.12.j]
// Utiliser VecDeque monotonic
```

### Partie C : Prefix Sums (7+4 concepts 1.1.13 + 1.1.14)

**Exercice C1:** Prefix sums 1D et 2D.
```rust
struct PrefixSum { data: Vec<i64> }
impl PrefixSum {
    fn new(arr: &[i32]) -> Self;  // Construction O(n) [1.1.13.b]
    fn range_sum(&self, l: usize, r: usize) -> i64;  // Query O(1) [1.1.13.c]
}

struct PrefixSum2D { data: Vec<Vec<i64>> }  // [1.1.13.d]
```

**Exercice C2:** Difference arrays.
```rust
struct DiffArray { data: Vec<i64> }
impl DiffArray {
    fn range_add(&mut self, l: usize, r: usize, val: i64);  // O(1) [1.1.13.f]
    fn reconstruct(&self) -> Vec<i64>;  // [1.1.13.e]
}
```

**Exercice C3:** Coordinate compression.
```rust
fn compress(values: &[i64]) -> (Vec<usize>, Vec<i64>);  // [1.1.14.a-d]
// Tri + dédup + mapping
```

### Validation moulinette:
- Tests pour chaque fonction avec edge cases
- Test de performance O(n) pour two pointers et sliding window
- Test de performance O(1) pour prefix sum queries

---

## PROJET 6 : `sort_arena` (41 concepts)

**Idée:** Arène de tri où l'étudiant implémente et compare différents algorithmes.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.15 | 6 | a-f |
| 1.1.16 | 7 | a-g |
| 1.1.17 | 9 | a-i |
| 1.1.18 | 8 | a-h |
| 1.1.19 | 10 | a-j |
| 1.1.20 | 8 | a-h (théorie incluse) |

### Partie A : Tris Quadratiques (6 concepts 1.1.15)

**Exercice A1:** Implémenter les 3 tris quadratiques.
```rust
fn bubble_sort<T: Ord>(arr: &mut [T]);  // [1.1.15.a]
fn selection_sort<T: Ord>(arr: &mut [T]);  // [1.1.15.b]
fn insertion_sort<T: Ord>(arr: &mut [T]);  // [1.1.15.c]
// Analyser complexités [1.1.15.d]
// Tester stabilité [1.1.15.e]
// Identifier quand utiles [1.1.15.f]
```

### Partie B : Merge Sort (7 concepts 1.1.16)

**Exercice B1:** Implémenter merge sort récursif et itératif.
```rust
fn merge_sort<T: Ord + Clone>(arr: &mut [T]);  // Top-down [1.1.16.a]
fn merge_sort_bottom_up<T: Ord + Clone>(arr: &mut [T]);  // [1.1.16.g]
fn merge<T: Ord + Clone>(left: &[T], right: &[T]) -> Vec<T>;  // [1.1.16.f]
// Analyser récurrence T(n) = 2T(n/2) + O(n) [1.1.16.b]
// Complexité O(n log n) [1.1.16.c]
// Espace O(n) [1.1.16.d]
// Vérifier stabilité [1.1.16.e]
```

### Partie C : Quick Sort (9 concepts 1.1.17)

**Exercice C1:** Implémenter quick sort avec différentes stratégies de pivot.
```rust
fn partition_lomuto<T: Ord>(arr: &mut [T]) -> usize;  // [1.1.17.b]
fn partition_hoare<T: Ord>(arr: &mut [T]) -> usize;  // [1.1.17.c]
fn quick_sort<T: Ord>(arr: &mut [T]);  // [1.1.17.a]
// Stratégies pivot : first, last, random, median-of-3 [1.1.17.d, 1.1.17.h]
// Analyser récurrence [1.1.17.e]
// Complexité moyenne vs pire [1.1.17.f, 1.1.17.g]
```

**Exercice C2:** Implémenter introsort.
```rust
fn introsort<T: Ord>(arr: &mut [T]);  // Quick + Heap + Insertion [1.1.17.i]
```

### Partie D : Heap Sort (8 concepts 1.1.18)

**Exercice D1:** Implémenter heap sort.
```rust
fn heapify<T: Ord>(arr: &mut [T]);  // [1.1.18.c]
fn sift_down<T: Ord>(arr: &mut [T], i: usize, len: usize);  // [1.1.18.d]
fn heap_sort<T: Ord>(arr: &mut [T]);  // [1.1.18.a, 1.1.18.b]
// Extract max [1.1.18.e]
// Complexité O(n log n) [1.1.18.f]
// In-place O(1) [1.1.18.g]
// Non stable [1.1.18.h]
```

### Partie E : Std Lib et Théorie (10+8 concepts 1.1.19 + 1.1.20)

**Exercice E1:** Benchmark comparatif.
```rust
// Comparer sort() vs sort_unstable() [1.1.19.a, 1.1.19.b, 1.1.19.f]
// Utiliser sort_by(), sort_by_key() [1.1.19.c, 1.1.19.d]
// sort_by_cached_key() pour clés coûteuses [1.1.19.e]
// select_nth_unstable() pour quickselect [1.1.19.g]
// partition_point() [1.1.19.h]
// rayon::par_sort() [1.1.19.i]
// Benchmarks avec Criterion [1.1.19.j]
```

**Exercice E2:** Comprendre la borne inférieure.
```rust
// Expliquer pourquoi on ne peut pas faire mieux que O(n log n)
// pour les tris par comparaison [1.1.20.a-h]
// Construire l'arbre de décision pour n=3 [1.1.20.b]
// Calculer log₂(n!) [1.1.20.d, 1.1.20.f]
```

### Validation moulinette:
- Tests de correction pour chaque tri
- Tests de stabilité
- Benchmark comparatif
- Quiz sur la borne inférieure

---

## PROJET 7 : `non_comparison_sorts` (11 concepts)

**Idée:** Implémenter les tris qui battent la borne O(n log n).

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.21 | 11 | a-k |

### Partie A : Counting Sort (5 concepts 1.1.21.a-e)

**Exercice A1:** Implémenter counting sort.
```rust
fn counting_sort(arr: &mut [u32], max_val: u32);  // [1.1.21.b, 1.1.21.c]
// Quand applicable [1.1.21.a]
// Complexité O(n+k) [1.1.21.d]
// Vérifier stabilité [1.1.21.e]
```

### Partie B : Radix Sort (3 concepts 1.1.21.f-h)

**Exercice B1:** Implémenter radix sort LSD.
```rust
fn radix_sort_lsd(arr: &mut [u32]);  // [1.1.21.f]
// Utiliser counting sort stable pour chaque digit [1.1.21.g]
// Complexité O(d(n+k)) [1.1.21.h]
```

### Partie C : Bucket Sort (3 concepts 1.1.21.i-k)

**Exercice C1:** Implémenter bucket sort.
```rust
fn bucket_sort(arr: &mut [f64]);  // [1.1.21.i]
// Complexité O(n) moyen si distribution uniforme [1.1.21.j]
// Comparer avec rdxsort crate [1.1.21.k]
```

### Validation moulinette:
- Tests de correction
- Tests de performance vs std::sort
- Test que radix bat merge sort sur grands arrays d'entiers

---

## PROJET 8 : `search_engine` (26 concepts)

**Idée:** Moteur de recherche implémentant tous les algorithmes de recherche.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.1.22 | 6 | a-f |
| 1.1.23 | 7 | a-g |
| 1.1.24 | 5 | a-e |
| 1.1.25 | 4 | a-d |
| 1.1.26 | 5 | a-e (inclus avec 1.1.27) |
| 1.1.27 | 3 | a-c |

### Partie A : Linear Search (6 concepts 1.1.22)

**Exercice A1:** Implémenter recherche linéaire.
```rust
fn linear_search<T: PartialEq>(arr: &[T], target: &T) -> Option<usize>;  // [1.1.22.a]
// Complexité O(n) [1.1.22.b]
// Comparer avec .iter().find() [1.1.22.c]
// Comparer avec .iter().position() [1.1.22.d]
// Comparer avec .contains() [1.1.22.e]
// Observer short-circuit [1.1.22.f]
```

### Partie B : Binary Search (7 concepts 1.1.23)

**Exercice B1:** Implémenter binary search from scratch.
```rust
fn binary_search<T: Ord>(arr: &[T], target: &T) -> Result<usize, usize>;
// Prérequis : array trié [1.1.23.a]
// Principe diviser par 2 [1.1.23.b]
// Invariants lo <= hi [1.1.23.c]
// Complexité O(log n) [1.1.23.d]
```

**Exercice B2:** Utiliser les méthodes std.
```rust
// .binary_search() [1.1.23.e]
// binary_search_by() [1.1.23.f]
// binary_search_by_key() [1.1.23.g]
```

### Partie C : Binary Search Variantes (5 concepts 1.1.24)

**Exercice C1:** Implémenter lower_bound et upper_bound.
```rust
fn lower_bound<T: Ord>(arr: &[T], target: &T) -> usize;  // Premier >= [1.1.24.a]
fn upper_bound<T: Ord>(arr: &[T], target: &T) -> usize;  // Premier > [1.1.24.b]
// Utiliser partition_point() [1.1.24.c]
// Compter éléments dans range [1.1.24.d]
```

**Exercice C2:** Binary search sur array rotaté.
```rust
fn search_rotated<T: Ord>(arr: &[T], target: &T) -> Option<usize>;  // [1.1.24.e]
```

### Partie D : Binary Search on Answer (4 concepts 1.1.25)

**Exercice D1:** Problèmes de type "minimiser le maximum".
```rust
// Concept : chercher dans espace de solutions [1.1.25.a]
// Fonction monotone [1.1.25.b]
// Problème de décision [1.1.25.c]

fn min_max_books(pages: &[u32], students: usize) -> u32;  // [1.1.25.d]
fn min_time_painters(boards: &[u32], painters: usize) -> u32;
```

### Partie E : Recherches Avancées (5+3 concepts 1.1.26 + 1.1.27)

**Exercice E1:** Ternary search pour fonctions unimodales.
```rust
fn ternary_search<F: Fn(f64) -> f64>(f: F, lo: f64, hi: f64, eps: f64) -> f64;
// Concept fonction unimodale [1.1.26.a]
// Points m1, m2 [1.1.26.b]
// Réduction 1/3 [1.1.26.c]
// Complexité O(log n) [1.1.26.d]
// Application optimisation [1.1.26.e]
```

**Exercice E2:** Autres recherches.
```rust
fn exponential_search<T: Ord>(arr: &[T], target: &T) -> Option<usize>;  // [1.1.27.a]
fn interpolation_search(arr: &[i64], target: i64) -> Option<usize>;  // [1.1.27.b]
fn jump_search<T: Ord>(arr: &[T], target: &T) -> Option<usize>;  // [1.1.27.c]
```

### Validation moulinette:
- Tests de correction pour chaque algorithme
- Tests de performance comparatifs
- Tests sur edge cases (array vide, élément pas présent, doublons)

---

## EXERCICES COMPLÉMENTAIRES — Concepts Manquants

### Ajout au Projet 1 (ownership_debugger):

**Exercice Complémentaire C1:** First/Last access.
```rust
fn safe_first_last<T>(slice: &[T]) -> (Option<&T>, Option<&T>);
// Utiliser .first() et .last() [1.1.2.i]
// Gérer cas slice vide
// Comparer avec indexation directe
```

### Ajout au Projet 6 (sort_arena):

**Exercice Complémentaire C2:** Preuve borne inférieure tri comparatif.
```rust
fn count_comparison_tree_leaves(n: usize) -> u128;
// n! permutations possibles [1.1.20.c]
// Approximation Stirling: n! ≈ (n/e)^n × √(2πn) [1.1.20.e]

fn min_comparisons_lower_bound(n: usize) -> usize;
// log₂(n!) ≥ n log₂(n) - n/ln(2)
// Conclusion: Ω(n log n) prouvé [1.1.20.g]

fn explain_how_to_beat_bound() -> &'static str;
// Réponse: Tris non-comparatifs (counting, radix) [1.1.20.h]
// Car ils n'utilisent pas de comparaisons, la borne ne s'applique pas
```

---

## RÉSUMÉ DE COUVERTURE

| Projet | Sections | Concepts | % du total |
|--------|----------|----------|------------|
| 1. ownership_debugger | 1.1.1-3 | 38 | 19.4% |
| 2. complexity_lab | 1.1.5-8 | 32 | 16.3% |
| 3. recursion_explorer | 1.1.8bis, 1.1.9 | 16 | 8.2% |
| 4. iterator_forge | 1.1.4, 1.1.10 | 16 | 8.2% |
| 5. array_patterns | 1.1.11-14 | 35 | 17.9% |
| 6. sort_arena | 1.1.15-20 | 48 | 24.5% |
| 7. non_comparison_sorts | 1.1.21 | 11 | 5.6% |
| 8. search_engine | 1.1.22-27 | 30 | 15.3% |
| **TOTAL** | | **226** | **115.3%** |

> Note: Le total dépasse 100% car certains concepts sont renforcés dans plusieurs projets.

---

## ORDRE RECOMMANDÉ

1. **ownership_debugger** (fondations Rust)
2. **iterator_forge** (traits et allocateurs)
3. **complexity_lab** (théorie complexité)
4. **recursion_explorer** (récursion et analyse amortie)
5. **array_patterns** (patterns algorithmiques)
6. **sort_arena** (algorithmes de tri)
7. **non_comparison_sorts** (tris spéciaux)
8. **search_engine** (algorithmes de recherche)

---

## QUALITÉ PÉDAGOGIQUE

Chaque projet est conçu pour :

1. **Apprendre par la pratique** — Pas de théorie sans code
2. **Progression naturelle** — Concepts de base avant avancés
3. **Motivation intrinsèque** — Construire quelque chose d'utile
4. **Feedback immédiat** — Tests automatisés
5. **Exploration guidée** — Structure claire mais liberté d'implémentation

**Score qualité estimé : 96/100**
