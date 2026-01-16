# MODULE 1.1 - EXERCICES SUPPLÉMENTAIRES
## Couverture des 64 Concepts Manquants

Ces exercices complètent la couverture du Module 1.1 pour atteindre 100%.

---

## Exercice SUP-1: `quadratic_sorts_complete`
**Couvre: 1.1.15.b-f (5 concepts)**

### Concepts
- [1.1.15.b] Selection sort — Trouver minimum, échanger
- [1.1.15.c] Insertion sort — Insérer au bon endroit
- [1.1.15.d] Complexités — O(n²) pire, O(n) meilleur pour insertion
- [1.1.15.e] Stabilité — Insertion et Bubble sont stables
- [1.1.15.f] Quand utiles — Petits arrays, presque triés

### Rust
```rust
/// Selection Sort - O(n²) toujours, non stable
/// [1.1.15.b] Trouve le minimum et l'échange avec la position courante
pub fn selection_sort<T: Ord>(arr: &mut [T]) {
    let n = arr.len();
    for i in 0..n {
        let mut min_idx = i;
        for j in (i + 1)..n {
            if arr[j] < arr[min_idx] {
                min_idx = j;
            }
        }
        arr.swap(i, min_idx);
    }
}

/// Insertion Sort - O(n²) pire, O(n) meilleur, stable
/// [1.1.15.c] Insère chaque élément à sa position correcte
pub fn insertion_sort<T: Ord>(arr: &mut [T]) {
    for i in 1..arr.len() {
        let mut j = i;
        while j > 0 && arr[j - 1] > arr[j] {
            arr.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// [1.1.15.d] Analyse de complexité
pub fn complexity_analysis() {
    // Selection: Θ(n²) comparaisons toujours, O(n) swaps
    // Insertion: O(n²) pire (inversé), O(n) meilleur (trié)
    // Bubble: O(n²) pire, O(n) meilleur avec early exit
}

/// [1.1.15.e] Test de stabilité
pub fn test_stability() {
    #[derive(Clone, Debug)]
    struct Item { key: i32, order: usize }
    
    impl PartialEq for Item {
        fn eq(&self, other: &Self) -> bool { self.key == other.key }
    }
    impl Eq for Item {}
    impl PartialOrd for Item {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.key.cmp(&other.key))
        }
    }
    impl Ord for Item {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.key.cmp(&other.key)
        }
    }
    
    // Insertion sort préserve l'ordre relatif des éléments égaux
    let mut items = vec![
        Item { key: 3, order: 0 },
        Item { key: 1, order: 1 },
        Item { key: 3, order: 2 },
    ];
    insertion_sort(&mut items);
    // items[1].order < items[2].order (stable)
}

/// [1.1.15.f] Quand utiliser les tris quadratiques
pub fn when_to_use() -> &'static str {
    "
    Insertion sort est idéal pour:
    - Petits tableaux (n < 20-50)
    - Tableaux presque triés (O(n) dans ce cas)
    - Tri en ligne (données arrivent une par une)
    - Utilisé comme cas de base dans les tris hybrides (Timsort, Introsort)
    "
}
```

### Tests Moulinette
```
selection_sort [64,25,12,22,11] -> [11,12,22,25,64]
insertion_sort [64,25,12,22,11] -> [11,12,22,25,64]
insertion_sort [1,2,3,4,5] -> [1,2,3,4,5] (O(n) operations)
stability_test -> items with same key maintain original order
```

---

## Exercice SUP-2: `merge_sort_complete`
**Couvre: 1.1.16.b-g (6 concepts)**

### Concepts
- [1.1.16.b] Récurrence — T(n) = 2T(n/2) + O(n)
- [1.1.16.c] Complexité — O(n log n) garanti
- [1.1.16.d] Espace — O(n) auxiliaire
- [1.1.16.e] Stabilité — Oui
- [1.1.16.f] Merge function — Two pointers
- [1.1.16.g] Bottom-up — Version itérative

### Rust
```rust
/// [1.1.16.f] Merge function - fusionne deux sous-tableaux triés
fn merge<T: Ord + Clone>(arr: &mut [T], left: &[T], right: &[T]) {
    let mut i = 0;
    let mut j = 0;
    let mut k = 0;
    
    // Two pointers merge
    while i < left.len() && j < right.len() {
        if left[i] <= right[j] {  // <= pour stabilité [1.1.16.e]
            arr[k] = left[i].clone();
            i += 1;
        } else {
            arr[k] = right[j].clone();
            j += 1;
        }
        k += 1;
    }
    
    // Copier les éléments restants
    while i < left.len() {
        arr[k] = left[i].clone();
        i += 1;
        k += 1;
    }
    while j < right.len() {
        arr[k] = right[j].clone();
        j += 1;
        k += 1;
    }
}

/// Merge Sort récursif - O(n log n), O(n) espace [1.1.16.c, 1.1.16.d]
pub fn merge_sort<T: Ord + Clone>(arr: &mut [T]) {
    let n = arr.len();
    if n <= 1 {
        return;
    }
    
    let mid = n / 2;
    let left: Vec<T> = arr[..mid].to_vec();
    let right: Vec<T> = arr[mid..].to_vec();
    
    // T(n) = 2T(n/2) + O(n) [1.1.16.b]
    merge_sort(&mut arr[..mid]);
    merge_sort(&mut arr[mid..]);
    
    merge(arr, &left, &right);
}

/// [1.1.16.g] Bottom-up Merge Sort - version itérative
pub fn merge_sort_bottom_up<T: Ord + Clone>(arr: &mut [T]) {
    let n = arr.len();
    let mut aux = arr.to_vec();
    
    let mut width = 1;
    while width < n {
        let mut i = 0;
        while i < n {
            let left = i;
            let mid = (i + width).min(n);
            let right = (i + 2 * width).min(n);
            
            // Merge arr[left..mid] et arr[mid..right]
            merge_in_place(arr, &mut aux, left, mid, right);
            i += 2 * width;
        }
        width *= 2;
    }
}

fn merge_in_place<T: Ord + Clone>(arr: &mut [T], aux: &mut [T], left: usize, mid: usize, right: usize) {
    aux[left..right].clone_from_slice(&arr[left..right]);
    
    let mut i = left;
    let mut j = mid;
    
    for k in left..right {
        if i >= mid {
            arr[k] = aux[j].clone();
            j += 1;
        } else if j >= right {
            arr[k] = aux[i].clone();
            i += 1;
        } else if aux[i] <= aux[j] {
            arr[k] = aux[i].clone();
            i += 1;
        } else {
            arr[k] = aux[j].clone();
            j += 1;
        }
    }
}

/// Analyse de récurrence [1.1.16.b]
pub fn recurrence_analysis() -> &'static str {
    "
    T(n) = 2T(n/2) + O(n)
    Par Master Theorem: a=2, b=2, f(n)=n
    log_b(a) = 1, f(n) = Θ(n^1)
    Cas 2: T(n) = Θ(n log n)
    "
}
```

### Tests Moulinette
```
merge_sort [38,27,43,3,9,82,10] -> [3,9,10,27,38,43,82]
merge_sort_bottom_up [38,27,43,3,9,82,10] -> [3,9,10,27,38,43,82]
merge_stability -> stable sort verified
```

---

## Exercice SUP-3: `quick_sort_complete`
**Couvre: 1.1.17.b-i (8 concepts)**

### Concepts
- [1.1.17.b] Lomuto — Partition simple
- [1.1.17.c] Hoare — Partition efficace
- [1.1.17.d] Pivot choice — Premier, dernier, médian, random
- [1.1.17.e] Récurrence — T(n) = T(k) + T(n-k-1) + O(n)
- [1.1.17.f] Complexité moyenne — O(n log n)
- [1.1.17.g] Pire cas — O(n²) avec mauvais pivot
- [1.1.17.h] Médian of 3 — Améliorer pivot
- [1.1.17.i] Introsort — Quick + Heap + Insertion

### Rust
```rust
use rand::Rng;

/// [1.1.17.b] Lomuto partition scheme
/// Pivot à la fin, partition autour du pivot
pub fn lomuto_partition<T: Ord>(arr: &mut [T], lo: usize, hi: usize) -> usize {
    let pivot_idx = hi;
    let mut i = lo;
    
    for j in lo..hi {
        if arr[j] <= arr[pivot_idx] {
            arr.swap(i, j);
            i += 1;
        }
    }
    arr.swap(i, hi);
    i
}

/// [1.1.17.c] Hoare partition scheme - plus efficace
/// Deux pointeurs qui se rapprochent
pub fn hoare_partition<T: Ord>(arr: &mut [T], lo: usize, hi: usize) -> usize {
    let pivot = lo;  // Pivot au début
    let mut i = lo.wrapping_sub(1);
    let mut j = hi + 1;
    
    loop {
        loop {
            i = i.wrapping_add(1);
            if arr[i] >= arr[pivot] { break; }
        }
        loop {
            j -= 1;
            if arr[j] <= arr[pivot] { break; }
        }
        if i >= j {
            return j;
        }
        arr.swap(i, j);
    }
}

/// [1.1.17.d] Stratégies de choix du pivot
pub enum PivotStrategy {
    First,
    Last,
    Random,
    MedianOf3,
}

/// [1.1.17.h] Median of 3 - choisit la médiane de first, middle, last
pub fn median_of_three<T: Ord>(arr: &mut [T], lo: usize, hi: usize) -> usize {
    let mid = lo + (hi - lo) / 2;
    
    if arr[lo] > arr[mid] { arr.swap(lo, mid); }
    if arr[lo] > arr[hi] { arr.swap(lo, hi); }
    if arr[mid] > arr[hi] { arr.swap(mid, hi); }
    
    // Maintenant arr[lo] <= arr[mid] <= arr[hi]
    arr.swap(mid, hi - 1);  // Place median avant le dernier
    hi - 1
}

/// Quick Sort avec Lomuto
pub fn quick_sort_lomuto<T: Ord>(arr: &mut [T]) {
    fn qs<T: Ord>(arr: &mut [T], lo: usize, hi: usize) {
        if lo < hi {
            let p = lomuto_partition(arr, lo, hi);
            if p > 0 { qs(arr, lo, p - 1); }
            qs(arr, p + 1, hi);
        }
    }
    if !arr.is_empty() {
        let hi = arr.len() - 1;
        qs(arr, 0, hi);
    }
}

/// [1.1.17.i] Introsort - hybride Quick + Heap + Insertion
pub fn introsort<T: Ord>(arr: &mut [T]) {
    let max_depth = 2 * (arr.len() as f64).log2() as usize;
    introsort_impl(arr, max_depth);
}

fn introsort_impl<T: Ord>(arr: &mut [T], depth_limit: usize) {
    let n = arr.len();
    
    // Cas de base: insertion sort pour petits tableaux
    if n <= 16 {
        insertion_sort(arr);
        return;
    }
    
    // [1.1.17.g] Éviter le pire cas O(n²) en passant à heapsort
    if depth_limit == 0 {
        heap_sort(arr);
        return;
    }
    
    // Quick sort avec median of 3
    if n > 1 {
        let pivot = median_of_three(arr, 0, n - 1);
        let p = lomuto_partition(arr, 0, n - 1);
        
        introsort_impl(&mut arr[..p], depth_limit - 1);
        if p + 1 < n {
            introsort_impl(&mut arr[p + 1..], depth_limit - 1);
        }
    }
}

fn insertion_sort<T: Ord>(arr: &mut [T]) {
    for i in 1..arr.len() {
        let mut j = i;
        while j > 0 && arr[j - 1] > arr[j] {
            arr.swap(j - 1, j);
            j -= 1;
        }
    }
}

fn heap_sort<T: Ord>(arr: &mut [T]) {
    // Build max heap
    let n = arr.len();
    for i in (0..n / 2).rev() {
        heapify(arr, n, i);
    }
    // Extract elements
    for i in (1..n).rev() {
        arr.swap(0, i);
        heapify(arr, i, 0);
    }
}

fn heapify<T: Ord>(arr: &mut [T], n: usize, i: usize) {
    let mut largest = i;
    let left = 2 * i + 1;
    let right = 2 * i + 2;
    
    if left < n && arr[left] > arr[largest] { largest = left; }
    if right < n && arr[right] > arr[largest] { largest = right; }
    
    if largest != i {
        arr.swap(i, largest);
        heapify(arr, n, largest);
    }
}

/// [1.1.17.e, 1.1.17.f, 1.1.17.g] Analyse de complexité
pub fn complexity_analysis() -> &'static str {
    "
    Récurrence: T(n) = T(k) + T(n-k-1) + O(n)
    
    Cas moyen (pivot aléatoire): O(n log n)
    - Partition équilibrée en moyenne
    
    Pire cas: O(n²)
    - Tableau déjà trié + pivot = premier élément
    - Chaque partition ne réduit que de 1
    
    Introsort évite le pire cas en:
    - Passant à heapsort après log(n) niveaux
    - Utilisant insertion sort pour n < 16
    "
}
```

### Tests Moulinette
```
quick_sort_lomuto [10,7,8,9,1,5] -> [1,5,7,8,9,10]
quick_sort_hoare [10,7,8,9,1,5] -> [1,5,7,8,9,10]
introsort [10,7,8,9,1,5] -> [1,5,7,8,9,10]
worst_case_avoided [1,2,3,4,5,6,7,8,9,10] -> introsort O(n log n)
```

---

## Exercice SUP-4: `heap_sort_complete`
**Couvre: 1.1.18.b-h (7 concepts)**

### Concepts
- [1.1.18.b] Max-heap property — Parent ≥ enfants
- [1.1.18.c] Heapify — Construire le heap
- [1.1.18.d] Sift down — Restaurer propriété
- [1.1.18.e] Extract max — Retirer racine
- [1.1.18.f] Complexité — O(n log n)
- [1.1.18.g] In-place — O(1) espace auxiliaire
- [1.1.18.h] Non stable — Ordre relatif non préservé

### Rust
```rust
/// Binary Heap structure représentée dans un array
/// [1.1.18.b] Max-heap: arr[parent] >= arr[children]
/// parent(i) = (i-1)/2, left(i) = 2i+1, right(i) = 2i+2

/// [1.1.18.d] Sift down - restaure la propriété max-heap
fn sift_down<T: Ord>(arr: &mut [T], n: usize, mut i: usize) {
    loop {
        let mut largest = i;
        let left = 2 * i + 1;
        let right = 2 * i + 2;
        
        // [1.1.18.b] Vérifier la propriété max-heap
        if left < n && arr[left] > arr[largest] {
            largest = left;
        }
        if right < n && arr[right] > arr[largest] {
            largest = right;
        }
        
        if largest == i {
            break;
        }
        
        arr.swap(i, largest);
        i = largest;
    }
}

/// [1.1.18.c] Heapify - construit un max-heap en O(n)
fn build_max_heap<T: Ord>(arr: &mut [T]) {
    let n = arr.len();
    // Partir du dernier nœud non-feuille
    for i in (0..n / 2).rev() {
        sift_down(arr, n, i);
    }
}

/// [1.1.18.e] Extract max - retire et retourne le maximum
fn extract_max<T: Ord + Clone>(arr: &mut Vec<T>) -> Option<T> {
    if arr.is_empty() {
        return None;
    }
    
    let max = arr[0].clone();
    let last_idx = arr.len() - 1;
    arr.swap(0, last_idx);
    arr.pop();
    
    if !arr.is_empty() {
        sift_down(arr, arr.len(), 0);
    }
    
    Some(max)
}

/// Heap Sort - [1.1.18.f] O(n log n), [1.1.18.g] O(1) espace
pub fn heap_sort<T: Ord>(arr: &mut [T]) {
    let n = arr.len();
    
    // Phase 1: Build max-heap O(n)
    build_max_heap(arr);
    
    // Phase 2: Extract elements O(n log n)
    for i in (1..n).rev() {
        // Le max est toujours à arr[0]
        arr.swap(0, i);
        // Restaurer le heap pour arr[0..i]
        sift_down(arr, i, 0);
    }
}

/// [1.1.18.h] Démonstration que heap sort n'est pas stable
pub fn stability_demo() {
    #[derive(Clone, Debug)]
    struct Item { key: i32, order: usize }
    
    impl PartialEq for Item {
        fn eq(&self, other: &Self) -> bool { self.key == other.key }
    }
    impl Eq for Item {}
    impl PartialOrd for Item {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Item {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.key.cmp(&other.key)
        }
    }
    
    let mut items = vec![
        Item { key: 3, order: 0 },
        Item { key: 1, order: 1 },
        Item { key: 3, order: 2 },  // Même clé, ordre différent
    ];
    
    heap_sort(&mut items);
    // L'ordre relatif des éléments avec key=3 peut être inversé
    // items[1].order pourrait être > items[2].order (non stable)
}

/// Analyse de complexité [1.1.18.f]
pub fn complexity_analysis() -> &'static str {
    "
    Build heap: O(n) - chaque sift_down est O(log n) mais somme = O(n)
    N extractions: O(n log n)
    Total: O(n log n)
    
    Espace: O(1) in-place [1.1.18.g]
    Stabilité: Non [1.1.18.h]
    
    Avantages:
    - Garanti O(n log n) même pire cas
    - In-place
    
    Inconvénients:
    - Cache-unfriendly (accès non-séquentiels)
    - Non stable
    "
}
```

### Tests Moulinette
```
heap_sort [12,11,13,5,6,7] -> [5,6,7,11,12,13]
build_heap [4,10,3,5,1] -> max_heap_property_verified
extract_max [16,14,10,8,7,9,3] -> 16, remaining is valid heap
stability_test -> demonstrates non-stable behavior
```

---

## Exercice SUP-5: `std_sorts_complete`
**Couvre: 1.1.19.b-h (7 concepts)**

### Concepts
- [1.1.19.b] `sort_unstable()` — Unstable, pattern-defeating quicksort
- [1.1.19.c] `sort_by()` — Avec comparateur custom
- [1.1.19.d] `sort_by_key()` — Par clé extraite
- [1.1.19.e] `sort_by_cached_key()` — Cache les clés (coûteuses)
- [1.1.19.f] Performance — `sort_unstable` souvent 2x plus rapide
- [1.1.19.g] `select_nth_unstable()` — Quickselect, O(n) moyen
- [1.1.19.h] `partition_point()` — Binary search idiomatique

### Rust
```rust
use std::cmp::Ordering;

pub fn demonstrate_std_sorts() {
    // [1.1.19.b] sort_unstable - plus rapide, non stable
    let mut v1 = vec![5, 4, 1, 3, 2];
    v1.sort_unstable();  // Pattern-defeating quicksort
    assert_eq!(v1, [1, 2, 3, 4, 5]);
    
    // [1.1.19.c] sort_by - comparateur custom
    let mut v2 = vec![5, 4, 1, 3, 2];
    v2.sort_by(|a, b| b.cmp(a));  // Tri décroissant
    assert_eq!(v2, [5, 4, 3, 2, 1]);
    
    // [1.1.19.d] sort_by_key - par clé extraite
    let mut words = vec!["banana", "apple", "cherry"];
    words.sort_by_key(|s| s.len());
    assert_eq!(words, ["apple", "banana", "cherry"]);
    
    // [1.1.19.e] sort_by_cached_key - cache les clés coûteuses
    let mut data = vec!["Hello World", "Rust", "Programming"];
    data.sort_by_cached_key(|s| {
        // Simulation d'une clé coûteuse à calculer
        expensive_key_computation(s)
    });
}

fn expensive_key_computation(s: &str) -> usize {
    // Simuler un calcul coûteux
    s.chars().map(|c| c as usize).sum()
}

/// [1.1.19.f] Comparaison de performance
pub fn performance_comparison() {
    use std::time::Instant;
    
    let mut v1: Vec<i32> = (0..100000).rev().collect();
    let mut v2 = v1.clone();
    
    let start = Instant::now();
    v1.sort();  // Stable, merge sort variant
    let stable_time = start.elapsed();
    
    let start = Instant::now();
    v2.sort_unstable();  // Unstable, quicksort variant
    let unstable_time = start.elapsed();
    
    println!("sort(): {:?}", stable_time);
    println!("sort_unstable(): {:?}", unstable_time);
    // sort_unstable est généralement 2x plus rapide
}

/// [1.1.19.g] select_nth_unstable - trouve le n-ième élément en O(n)
pub fn quickselect_demo() {
    let mut v = vec![5, 3, 8, 1, 9, 2, 7, 4, 6];
    
    // Trouve la médiane (4ème élément dans un tableau de 9)
    let (_, median, _) = v.select_nth_unstable(4);
    println!("Médiane: {}", median);  // 5
    
    // Après select_nth_unstable:
    // - Tous les éléments avant l'index 4 sont <= v[4]
    // - Tous les éléments après l'index 4 sont >= v[4]
    
    // Trouver les k plus petits éléments
    let k = 3;
    let mut v2 = vec![5, 3, 8, 1, 9, 2, 7, 4, 6];
    v2.select_nth_unstable(k);
    let smallest_k = &v2[..k];  // Les k plus petits (non triés)
}

/// [1.1.19.h] partition_point - binary search idiomatique
pub fn partition_point_demo() {
    let v = [1, 2, 3, 3, 5, 6, 7];
    
    // Trouve le premier index où le prédicat devient faux
    let i = v.partition_point(|&x| x < 5);
    assert_eq!(i, 4);  // v[4] = 5, premier élément >= 5
    
    // Équivalent à binary_search mais plus flexible
    // Utile pour lower_bound / upper_bound
    
    // Lower bound: premier élément >= target
    let lower = v.partition_point(|&x| x < 3);
    assert_eq!(lower, 2);  // v[2] = 3
    
    // Upper bound: premier élément > target
    let upper = v.partition_point(|&x| x <= 3);
    assert_eq!(upper, 4);  // v[4] = 5
    
    // Nombre d'éléments == target
    let count = upper - lower;
    assert_eq!(count, 2);  // Deux 3 dans le tableau
}

/// Comparateur custom avancé
pub fn custom_comparator_examples() {
    #[derive(Debug, Clone)]
    struct Person {
        name: String,
        age: u32,
        score: f64,
    }
    
    let mut people = vec![
        Person { name: "Alice".into(), age: 30, score: 85.5 },
        Person { name: "Bob".into(), age: 25, score: 90.0 },
        Person { name: "Charlie".into(), age: 30, score: 80.0 },
    ];
    
    // Tri par âge, puis par score décroissant
    people.sort_by(|a, b| {
        match a.age.cmp(&b.age) {
            Ordering::Equal => b.score.partial_cmp(&a.score).unwrap(),
            other => other,
        }
    });
}
```

### Tests Moulinette
```
sort_unstable [5,4,1,3,2] -> [1,2,3,4,5]
sort_by_key ["banana","apple","cherry"] by_len -> ["apple","banana","cherry"]
select_nth_unstable [5,3,8,1,9] 2 -> median = 5
partition_point [1,2,3,3,5,6] (<5) -> 4
```

---

## Exercice SUP-6: `lower_bound_proof`
**Couvre: 1.1.20.b-h (7 concepts)**

### Concepts
- [1.1.20.b] Arbre de décision — Représentation comparaisons
- [1.1.20.c] Feuilles — n! permutations
- [1.1.20.d] Hauteur minimale — log₂(n!)
- [1.1.20.e] Stirling — n! ≈ (n/e)^n × √(2πn)
- [1.1.20.f] log₂(n!) — = Ω(n log n)
- [1.1.20.g] Conclusion — Borne inférieure prouvée
- [1.1.20.h] Implications — Comment battre cette borne?

### Rust
```rust
use std::f64::consts::{E, PI};

/// [1.1.20.b] Modèle de l'arbre de décision
/// Chaque nœud interne = une comparaison a[i] vs a[j]
/// Chaque feuille = une permutation résultante
pub fn decision_tree_model() -> &'static str {
    "
    Arbre de décision pour tri comparatif:
    - Chaque nœud interne: comparaison a[i] <= a[j]?
    - Branche gauche: oui (a[i] <= a[j])
    - Branche droite: non (a[i] > a[j])
    - Chaque feuille: une permutation unique
    "
}

/// [1.1.20.c] Nombre de feuilles nécessaires
pub fn leaf_count(n: usize) -> u128 {
    // n! permutations possibles = n! feuilles nécessaires
    (1..=n as u128).product()
}

/// [1.1.20.d] Hauteur minimale de l'arbre
pub fn minimum_height(n: usize) -> f64 {
    // Un arbre binaire de hauteur h a au plus 2^h feuilles
    // Donc: 2^h >= n!
    // h >= log₂(n!)
    let n_factorial = factorial(n);
    (n_factorial as f64).log2()
}

fn factorial(n: usize) -> u128 {
    (1..=n as u128).product()
}

/// [1.1.20.e] Approximation de Stirling
pub fn stirling_approximation(n: usize) -> f64 {
    // n! ≈ √(2πn) × (n/e)^n
    let n = n as f64;
    (2.0 * PI * n).sqrt() * (n / E).powf(n)
}

/// [1.1.20.f] Calcul de log₂(n!)
pub fn log2_factorial(n: usize) -> f64 {
    // log₂(n!) = log₂(1) + log₂(2) + ... + log₂(n)
    //          = Σ log₂(i) pour i de 1 à n
    
    // Approximation: log₂(n!) ≈ n log₂(n) - n/ln(2) + O(log n)
    // Par Stirling: log₂(n!) ≈ n log₂(n) - n log₂(e) + 0.5 log₂(2πn)
    
    let n = n as f64;
    n * n.log2() - n * E.log2() + 0.5 * (2.0 * PI * n).log2()
}

/// [1.1.20.f] Preuve que log₂(n!) = Ω(n log n)
pub fn omega_n_log_n_proof() -> &'static str {
    "
    log₂(n!) = log₂(1 × 2 × ... × n)
             = log₂(1) + log₂(2) + ... + log₂(n)
             
    Borne inférieure:
    log₂(n!) >= log₂((n/2)^(n/2))  (les n/2 plus grands termes)
             = (n/2) × log₂(n/2)
             = (n/2) × (log₂(n) - 1)
             = Ω(n log n)
             
    Donc: h >= log₂(n!) = Ω(n log n)
    "
}

/// [1.1.20.g] Conclusion du théorème
pub fn theorem_conclusion() -> &'static str {
    "
    THÉORÈME: Tout algorithme de tri basé sur les comparaisons
    nécessite Ω(n log n) comparaisons dans le pire cas.
    
    PREUVE:
    1. L'algorithme peut être modélisé par un arbre de décision
    2. L'arbre doit avoir au moins n! feuilles (une par permutation)
    3. Un arbre binaire avec L feuilles a hauteur >= log₂(L)
    4. Donc hauteur >= log₂(n!) = Ω(n log n)
    5. La hauteur = nombre de comparaisons dans le pire cas
    
    QED
    "
}

/// [1.1.20.h] Implications et comment "battre" la borne
pub fn implications() -> &'static str {
    "
    IMPLICATIONS:
    
    1. Merge Sort, Heap Sort, et les meilleurs Quick Sort
       sont OPTIMAUX asymptotiquement: Θ(n log n)
    
    2. Pour faire mieux que Ω(n log n), on doit:
       - NE PAS utiliser de comparaisons
       - Exploiter des propriétés des données
    
    TRIS NON-COMPARATIFS (peuvent être O(n)):
    - Counting Sort: O(n + k) si valeurs dans [0, k]
    - Radix Sort: O(d(n + k)) pour d digits
    - Bucket Sort: O(n) si distribution uniforme
    
    Ces algorithmes utilisent les VALEURS directement,
    pas seulement les résultats de comparaisons.
    "
}

/// Démonstration numérique
pub fn numerical_demo() {
    for n in [10, 100, 1000, 10000] {
        let exact = log2_factorial(n);
        let n_log_n = (n as f64) * (n as f64).log2();
        let ratio = exact / n_log_n;
        
        println!("n={}: log₂(n!)={:.1}, n·log₂(n)={:.1}, ratio={:.3}",
                 n, exact, n_log_n, ratio);
    }
    // Le ratio tend vers 1 quand n augmente
}
```

### Tests Moulinette
```
factorial 5 -> 120
minimum_height 5 -> ~6.9 (log₂(120))
stirling 10 -> ~3628800 (close to 10!)
log2_factorial 1000 -> ~8530 (≈ n log n)
```

---

## Exercice SUP-7: `non_comparison_sorts_complete`
**Couvre: 1.1.21.b-i (8 concepts)**

### Concepts
- [1.1.21.b] Counting Sort — Valeurs comme indices
- [1.1.21.c] Counting implémentation — `vec![0; max+1]` compteurs
- [1.1.21.d] Counting complexité — O(n + k)
- [1.1.21.e] Counting stabilité — Oui
- [1.1.21.f] Radix Sort LSD — Digit par digit
- [1.1.21.g] Radix avec counting — Stable digit sort
- [1.1.21.h] Radix complexité — O(d(n + k))
- [1.1.21.i] Bucket Sort — Distribution dans buckets

### Rust
```rust
/// [1.1.21.b, 1.1.21.c] Counting Sort
/// Utilise les valeurs comme indices dans un tableau de compteurs
pub fn counting_sort(arr: &mut [usize], max_val: usize) {
    // [1.1.21.c] Tableau de compteurs
    let mut count = vec![0usize; max_val + 1];
    
    // Compter les occurrences
    for &x in arr.iter() {
        count[x] += 1;
    }
    
    // Reconstruire le tableau trié
    let mut idx = 0;
    for (val, &cnt) in count.iter().enumerate() {
        for _ in 0..cnt {
            arr[idx] = val;
            idx += 1;
        }
    }
}

/// [1.1.21.e] Counting Sort stable (préserve l'ordre des éléments égaux)
pub fn counting_sort_stable<T: Clone>(arr: &[T], key: impl Fn(&T) -> usize, max_key: usize) -> Vec<T> {
    let n = arr.len();
    
    // Compter
    let mut count = vec![0usize; max_key + 1];
    for item in arr {
        count[key(item)] += 1;
    }
    
    // Préfixes cumulés (positions de départ)
    for i in 1..=max_key {
        count[i] += count[i - 1];
    }
    
    // Placer les éléments (parcours inverse pour stabilité)
    let mut output = vec![arr[0].clone(); n];
    for item in arr.iter().rev() {
        let k = key(item);
        count[k] -= 1;
        output[count[k]] = item.clone();
    }
    
    output
}

/// [1.1.21.d] Complexité de Counting Sort
pub fn counting_sort_complexity() -> &'static str {
    "
    Temps: O(n + k)
    - n: taille du tableau
    - k: plage des valeurs (max - min + 1)
    
    Espace: O(k) pour le tableau de compteurs
    
    Efficace quand k = O(n)
    Inefficace quand k >> n
    "
}

/// [1.1.21.f, 1.1.21.g] Radix Sort LSD (Least Significant Digit)
pub fn radix_sort_lsd(arr: &mut [u32]) {
    let max_val = *arr.iter().max().unwrap_or(&0);
    let mut exp = 1u32;
    
    // Traiter chaque digit de droite à gauche
    while max_val / exp > 0 {
        // [1.1.21.g] Utiliser counting sort stable pour chaque digit
        counting_sort_by_digit(arr, exp);
        exp *= 10;
    }
}

fn counting_sort_by_digit(arr: &mut [u32], exp: u32) {
    let n = arr.len();
    let mut output = vec![0u32; n];
    let mut count = [0usize; 10];
    
    // Compter les digits
    for &x in arr.iter() {
        let digit = ((x / exp) % 10) as usize;
        count[digit] += 1;
    }
    
    // Préfixes cumulés
    for i in 1..10 {
        count[i] += count[i - 1];
    }
    
    // Placer (parcours inverse pour stabilité)
    for &x in arr.iter().rev() {
        let digit = ((x / exp) % 10) as usize;
        count[digit] -= 1;
        output[count[digit]] = x;
    }
    
    arr.copy_from_slice(&output);
}

/// [1.1.21.h] Complexité de Radix Sort
pub fn radix_sort_complexity() -> &'static str {
    "
    Temps: O(d × (n + k))
    - d: nombre de digits
    - n: taille du tableau
    - k: base (10 pour décimal, 256 pour bytes)
    
    Pour des entiers 32-bit en base 256:
    - d = 4 (4 bytes)
    - k = 256
    - O(4 × (n + 256)) = O(n)
    
    Linéaire en pratique pour des entiers bornés!
    "
}

/// [1.1.21.i] Bucket Sort
pub fn bucket_sort(arr: &mut [f64]) {
    let n = arr.len();
    if n == 0 { return; }
    
    // Trouver min et max
    let min = arr.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = arr.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;
    
    if range == 0.0 { return; }  // Tous égaux
    
    // Créer n buckets
    let mut buckets: Vec<Vec<f64>> = vec![Vec::new(); n];
    
    // Distribuer dans les buckets
    for &x in arr.iter() {
        let idx = ((x - min) / range * (n - 1) as f64) as usize;
        buckets[idx.min(n - 1)].push(x);
    }
    
    // Trier chaque bucket (insertion sort car petits)
    for bucket in &mut buckets {
        bucket.sort_by(|a, b| a.partial_cmp(b).unwrap());
    }
    
    // Concaténer
    let mut idx = 0;
    for bucket in buckets {
        for x in bucket {
            arr[idx] = x;
            idx += 1;
        }
    }
}

/// Bucket Sort complexité
pub fn bucket_sort_complexity() -> &'static str {
    "
    Temps moyen: O(n) si distribution uniforme
    Temps pire: O(n²) si tous dans le même bucket
    
    Espace: O(n)
    
    Hypothèse clé: les éléments sont uniformément distribués
    "
}
```

### Tests Moulinette
```
counting_sort [4,2,2,8,3,3,1] 8 -> [1,2,2,3,3,4,8]
radix_sort [170,45,75,90,802,24,2,66] -> [2,24,45,66,75,90,170,802]
bucket_sort [0.42,0.32,0.33,0.52,0.37,0.47,0.51] -> sorted
```

---

## Exercice SUP-8: `linear_search_complete`
**Couvre: 1.1.22.b-f (5 concepts)**

### Concepts
- [1.1.22.b] Complexité — O(n) temps, O(1) espace
- [1.1.22.c] `.iter().find()` — Idiomatique Rust
- [1.1.22.d] `.iter().position()` — Retourner index
- [1.1.22.e] `.contains()` — Existence
- [1.1.22.f] Short-circuit — Arrêt dès trouvé

### Rust
```rust
/// [1.1.22.b] Complexité de la recherche linéaire
pub fn linear_search_complexity() -> &'static str {
    "
    Temps: O(n) pire cas et moyen
    - Parcourt tous les éléments dans le pire cas
    - En moyenne n/2 comparaisons
    
    Espace: O(1)
    - Pas de mémoire supplémentaire
    
    Avantages:
    - Fonctionne sur des données non triées
    - Simple à implémenter
    - Optimal pour les recherches uniques sur petits tableaux
    "
}

/// [1.1.22.c] iter().find() - trouve le premier élément satisfaisant le prédicat
pub fn find_examples() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // Trouver le premier pair
    let first_even = numbers.iter().find(|&&x| x % 2 == 0);
    assert_eq!(first_even, Some(&2));
    
    // Trouver un élément spécifique
    let found = numbers.iter().find(|&&x| x == 3);
    assert_eq!(found, Some(&3));
    
    // Élément non trouvé
    let not_found = numbers.iter().find(|&&x| x == 10);
    assert_eq!(not_found, None);
    
    // Avec des structs
    #[derive(Debug, PartialEq)]
    struct Person { name: String, age: u32 }
    
    let people = vec![
        Person { name: "Alice".into(), age: 30 },
        Person { name: "Bob".into(), age: 25 },
    ];
    
    let adult = people.iter().find(|p| p.age >= 30);
    assert_eq!(adult.map(|p| &p.name), Some(&"Alice".to_string()));
}

/// [1.1.22.d] iter().position() - retourne l'index du premier élément trouvé
pub fn position_examples() {
    let numbers = vec![10, 20, 30, 40, 50];
    
    // Trouver l'index de 30
    let idx = numbers.iter().position(|&x| x == 30);
    assert_eq!(idx, Some(2));
    
    // Index du premier élément > 25
    let idx = numbers.iter().position(|&x| x > 25);
    assert_eq!(idx, Some(2));  // 30 est à l'index 2
    
    // Élément non trouvé
    let idx = numbers.iter().position(|&x| x == 100);
    assert_eq!(idx, None);
    
    // rposition() pour chercher depuis la fin
    let numbers = vec![1, 2, 3, 2, 1];
    let last_two = numbers.iter().rposition(|&x| x == 2);
    assert_eq!(last_two, Some(3));  // Dernier 2 à l'index 3
}

/// [1.1.22.e] contains() - vérifie l'existence
pub fn contains_examples() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // Vérifier si un élément existe
    assert!(numbers.contains(&3));
    assert!(!numbers.contains(&10));
    
    // Pour les slices
    let slice: &[i32] = &[1, 2, 3];
    assert!(slice.contains(&2));
    
    // Note: contains() utilise PartialEq, pas un prédicat
    // Pour un prédicat, utiliser any()
    let has_even = numbers.iter().any(|&x| x % 2 == 0);
    assert!(has_even);
}

/// [1.1.22.f] Short-circuit - arrêt dès que trouvé
pub fn short_circuit_demo() {
    let numbers = vec![1, 2, 3, 4, 5];
    let mut comparisons = 0;
    
    // find() s'arrête dès qu'il trouve
    let _ = numbers.iter().find(|&&x| {
        comparisons += 1;
        x == 3
    });
    
    assert_eq!(comparisons, 3);  // Seulement 3 comparaisons, pas 5
    
    // Pareil pour position(), any(), all(), contains()
    
    // any() - short-circuit sur true
    comparisons = 0;
    let _ = numbers.iter().any(|&x| {
        comparisons += 1;
        x == 2
    });
    assert_eq!(comparisons, 2);
    
    // all() - short-circuit sur false
    comparisons = 0;
    let _ = numbers.iter().all(|&x| {
        comparisons += 1;
        x < 3
    });
    assert_eq!(comparisons, 3);  // S'arrête à 3 (qui n'est pas < 3)
}

/// Comparaison avec binary_search
pub fn linear_vs_binary() {
    let sorted = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    
    // Linear search O(n) - fonctionne sur non-trié
    let _ = sorted.iter().position(|&x| x == 7);
    
    // Binary search O(log n) - nécessite trié
    let _ = sorted.binary_search(&7);
    
    // Pour n petit (< 100), linear search peut être plus rapide
    // à cause de la meilleure localité cache
}
```

### Tests Moulinette
```
find [1,2,3,4,5] (==3) -> Some(&3)
position [10,20,30] (==20) -> Some(1)
contains [1,2,3] 2 -> true
short_circuit [1,2,3,4,5] find(==2) -> 2 comparisons
```

---

## Exercice SUP-9: `binary_search_variants`
**Couvre: 1.1.24.b-e (4 concepts)**

### Concepts
- [1.1.24.b] Upper bound — Premier > x
- [1.1.24.c] `partition_point()` — Idiomatique Rust
- [1.1.24.d] Range count — upper - lower
- [1.1.24.e] Rotated array — Modification pour rotation

### Rust
```rust
/// [1.1.24.b] Upper bound - premier élément strictement supérieur
pub fn upper_bound<T: Ord>(arr: &[T], target: &T) -> usize {
    arr.partition_point(|x| x <= target)
}

/// Lower bound - premier élément >= target
pub fn lower_bound<T: Ord>(arr: &[T], target: &T) -> usize {
    arr.partition_point(|x| x < target)
}

/// [1.1.24.c] partition_point - idiomatique Rust
pub fn partition_point_examples() {
    let arr = [1, 2, 3, 3, 3, 5, 6, 7];
    
    // Lower bound: premier >= 3
    let lower = arr.partition_point(|&x| x < 3);
    assert_eq!(lower, 2);  // arr[2] = 3
    
    // Upper bound: premier > 3
    let upper = arr.partition_point(|&x| x <= 3);
    assert_eq!(upper, 5);  // arr[5] = 5
    
    // [1.1.24.d] Range count: nombre d'éléments == target
    let count = upper - lower;
    assert_eq!(count, 3);  // Trois 3 dans le tableau
    
    // Équivalent de equal_range en C++
    fn equal_range<T: Ord>(arr: &[T], target: &T) -> (usize, usize) {
        (lower_bound(arr, target), upper_bound(arr, target))
    }
    
    let (lo, hi) = equal_range(&arr, &3);
    assert_eq!((lo, hi), (2, 5));
}

/// [1.1.24.d] Range count avec partition_point
pub fn count_occurrences<T: Ord>(arr: &[T], target: &T) -> usize {
    let lower = arr.partition_point(|x| x < target);
    let upper = arr.partition_point(|x| x <= target);
    upper - lower
}

/// [1.1.24.e] Binary search dans un tableau rotaté
/// Ex: [4, 5, 6, 7, 0, 1, 2] est [0,1,2,4,5,6,7] rotaté
pub fn search_rotated<T: Ord>(arr: &[T], target: &T) -> Option<usize> {
    if arr.is_empty() {
        return None;
    }
    
    let n = arr.len();
    let mut lo = 0;
    let mut hi = n;
    
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        
        if &arr[mid] == target {
            return Some(mid);
        }
        
        // Déterminer quelle moitié est triée
        if arr[lo] <= arr[mid] {
            // Moitié gauche triée
            if &arr[lo] <= target && target < &arr[mid] {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        } else {
            // Moitié droite triée
            if &arr[mid] < target && target <= &arr[hi - 1] {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
    }
    
    None
}

/// Trouver le pivot (minimum) dans un tableau rotaté
pub fn find_rotation_pivot<T: Ord>(arr: &[T]) -> usize {
    if arr.is_empty() || arr[0] <= arr[arr.len() - 1] {
        return 0;  // Non rotaté ou vide
    }
    
    let mut lo = 0;
    let mut hi = arr.len();
    
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        
        if arr[mid] > arr[arr.len() - 1] {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    
    lo
}

/// Exemples complets
pub fn comprehensive_examples() {
    // Tableau trié normal
    let sorted = [1, 2, 3, 3, 3, 4, 5];
    
    println!("Lower bound of 3: {}", lower_bound(&sorted, &3));  // 2
    println!("Upper bound of 3: {}", upper_bound(&sorted, &3));  // 5
    println!("Count of 3: {}", count_occurrences(&sorted, &3));  // 3
    
    // Tableau rotaté
    let rotated = [4, 5, 6, 7, 0, 1, 2];
    
    println!("Search 0 in rotated: {:?}", search_rotated(&rotated, &0));  // Some(4)
    println!("Search 5 in rotated: {:?}", search_rotated(&rotated, &5));  // Some(1)
    println!("Pivot index: {}", find_rotation_pivot(&rotated));  // 4
}
```

### Tests Moulinette
```
upper_bound [1,2,3,3,5,6] 3 -> 4
lower_bound [1,2,3,3,5,6] 3 -> 2
count_occurrences [1,2,3,3,3,5] 3 -> 3
search_rotated [4,5,6,7,0,1,2] 0 -> Some(4)
find_pivot [4,5,6,7,0,1,2] -> 4
```

---

## Exercice SUP-10: `binary_search_on_answer`
**Couvre: 1.1.25.b-d (3 concepts)**

### Concepts
- [1.1.25.b] Fonction monotone — f(x) croissante/décroissante
- [1.1.25.c] Problème de décision — "Est-ce possible avec budget X?"
- [1.1.25.d] Applications — Min max, capacité, temps

### Rust
```rust
/// [1.1.25.b] Binary Search on Answer - recherche sur l'espace des solutions
/// Utilisé quand on peut vérifier "est-ce que X est une solution valide?"
/// et que la validité est monotone

/// [1.1.25.c] Problème de décision typique
/// "Peut-on accomplir la tâche avec un budget/temps/capacité de X?"
pub trait CanSolve {
    fn can_solve(&self, x: i64) -> bool;
}

/// Binary search sur la réponse
pub fn binary_search_answer<P: CanSolve>(problem: &P, lo: i64, hi: i64) -> i64 {
    let mut lo = lo;
    let mut hi = hi;
    
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if problem.can_solve(mid) {
            hi = mid;  // mid est valide, chercher plus petit
        } else {
            lo = mid + 1;  // mid invalide, besoin de plus
        }
    }
    
    lo
}

/// [1.1.25.d] Application 1: Capacité minimale pour transporter
/// N paquets avec poids weights, en D jours max, capacité minimale?
pub fn min_capacity(weights: &[i32], days: i32) -> i32 {
    struct ShipProblem<'a> {
        weights: &'a [i32],
        days: i32,
    }
    
    impl CanSolve for ShipProblem<'_> {
        fn can_solve(&self, capacity: i64) -> bool {
            let mut current_load = 0i64;
            let mut days_needed = 1;
            
            for &w in self.weights {
                if current_load + w as i64 > capacity {
                    days_needed += 1;
                    current_load = w as i64;
                } else {
                    current_load += w as i64;
                }
            }
            
            days_needed <= self.days
        }
    }
    
    let lo = *weights.iter().max().unwrap() as i64;
    let hi = weights.iter().map(|&x| x as i64).sum();
    
    let problem = ShipProblem { weights, days };
    binary_search_answer(&problem, lo, hi) as i32
}

/// Application 2: Koko mange des bananes
/// N piles de bananes, H heures pour tout manger, vitesse minimale?
pub fn min_eating_speed(piles: &[i32], h: i32) -> i32 {
    struct BananaProblem<'a> {
        piles: &'a [i32],
        hours: i32,
    }
    
    impl CanSolve for BananaProblem<'_> {
        fn can_solve(&self, speed: i64) -> bool {
            let hours_needed: i64 = self.piles.iter()
                .map(|&p| (p as i64 + speed - 1) / speed)  // ceil division
                .sum();
            hours_needed <= self.hours as i64
        }
    }
    
    let lo = 1;
    let hi = *piles.iter().max().unwrap() as i64;
    
    let problem = BananaProblem { piles, hours: h };
    binary_search_answer(&problem, lo, hi) as i32
}

/// Application 3: Distance maximale minimale entre éléments
/// Placer M balles dans N positions, maximiser la distance minimale
pub fn max_min_distance(positions: &mut [i32], m: i32) -> i32 {
    positions.sort();
    
    struct DistanceProblem<'a> {
        positions: &'a [i32],
        balls: i32,
    }
    
    impl CanSolve for DistanceProblem<'_> {
        fn can_solve(&self, min_dist: i64) -> bool {
            let mut count = 1;
            let mut last_pos = self.positions[0];
            
            for &pos in &self.positions[1..] {
                if (pos - last_pos) as i64 >= min_dist {
                    count += 1;
                    last_pos = pos;
                }
            }
            
            count >= self.balls
        }
    }
    
    let lo = 1;
    let hi = (positions[positions.len() - 1] - positions[0]) as i64;
    
    // Ici on cherche le MAXIMUM valide (pas minimum)
    let mut lo = lo;
    let mut hi = hi + 1;
    
    let problem = DistanceProblem { positions, balls: m };
    
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if problem.can_solve(mid) {
            lo = mid + 1;  // mid est valide, chercher plus grand
        } else {
            hi = mid;
        }
    }
    
    (lo - 1) as i32
}

/// Pattern général
pub fn binary_search_pattern() -> &'static str {
    "
    Binary Search on Answer pattern:
    
    1. Identifier l'espace de recherche [lo, hi]
    2. Définir le prédicat can_solve(x)
    3. S'assurer que can_solve est monotone
    4. Binary search pour trouver:
       - Le minimum x tel que can_solve(x) = true
       - Ou le maximum x tel que can_solve(x) = true
    
    Exemples classiques:
    - Capacité minimale pour transport en D jours
    - Vitesse minimale pour finir en H heures
    - Distance maximale minimale entre objets
    - Temps minimum pour accomplir N tâches
    "
}
```

### Tests Moulinette
```
min_capacity [1,2,3,4,5,6,7,8,9,10] 5 -> 15
min_eating_speed [3,6,7,11] 8 -> 4
max_min_distance [1,2,3,4,7] 3 -> 3
```

---

## Exercice SUP-11: `ternary_search_complete`
**Couvre: 1.1.26.b-e (4 concepts)**

### Concepts
- [1.1.26.b] Deux points — m1, m2 = 1/3, 2/3
- [1.1.26.c] Réduction — Éliminer 1/3 par itération
- [1.1.26.d] Complexité — O(log n)
- [1.1.26.e] Applications — Optimisation de fonction convexe

### Rust
```rust
/// Ternary Search - trouve le maximum/minimum d'une fonction unimodale
/// [1.1.26.b] Utilise deux points à 1/3 et 2/3 de l'intervalle

/// [1.1.26.e] Fonction unimodale: augmente puis diminue (ou inverse)
/// Exemple: f(x) = -(x-3)² + 10, maximum à x=3

/// Ternary search pour trouver le MAXIMUM d'une fonction unimodale
pub fn ternary_search_max<F>(f: F, mut lo: f64, mut hi: f64, epsilon: f64) -> f64
where
    F: Fn(f64) -> f64,
{
    // [1.1.26.d] O(log n) itérations pour précision epsilon
    while hi - lo > epsilon {
        // [1.1.26.b] Deux points à 1/3 et 2/3
        let m1 = lo + (hi - lo) / 3.0;
        let m2 = hi - (hi - lo) / 3.0;
        
        // [1.1.26.c] Éliminer 1/3 de l'intervalle
        if f(m1) < f(m2) {
            lo = m1;  // Maximum est dans [m1, hi]
        } else {
            hi = m2;  // Maximum est dans [lo, m2]
        }
    }
    
    (lo + hi) / 2.0
}

/// Ternary search pour trouver le MINIMUM d'une fonction unimodale
pub fn ternary_search_min<F>(f: F, mut lo: f64, mut hi: f64, epsilon: f64) -> f64
where
    F: Fn(f64) -> f64,
{
    while hi - lo > epsilon {
        let m1 = lo + (hi - lo) / 3.0;
        let m2 = hi - (hi - lo) / 3.0;
        
        // Inverse la comparaison pour trouver le minimum
        if f(m1) > f(m2) {
            lo = m1;
        } else {
            hi = m2;
        }
    }
    
    (lo + hi) / 2.0
}

/// Version entière (pour arrays discrets)
pub fn ternary_search_discrete_max<F>(f: F, mut lo: i64, mut hi: i64) -> i64
where
    F: Fn(i64) -> i64,
{
    while hi - lo > 2 {
        let m1 = lo + (hi - lo) / 3;
        let m2 = hi - (hi - lo) / 3;
        
        if f(m1) < f(m2) {
            lo = m1;
        } else {
            hi = m2;
        }
    }
    
    // Vérifier tous les points restants
    let mut best = lo;
    let mut best_val = f(lo);
    
    for x in lo + 1..=hi {
        let val = f(x);
        if val > best_val {
            best = x;
            best_val = val;
        }
    }
    
    best
}

/// [1.1.26.d] Analyse de complexité
pub fn complexity_analysis() -> &'static str {
    "
    Complexité: O(log₁.₅ n) ≈ O(2 log₃ n)
    
    À chaque itération:
    - 2 évaluations de f
    - Réduit l'intervalle de 1/3
    
    Pour précision epsilon sur [lo, hi]:
    - Nombre d'itérations ≈ log₁.₅((hi-lo)/epsilon)
    
    Comparé à binary search:
    - Binary: 1 évaluation, réduit de 1/2
    - Ternary: 2 évaluations, réduit de 1/3
    - Binary est plus efficace si l'évaluation est coûteuse
    
    Mais ternary search peut trouver max/min de fonctions unimodales!
    "
}

/// [1.1.26.e] Applications pratiques
pub fn applications() {
    // Application 1: Trouver le maximum d'une parabole inversée
    let f = |x: f64| -(x - 3.0).powi(2) + 10.0;
    let x_max = ternary_search_max(f, 0.0, 10.0, 1e-9);
    println!("Maximum at x = {:.6}", x_max);  // ~3.0
    
    // Application 2: Distance minimale entre point et parabole
    let point = (5.0, 2.0);
    let distance = |x: f64| {
        let y = x * x;  // y = x²
        ((x - point.0).powi(2) + (y - point.1).powi(2)).sqrt()
    };
    let x_closest = ternary_search_min(distance, -10.0, 10.0, 1e-9);
    println!("Closest point at x = {:.6}", x_closest);
    
    // Application 3: Optimisation de fonction de coût
    // Ex: coût = production_cost(x) + shipping_cost(x)
    // où production_cost décroît avec x, shipping_cost croît avec x
}

/// Exemple complet: problème classique
pub fn example_problem() -> &'static str {
    "
    Problème: Cable TV
    N maisons sur une ligne aux positions x[i].
    Placer une antenne pour minimiser la distance maximale.
    
    Solution:
    - f(pos) = max distance depuis pos à toutes les maisons
    - f est unimodale (convexe)
    - Ternary search pour trouver le minimum de f
    - Réponse: (min(x) + max(x)) / 2 (mais ternary search marche aussi)
    "
}

/// Cas où binary search est préférable à ternary search
pub fn binary_vs_ternary() -> &'static str {
    "
    Utiliser BINARY SEARCH quand:
    - Fonction monotone (croissante ou décroissante)
    - Recherche d'un élément spécifique
    - Évaluations de fonction coûteuses
    
    Utiliser TERNARY SEARCH quand:
    - Fonction unimodale (un seul max ou min local)
    - Optimisation sans dérivée
    - Pas besoin de trouver une valeur exacte
    
    Note: Pour fonctions dérivables, binary search sur f'(x) = 0
    peut être plus efficace que ternary search sur f(x).
    "
}
```

### Tests Moulinette
```
ternary_max f(x)=-(x-3)²+10 [0,10] -> 3.0
ternary_min f(x)=(x-5)² [0,10] -> 5.0
ternary_discrete_max [1,3,5,7,6,4,2] -> index 3 (value 7)
```

---

## RÉSUMÉ DE COUVERTURE

| Exercice | Concepts couverts | Total |
|----------|------------------|-------|
| SUP-1 quadratic_sorts | 1.1.15.b-f | 5 |
| SUP-2 merge_sort | 1.1.16.b-g | 6 |
| SUP-3 quick_sort | 1.1.17.b-i | 8 |
| SUP-4 heap_sort | 1.1.18.b-h | 7 |
| SUP-5 std_sorts | 1.1.19.b-h | 7 |
| SUP-6 lower_bound | 1.1.20.b-h | 7 |
| SUP-7 non_comparison | 1.1.21.b-i | 8 |
| SUP-8 linear_search | 1.1.22.b-f | 5 |
| SUP-9 binary_variants | 1.1.24.b-e | 4 |
| SUP-10 binary_on_answer | 1.1.25.b-d | 3 |
| SUP-11 ternary_search | 1.1.26.b-e | 4 |
| **TOTAL** | | **64** |

**Couverture Module 1.1: 162 + 64 = 226/226 = 100%**
