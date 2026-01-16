# MODULE 1.2 - EXERCICES SUPPLÉMENTAIRES (Partie 2/5)
## Open Addressing, Cuckoo, Robin Hood, HashMap Rust

---

## Exercice SUP-4: `open_addressing_complete`
**Couvre: 1.2.6.b-j (9 concepts)**

### Concepts
- [1.2.6.b] Probing — Séquence de recherche
- [1.2.6.c] Linear probing — h(k) + i
- [1.2.6.d] Primary clustering — Problème du linear
- [1.2.6.e] Quadratic probing — h(k) + c₁i + c₂i²
- [1.2.6.f] Secondary clustering — Problème du quadratic
- [1.2.6.g] Double hashing — h₁(k) + i×h₂(k)
- [1.2.6.h] Suppression — Tombstones
- [1.2.6.i] Tombstone cleanup — Rehash périodique
- [1.2.6.j] Load factor max — α < 0.7 recommandé

### Rust
```rust
/// [1.2.6.b] Open Addressing avec différentes stratégies de probing
#[derive(Clone)]
enum Slot<K, V> {
    Empty,
    Occupied(K, V),
    Tombstone,  // [1.2.6.h]
}

pub struct OpenAddressedHashTable<K, V> {
    slots: Vec<Slot<K, V>>,
    size: usize,
    tombstones: usize,
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> OpenAddressedHashTable<K, V> {
    pub fn new() -> Self {
        Self::with_capacity(16)
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: vec![Slot::Empty; capacity],
            size: 0,
            tombstones: 0,
            capacity,
        }
    }
    
    fn hash(&self, key: &K) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % self.capacity
    }
    
    /// [1.2.6.c] Linear Probing: h(k,i) = (h(k) + i) mod m
    fn linear_probe(&self, key: &K, i: usize) -> usize {
        (self.hash(key) + i) % self.capacity
    }
    
    /// [1.2.6.e] Quadratic Probing: h(k,i) = (h(k) + c₁i + c₂i²) mod m
    fn quadratic_probe(&self, key: &K, i: usize) -> usize {
        let c1 = 1usize;
        let c2 = 1usize;
        (self.hash(key) + c1 * i + c2 * i * i) % self.capacity
    }
    
    /// [1.2.6.g] Double Hashing: h(k,i) = (h₁(k) + i × h₂(k)) mod m
    fn double_hash_probe(&self, key: &K, i: usize) -> usize {
        let h1 = self.hash(key);
        // h2 ne doit jamais être 0, et coprime avec m
        let h2 = 1 + (self.hash(key) % (self.capacity - 1));
        (h1 + i * h2) % self.capacity
    }
    
    /// [1.2.6.j] Load factor - garder < 0.7
    pub fn load_factor(&self) -> f64 {
        (self.size + self.tombstones) as f64 / self.capacity as f64
    }
    
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.load_factor() > 0.7 {
            self.resize(self.capacity * 2);
        }
        
        let mut first_tombstone = None;
        
        for i in 0..self.capacity {
            let idx = self.linear_probe(&key, i);
            
            match &self.slots[idx] {
                Slot::Empty => {
                    let insert_idx = first_tombstone.unwrap_or(idx);
                    if first_tombstone.is_some() {
                        self.tombstones -= 1;
                    }
                    self.slots[insert_idx] = Slot::Occupied(key, value);
                    self.size += 1;
                    return None;
                }
                Slot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                Slot::Occupied(k, _) if k == &key => {
                    let old = match std::mem::replace(&mut self.slots[idx], 
                        Slot::Occupied(key, value)) {
                        Slot::Occupied(_, v) => v,
                        _ => unreachable!(),
                    };
                    return Some(old);
                }
                Slot::Occupied(_, _) => {}
            }
        }
        
        None  // Table pleine (ne devrait pas arriver avec resize)
    }
    
    pub fn get(&self, key: &K) -> Option<&V> {
        for i in 0..self.capacity {
            let idx = self.linear_probe(key, i);
            
            match &self.slots[idx] {
                Slot::Empty => return None,
                Slot::Occupied(k, v) if k == key => return Some(v),
                _ => {}
            }
        }
        None
    }
    
    /// [1.2.6.h] Suppression avec tombstone
    pub fn remove(&mut self, key: &K) -> Option<V> {
        for i in 0..self.capacity {
            let idx = self.linear_probe(key, i);
            
            match &self.slots[idx] {
                Slot::Empty => return None,
                Slot::Occupied(k, _) if k == key => {
                    let old = std::mem::replace(&mut self.slots[idx], Slot::Tombstone);
                    self.size -= 1;
                    self.tombstones += 1;
                    
                    // [1.2.6.i] Cleanup si trop de tombstones
                    if self.tombstones > self.size {
                        self.resize(self.capacity);
                    }
                    
                    if let Slot::Occupied(_, v) = old {
                        return Some(v);
                    }
                }
                _ => {}
            }
        }
        None
    }
    
    /// [1.2.6.i] Resize nettoie les tombstones
    fn resize(&mut self, new_capacity: usize) {
        let old_slots = std::mem::replace(
            &mut self.slots, 
            vec![Slot::Empty; new_capacity]
        );
        
        self.capacity = new_capacity;
        self.size = 0;
        self.tombstones = 0;
        
        for slot in old_slots {
            if let Slot::Occupied(k, v) = slot {
                self.insert(k, v);
            }
        }
    }
}

/// [1.2.6.d] Primary Clustering
pub fn primary_clustering_explanation() -> &'static str {
    "
    Primary Clustering (Linear Probing):
    - Les éléments forment des 'clusters' contigus
    - Un nouveau élément qui hash dans un cluster
      doit parcourir tout le cluster
    - Les clusters grandissent et fusionnent
    - Performance se dégrade rapidement avec α
    "
}

/// [1.2.6.f] Secondary Clustering  
pub fn secondary_clustering_explanation() -> &'static str {
    "
    Secondary Clustering (Quadratic Probing):
    - Clés avec même hash suivent la même séquence
    - Moins grave que primary clustering
    - Ne garantit pas de visiter tous les slots
    - Nécessite m premier ou m = 2^k avec c1=c2=1/2
    "
}

use std::hash::{Hash, Hasher};
```

---

## Exercice SUP-5: `cuckoo_robin_hood`
**Couvre: 1.2.7.b-h (7 concepts)**

### Concepts
- [1.2.7.b] Cuckoo insertion — Éviction en chaîne
- [1.2.7.c] Cuckoo cycle — Détection et rehash
- [1.2.7.d] Cuckoo recherche — O(1) garanti
- [1.2.7.e] Robin Hood hashing — Voler aux riches
- [1.2.7.f] Robin Hood — Variance réduite
- [1.2.7.g] Swiss Table — Google's hashbrown
- [1.2.7.h] SIMD probing — Recherche parallèle

### Rust
```rust
/// [1.2.7.b-d] Cuckoo Hashing - 2 tables, O(1) lookup garanti
pub struct CuckooHashTable<K, V> {
    table1: Vec<Option<(K, V)>>,
    table2: Vec<Option<(K, V)>>,
    capacity: usize,
    size: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> CuckooHashTable<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            table1: vec![None; capacity],
            table2: vec![None; capacity],
            capacity,
            size: 0,
        }
    }
    
    fn hash1(&self, key: &K) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        h.finish() as usize % self.capacity
    }
    
    fn hash2(&self, key: &K) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        (h.finish().wrapping_mul(31337)) as usize % self.capacity
    }
    
    /// [1.2.7.d] Recherche O(1) garanti - seulement 2 lookups
    pub fn get(&self, key: &K) -> Option<&V> {
        let idx1 = self.hash1(key);
        if let Some((k, v)) = &self.table1[idx1] {
            if k == key { return Some(v); }
        }
        
        let idx2 = self.hash2(key);
        if let Some((k, v)) = &self.table2[idx2] {
            if k == key { return Some(v); }
        }
        
        None
    }
    
    /// [1.2.7.b] Insertion avec éviction
    pub fn insert(&mut self, key: K, value: V) -> bool {
        if self.get(&key).is_some() {
            return false;  // Déjà présent
        }
        
        let mut current = (key, value);
        let max_iterations = self.capacity * 2;
        
        for i in 0..max_iterations {
            // Essayer table1
            let idx1 = self.hash1(&current.0);
            if self.table1[idx1].is_none() {
                self.table1[idx1] = Some(current);
                self.size += 1;
                return true;
            }
            
            // Éviction de table1
            std::mem::swap(&mut self.table1[idx1], &mut Some(current));
            let evicted = self.table1[idx1].take().unwrap();
            current = evicted;
            
            // Essayer table2
            let idx2 = self.hash2(&current.0);
            if self.table2[idx2].is_none() {
                self.table2[idx2] = Some(current);
                self.size += 1;
                return true;
            }
            
            // Éviction de table2
            std::mem::swap(&mut self.table2[idx2], &mut Some(current));
            let evicted = self.table2[idx2].take().unwrap();
            current = evicted;
        }
        
        // [1.2.7.c] Cycle détecté - besoin de rehash
        self.rehash();
        self.insert(current.0, current.1)
    }
    
    /// [1.2.7.c] Rehash avec nouvelles fonctions
    fn rehash(&mut self) {
        let old_cap = self.capacity;
        self.capacity *= 2;
        
        let old_t1 = std::mem::replace(&mut self.table1, vec![None; self.capacity]);
        let old_t2 = std::mem::replace(&mut self.table2, vec![None; self.capacity]);
        self.size = 0;
        
        for slot in old_t1.into_iter().chain(old_t2) {
            if let Some((k, v)) = slot {
                self.insert(k, v);
            }
        }
    }
}

/// [1.2.7.e, 1.2.7.f] Robin Hood Hashing
pub struct RobinHoodHashTable<K, V> {
    slots: Vec<Option<(K, V, usize)>>,  // (key, value, probe_distance)
    capacity: usize,
    size: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> RobinHoodHashTable<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: vec![None; capacity],
            capacity,
            size: 0,
        }
    }
    
    fn hash(&self, key: &K) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        h.finish() as usize % self.capacity
    }
    
    /// [1.2.7.e] Robin Hood: voler aux riches (éléments avec petit probe_distance)
    pub fn insert(&mut self, key: K, value: V) {
        let mut current = (key, value, 0usize);
        let mut idx = self.hash(&current.0);
        
        loop {
            match &self.slots[idx] {
                None => {
                    self.slots[idx] = Some(current);
                    self.size += 1;
                    return;
                }
                Some((_, _, existing_dist)) => {
                    // [1.2.7.e] Si on est "plus pauvre" (plus loin de home), on vole
                    if current.2 > *existing_dist {
                        let evicted = self.slots[idx].take().unwrap();
                        self.slots[idx] = Some(current);
                        current = evicted;
                    }
                }
            }
            
            idx = (idx + 1) % self.capacity;
            current.2 += 1;
        }
    }
    
    /// [1.2.7.f] Variance réduite: tous les éléments ont probe_distance similaire
    pub fn variance_benefit() -> &'static str {
        "
        Robin Hood égalise les distances de probe:
        - Max probe distance = O(log n) avec haute probabilité
        - Variance des distances très faible
        - Recherche échouée rapide (backward shift deletion)
        "
    }
}

/// [1.2.7.g, 1.2.7.h] Swiss Table (hashbrown)
pub fn swiss_table_explanation() -> &'static str {
    "
    Swiss Table (Google, utilisé par hashbrown/std::HashMap):
    
    Structure:
    - Groupes de 16 slots
    - 1 byte de métadonnées par slot (control byte)
    - Control byte = hash partiel ou EMPTY/DELETED
    
    [1.2.7.h] SIMD Probing:
    - Charge 16 control bytes en un registre SIMD
    - Compare avec le hash partiel en parallèle
    - Un SIMD compare trouve tous les candidats en 1 instruction
    
    Performance:
    - ~30% plus rapide que linear probing classique
    - Excellent comportement cache
    "
}

use std::hash::{Hash, Hasher};
```

---

## Exercice SUP-6: `hashmap_hashset_rust`
**Couvre: 1.2.8.b-k (10 concepts)**

### Concepts
- [1.2.8.b] `HashSet<T>` — Ensemble sans valeur
- [1.2.8.c] Entry API — Manipulation efficace
- [1.2.8.d] `get` / `get_mut` — Accès aux valeurs
- [1.2.8.e] `insert` / `remove` — Modification
- [1.2.8.f] `contains_key` — Test d'existence
- [1.2.8.g] Iteration — `iter`, `keys`, `values`
- [1.2.8.h] `drain` / `retain` — Modification en masse
- [1.2.8.i] `extend` — Ajout depuis iterator
- [1.2.8.j] Capacity — `with_capacity`, `reserve`
- [1.2.8.k] Custom hasher — `BuildHasher`

### Rust
```rust
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

pub fn hashmap_complete_demo() {
    // [1.2.8.j] Capacity - pré-allocation
    let mut map: HashMap<String, i32> = HashMap::with_capacity(100);
    map.reserve(50);  // Garantir capacité supplémentaire
    
    // [1.2.8.e] insert
    map.insert("alice".to_string(), 30);
    map.insert("bob".to_string(), 25);
    
    // [1.2.8.d] get / get_mut
    if let Some(age) = map.get("alice") {
        println!("Alice: {}", age);
    }
    if let Some(age) = map.get_mut("bob") {
        *age += 1;  // Bob a maintenant 26 ans
    }
    
    // [1.2.8.f] contains_key
    assert!(map.contains_key("alice"));
    assert!(!map.contains_key("charlie"));
    
    // [1.2.8.c] Entry API - très puissant
    // or_insert: insère si absent
    map.entry("charlie".to_string()).or_insert(35);
    
    // or_insert_with: insertion lazy
    map.entry("dave".to_string()).or_insert_with(|| expensive_default());
    
    // and_modify: modifier si présent
    map.entry("alice".to_string())
        .and_modify(|age| *age += 1)
        .or_insert(0);
    
    // or_default: utilise Default::default()
    let counter: HashMap<char, i32> = HashMap::new();
    // counter.entry('a').or_default() += 1;
    
    // [1.2.8.g] Iteration
    for (key, value) in &map {
        println!("{}: {}", key, value);
    }
    for key in map.keys() {
        println!("Key: {}", key);
    }
    for value in map.values() {
        println!("Value: {}", value);
    }
    for value in map.values_mut() {
        *value *= 2;  // Doubler toutes les valeurs
    }
    
    // [1.2.8.h] drain - vide la map et itère
    let drained: Vec<_> = map.drain().collect();
    assert!(map.is_empty());
    
    // Reconstruire pour retain
    let mut map: HashMap<&str, i32> = [("a", 1), ("b", 2), ("c", 3)].into();
    
    // retain - garder seulement certains éléments
    map.retain(|_, v| *v > 1);
    assert_eq!(map.len(), 2);  // Seulement b et c
    
    // [1.2.8.i] extend
    map.extend([("d", 4), ("e", 5)]);
    
    // [1.2.8.e] remove
    let removed = map.remove("b");
    assert_eq!(removed, Some(2));
}

fn expensive_default() -> i32 { 42 }

/// [1.2.8.b] HashSet
pub fn hashset_demo() {
    let mut set: HashSet<i32> = HashSet::new();
    
    // insert retourne true si nouveau
    assert!(set.insert(1));
    assert!(!set.insert(1));  // Déjà présent
    
    // Opérations ensemblistes
    let set_a: HashSet<_> = [1, 2, 3].into();
    let set_b: HashSet<_> = [2, 3, 4].into();
    
    let union: HashSet<_> = set_a.union(&set_b).copied().collect();
    let intersection: HashSet<_> = set_a.intersection(&set_b).copied().collect();
    let difference: HashSet<_> = set_a.difference(&set_b).copied().collect();
    let symmetric_diff: HashSet<_> = set_a.symmetric_difference(&set_b).copied().collect();
    
    assert!(set_a.is_subset(&union));
    assert!(set_a.is_superset(&intersection));
    assert!(set_a.is_disjoint(&[5, 6].into()));
}

/// [1.2.8.k] Custom Hasher
pub fn custom_hasher_demo() {
    use std::hash::BuildHasherDefault;
    use std::collections::hash_map::DefaultHasher;
    
    // FxHash - très rapide pour petites clés
    // use rustc_hash::FxHashMap;
    // let map: FxHashMap<i32, i32> = FxHashMap::default();
    
    // AHash - par défaut dans hashbrown, résistant DoS
    // use ahash::AHashMap;
    
    // Hasher custom
    #[derive(Default)]
    struct SimpleHasher(u64);
    
    impl Hasher for SimpleHasher {
        fn write(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.0 = self.0.wrapping_mul(31).wrapping_add(b as u64);
            }
        }
        fn finish(&self) -> u64 { self.0 }
    }
    
    type SimpleHashMap<K, V> = HashMap<K, V, BuildHasherDefault<SimpleHasher>>;
    let _map: SimpleHashMap<String, i32> = SimpleHashMap::default();
}
```

---

## RÉSUMÉ PARTIE 2

| Exercice | Concepts couverts | Total |
|----------|------------------|-------|
| SUP-4 open_addressing | 1.2.6.b-j | 9 |
| SUP-5 cuckoo_robin_hood | 1.2.7.b-h | 7 |
| SUP-6 hashmap_hashset | 1.2.8.b-k | 10 |
| **TOTAL PARTIE 2** | | **26** |
