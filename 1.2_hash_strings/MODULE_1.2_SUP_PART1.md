# MODULE 1.2 - EXERCICES SUPPLÉMENTAIRES (Partie 1/5)
## Hash Tables: Universal, Perfect, Chaining

---

## Exercice SUP-1: `universal_hashing`
**Couvre: 1.2.3.b-g (6 concepts)**

### Concepts
- [1.2.3.b] Propriété — Pr[h(x) = h(y)] ≤ 1/m pour x ≠ y
- [1.2.3.c] Construction — Famille de fonctions hash
- [1.2.3.d] Preuve — Borne sur collisions
- [1.2.3.e] 2-universal — Paire indépendante
- [1.2.3.f] k-universal — k-wise indépendance
- [1.2.3.g] Applications — Hash tables, sketches

### Rust
```rust
use rand::Rng;

/// [1.2.3.b, 1.2.3.c] Universal Hash Family: h(x) = ((a*x + b) mod p) mod m
pub struct UniversalHashFamily {
    p: u64,  // Grand nombre premier
    m: u64,  // Taille de la table
}

impl UniversalHashFamily {
    pub fn new(m: u64) -> Self {
        // p doit être premier et > max(clé)
        let p = 1_000_000_007;  // Grand premier
        Self { p, m }
    }
    
    /// [1.2.3.c] Génère une fonction hash aléatoire de la famille
    pub fn random_hash(&self) -> impl Fn(u64) -> u64 {
        let mut rng = rand::thread_rng();
        let a = rng.gen_range(1..self.p);  // a ∈ [1, p-1]
        let b = rng.gen_range(0..self.p);  // b ∈ [0, p-1]
        let p = self.p;
        let m = self.m;
        
        move |x: u64| ((a.wrapping_mul(x).wrapping_add(b)) % p) % m
    }
}

/// [1.2.3.d] Preuve de l'universalité
pub fn universality_proof() -> &'static str {
    "
    Pour h(x) = ((ax + b) mod p) mod m:
    
    Fixons x ≠ y. Pour un 'a' fixé:
    - ax + b ≢ ay + b (mod p) car a ≠ 0 et x ≠ y
    - Donc h(x) et h(y) sont différents mod p
    
    La probabilité que ((ax+b) mod p) mod m = ((ay+b) mod p) mod m
    est ≤ ⌈p/m⌉ / p ≤ 1/m + 1/p ≈ 1/m
    
    Donc Pr[h(x) = h(y)] ≤ 1/m pour x ≠ y ✓
    "
}

/// [1.2.3.e] 2-Universal: toute paire est indépendante
pub fn two_universal_example() {
    // Pour h ∈ H famille 2-universelle:
    // Pr[h(x) = a ET h(y) = b] = 1/m² pour x ≠ y
    
    // La famille h(x) = (ax + b) mod p mod m est 2-universelle
}

/// [1.2.3.f] k-Universal: k-wise indépendance
pub fn k_universal() -> &'static str {
    "
    k-Universal: pour tout k points distincts x₁,...,xₖ
    et valeurs a₁,...,aₖ:
    
    Pr[h(x₁)=a₁ ∧ ... ∧ h(xₖ)=aₖ] = 1/mᵏ
    
    Construction: polynôme de degré k-1
    h(x) = (a₀ + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹) mod p mod m
    "
}

/// [1.2.3.g] Applications
pub fn applications() -> &'static str {
    "
    1. Hash Tables: garantie O(1) moyen avec randomisation
    2. Count-Min Sketch: estimation de fréquences
    3. Bloom Filters: réduire faux positifs
    4. MinHash: estimation similarité Jaccard
    5. Load Balancing: distribution uniforme
    "
}
```

---

## Exercice SUP-2: `perfect_hashing`
**Couvre: 1.2.4.b-h (7 concepts)**

### Concepts
- [1.2.4.b] FKS scheme — Fredman-Komlós-Szemerédi
- [1.2.4.c] Two-level hashing — Premier niveau + buckets
- [1.2.4.d] Construction — Temps O(n) attendu
- [1.2.4.e] Query — O(1) garanti
- [1.2.4.f] Espace — O(n)
- [1.2.4.g] Minimal perfect — n slots pour n clés
- [1.2.4.h] `phf` crate — Perfect hash en Rust

### Rust
```rust
/// [1.2.4.b, 1.2.4.c] FKS Perfect Hashing (deux niveaux)
pub struct FKSPerfectHash {
    // Niveau 1: hash vers buckets
    first_level: Vec<Option<SecondLevel>>,
    m1: usize,  // Taille niveau 1
}

struct SecondLevel {
    hash_params: (u64, u64),  // (a, b) pour h(x) = (ax+b) mod p mod m²
    table: Vec<Option<u64>>,
}

impl FKSPerfectHash {
    /// [1.2.4.d] Construction en O(n) temps attendu
    pub fn new(keys: &[u64]) -> Self {
        let n = keys.len();
        let m1 = n;  // Taille premier niveau
        
        // Étape 1: Distribuer dans les buckets avec universal hash
        let mut buckets: Vec<Vec<u64>> = vec![Vec::new(); m1];
        let h1 = universal_hash(m1);
        
        for &key in keys {
            let idx = h1(key) as usize;
            buckets[idx].push(key);
        }
        
        // Étape 2: Pour chaque bucket, créer table de taille nᵢ²
        let mut first_level = vec![None; m1];
        
        for (i, bucket) in buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            
            let ni = bucket.len();
            let mi = ni * ni;  // Taille = nᵢ² garantit pas de collision
            
            // Trouver hash sans collision (essayer jusqu'à succès)
            let second = find_collision_free_hash(&bucket, mi);
            first_level[i] = Some(second);
        }
        
        Self { first_level, m1 }
    }
    
    /// [1.2.4.e] Query en O(1) garanti
    pub fn contains(&self, key: u64) -> bool {
        let h1 = universal_hash(self.m1);
        let idx = h1(key) as usize;
        
        if let Some(ref second) = self.first_level[idx] {
            let h2 = second_level_hash(&second.hash_params, second.table.len());
            let idx2 = h2(key) as usize;
            second.table[idx2] == Some(key)
        } else {
            false
        }
    }
}

fn universal_hash(m: usize) -> impl Fn(u64) -> u64 {
    let p = 1_000_000_007u64;
    let a = 31;
    let b = 17;
    move |x| ((a * x + b) % p) % (m as u64)
}

fn second_level_hash(params: &(u64, u64), m: usize) -> impl Fn(u64) -> u64 + '_ {
    let p = 1_000_000_007u64;
    move |x| ((params.0 * x + params.1) % p) % (m as u64)
}

fn find_collision_free_hash(keys: &[u64], m: usize) -> SecondLevel {
    // Essayer des paramètres aléatoires jusqu'à pas de collision
    let p = 1_000_000_007u64;
    
    loop {
        let a = rand::random::<u64>() % p + 1;
        let b = rand::random::<u64>() % p;
        
        let mut table = vec![None; m];
        let mut collision = false;
        
        for &key in keys {
            let idx = ((a * key + b) % p) % (m as u64);
            if table[idx as usize].is_some() {
                collision = true;
                break;
            }
            table[idx as usize] = Some(key);
        }
        
        if !collision {
            return SecondLevel {
                hash_params: (a, b),
                table,
            };
        }
    }
}

/// [1.2.4.f] Analyse d'espace
pub fn space_analysis() -> &'static str {
    "
    Espace total = O(n)
    
    Preuve:
    - Σ nᵢ² où nᵢ = taille bucket i
    - E[Σ nᵢ²] = E[Σ collisions] + n ≤ n + n = O(n)
    - Avec universal hashing, E[collisions] ≤ n
    "
}

/// [1.2.4.g] Minimal Perfect Hashing
pub fn minimal_perfect() -> &'static str {
    "
    Minimal Perfect Hash: exactement n slots pour n clés
    - Chaque clé a un slot unique
    - Pas d'espace gaspillé
    
    Algorithmes: CHD, BDZ, PTHash
    Utilisé pour dictionnaires statiques
    "
}

/// [1.2.4.h] Utilisation de phf crate
pub fn phf_example() -> &'static str {
    r#"
    use phf::phf_map;
    
    static KEYWORDS: phf::Map<&'static str, i32> = phf_map! {
        "loop" => 1,
        "continue" => 2,
        "break" => 3,
        "fn" => 4,
    };
    
    // Lookup O(1) garanti, généré à compile-time
    let val = KEYWORDS.get("fn");
    "#
}
```

---

## Exercice SUP-3: `chaining_complete`
**Couvre: 1.2.5.b-j (9 concepts)**

### Concepts
- [1.2.5.b] Structure — Tableau de listes chaînées
- [1.2.5.c] Insertion — O(1) en tête de liste
- [1.2.5.d] Recherche — O(1+α) moyen
- [1.2.5.e] Suppression — O(1+α) moyen
- [1.2.5.f] Load factor α — n/m éléments par bucket
- [1.2.5.g] Analyse — Performance vs α
- [1.2.5.h] Worst case — O(n) si toutes collisions
- [1.2.5.i] Resize trigger — Quand α > seuil
- [1.2.5.j] Rust ownership — Gestion mémoire

### Rust
```rust
use std::collections::LinkedList;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// [1.2.5.b] Hash Table avec Chaining
pub struct ChainedHashTable<K, V> {
    buckets: Vec<LinkedList<(K, V)>>,
    size: usize,
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> ChainedHashTable<K, V> {
    pub fn new() -> Self {
        Self::with_capacity(16)
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buckets: (0..capacity).map(|_| LinkedList::new()).collect(),
            size: 0,
            capacity,
        }
    }
    
    fn hash(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.capacity
    }
    
    /// [1.2.5.f] Load factor
    pub fn load_factor(&self) -> f64 {
        self.size as f64 / self.capacity as f64
    }
    
    /// [1.2.5.c] Insertion O(1)
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        // [1.2.5.i] Resize si α > 0.75
        if self.load_factor() > 0.75 {
            self.resize(self.capacity * 2);
        }
        
        let idx = self.hash(&key);
        
        // Vérifier si la clé existe déjà
        for (k, v) in self.buckets[idx].iter_mut() {
            if k == &key {
                let old = v.clone();
                *v = value;
                return Some(old);
            }
        }
        
        // Insérer en tête de liste
        self.buckets[idx].push_front((key, value));
        self.size += 1;
        None
    }
    
    /// [1.2.5.d] Recherche O(1+α) moyen, [1.2.5.h] O(n) pire
    pub fn get(&self, key: &K) -> Option<&V> {
        let idx = self.hash(key);
        
        for (k, v) in &self.buckets[idx] {
            if k == key {
                return Some(v);
            }
        }
        None
    }
    
    /// [1.2.5.e] Suppression O(1+α) moyen
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.hash(key);
        
        // [1.2.5.j] Rust ownership - besoin de reconstruire la liste
        let mut new_list = LinkedList::new();
        let mut removed = None;
        
        while let Some((k, v)) = self.buckets[idx].pop_front() {
            if &k == key {
                removed = Some(v);
                self.size -= 1;
            } else {
                new_list.push_back((k, v));
            }
        }
        
        self.buckets[idx] = new_list;
        removed
    }
    
    /// [1.2.5.i] Resize
    fn resize(&mut self, new_capacity: usize) {
        let mut new_buckets: Vec<LinkedList<(K, V)>> = 
            (0..new_capacity).map(|_| LinkedList::new()).collect();
        
        for bucket in self.buckets.drain(..) {
            for (k, v) in bucket {
                let mut hasher = DefaultHasher::new();
                k.hash(&mut hasher);
                let idx = (hasher.finish() as usize) % new_capacity;
                new_buckets[idx].push_front((k, v));
            }
        }
        
        self.buckets = new_buckets;
        self.capacity = new_capacity;
    }
}

/// [1.2.5.g] Analyse de performance
pub fn performance_analysis() -> &'static str {
    "
    Load factor α = n/m
    
    Recherche réussie: O(1 + α/2) moyen
    Recherche échouée: O(1 + α) moyen
    
    Pour α = 1: ~2 comparaisons en moyenne
    Pour α = 0.5: ~1.5 comparaisons en moyenne
    
    Recommandation: garder α < 0.75
    "
}
```

---

## RÉSUMÉ PARTIE 1

| Exercice | Concepts couverts | Total |
|----------|------------------|-------|
| SUP-1 universal_hashing | 1.2.3.b-g | 6 |
| SUP-2 perfect_hashing | 1.2.4.b-h | 7 |
| SUP-3 chaining | 1.2.5.b-j | 9 |
| **TOTAL PARTIE 1** | | **22** |
