# MODULE 1.2 : Hash Tables & Strings
## Plan d'Exercices Couvrant les 254 Concepts

**Objectif:** Couverture complète de tous les concepts (lettres a-z) du Module 1.2
**Langages:** Rust Edition 2024 / Python 3.14
**Standard:** 95/100 minimum en qualité pédagogique

---

## SÉRIE A : Fondamentaux du Hashing (36 concepts)

### Exercice A1 : `hash_fundamentals` (Couvre 1.2.1.a-h, 1.2.2.a-m = 21 concepts)

**Concepts couverts:**
- [1.2.1.a] Concept - Clé → index via fonction
- [1.2.1.b] Déterminisme - Même clé → même hash
- [1.2.1.c] Uniformité - Distribution équilibrée
- [1.2.1.d] Efficacité - Calcul rapide O(1)
- [1.2.1.e] Avalanche effect - Petit changement → grand changement
- [1.2.1.f] Collision - Deux clés → même hash
- [1.2.1.g] Birthday paradox - Probabilité de collision
- [1.2.1.h] Applications - Dictionnaires, caches, déduplication
- [1.2.2.a] Division method - h(k) = k mod m
- [1.2.2.b] Choix de m - Nombre premier, pas puissance de 2
- [1.2.2.c] Multiplication method - h(k) = ⌊m(kA mod 1)⌋
- [1.2.2.d] Knuth's suggestion - A ≈ (√5-1)/2
- [1.2.2.e] djb2 - Hash pour strings populaire
- [1.2.2.f] FNV-1a - Fowler-Noll-Vo
- [1.2.2.g] MurmurHash - Non-cryptographique rapide
- [1.2.2.h] CityHash - Google's hash
- [1.2.2.i] SipHash - Résistant aux attaques
- [1.2.2.j] xxHash - Extrêmement rapide
- [1.2.2.k] Polynomial rolling hash - Pour strings
- [1.2.2.l] Implémentation - Code des fonctions
- [1.2.2.m] Benchmark - Comparaison des fonctions

**Description:**
Implémenter et comparer différentes fonctions de hashing.

**Rust:**
```rust
// src/lib.rs

/// Trait pour les fonctions de hashing
pub trait Hasher {
    fn hash(&self, key: &[u8]) -> u64;
    fn name(&self) -> &'static str;
}

/// Division method hasher
pub struct DivisionHasher {
    m: u64,
}

impl DivisionHasher {
    pub fn new(m: u64) -> Self;
}

/// Multiplication method hasher (Knuth)
pub struct MultiplicationHasher {
    m: u64,
}

/// djb2 hasher
pub struct Djb2Hasher;

impl Djb2Hasher {
    pub fn hash_str(s: &str) -> u64 {
        let mut hash: u64 = 5381;
        for c in s.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u64);
        }
        hash
    }
}

/// FNV-1a hasher
pub struct Fnv1aHasher;

impl Fnv1aHasher {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    pub fn hash_bytes(data: &[u8]) -> u64 {
        let mut hash = Self::FNV_OFFSET;
        for byte in data {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(Self::FNV_PRIME);
        }
        hash
    }
}

/// Polynomial rolling hash
pub struct PolynomialRollingHash {
    base: u64,
    modulus: u64,
}

impl PolynomialRollingHash {
    pub fn new(base: u64, modulus: u64) -> Self;
    pub fn hash(&self, s: &str) -> u64;
    pub fn roll(&self, old_hash: u64, old_char: u8, new_char: u8, power: u64) -> u64;
}

/// Analyse de qualité d'une fonction de hash
pub struct HashQuality {
    pub collisions: usize,
    pub distribution_chi_squared: f64,
    pub avalanche_score: f64,
    pub time_per_hash_ns: f64,
}

pub fn analyze_hash_quality<H: Hasher>(
    hasher: &H,
    test_keys: &[&[u8]],
    buckets: usize
) -> HashQuality;

pub fn benchmark_hashers(keys: &[&[u8]]) -> Vec<(&'static str, HashQuality)>;
```

**Python:**
```python
# hash_fundamentals.py
from abc import ABC, abstractmethod
from typing import List, Tuple
import time

class Hasher(ABC):
    @abstractmethod
    def hash(self, key: bytes) -> int:
        pass

    @abstractmethod
    def name(self) -> str:
        pass

class DivisionHasher(Hasher):
    def __init__(self, m: int):
        self.m = m

    def hash(self, key: bytes) -> int:
        return int.from_bytes(key, 'little') % self.m

    def name(self) -> str:
        return f"Division(m={self.m})"

class MultiplicationHasher(Hasher):
    """Knuth's multiplication method with A ≈ (√5-1)/2"""
    A = 0.6180339887498949  # (sqrt(5) - 1) / 2

    def __init__(self, m: int):
        self.m = m

    def hash(self, key: bytes) -> int:
        k = int.from_bytes(key, 'little')
        return int(self.m * ((k * self.A) % 1))

    def name(self) -> str:
        return "Multiplication(Knuth)"

class Djb2Hasher(Hasher):
    def hash(self, key: bytes) -> int:
        h = 5381
        for byte in key:
            h = ((h << 5) + h) + byte  # h * 33 + byte
        return h & 0xFFFFFFFFFFFFFFFF

    def name(self) -> str:
        return "djb2"

class Fnv1aHasher(Hasher):
    FNV_OFFSET = 14695981039346656037
    FNV_PRIME = 1099511628211

    def hash(self, key: bytes) -> int:
        h = self.FNV_OFFSET
        for byte in key:
            h ^= byte
            h = (h * self.FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
        return h

    def name(self) -> str:
        return "FNV-1a"

class PolynomialRollingHash:
    def __init__(self, base: int = 31, modulus: int = 10**9 + 7):
        self.base = base
        self.modulus = modulus

    def hash(self, s: str) -> int:
        h = 0
        p = 1
        for c in s:
            h = (h + ord(c) * p) % self.modulus
            p = (p * self.base) % self.modulus
        return h

    def roll(self, old_hash: int, old_char: str, new_char: str, power: int) -> int:
        """Update hash when window slides"""
        h = old_hash - ord(old_char)
        h = (h * pow(self.base, -1, self.modulus)) % self.modulus
        h = (h + ord(new_char) * power) % self.modulus
        return h

@dataclass
class HashQuality:
    collisions: int
    distribution_chi_squared: float
    avalanche_score: float
    time_per_hash_ns: float

def analyze_hash_quality(
    hasher: Hasher,
    test_keys: list[bytes],
    buckets: int
) -> HashQuality:
    """Analyse la qualité d'une fonction de hash"""
    pass

def demonstrate_birthday_paradox(hasher: Hasher, bits: int = 32) -> dict:
    """Démontre le paradoxe des anniversaires"""
    pass
```

**Tests obligatoires:**
1. Déterminisme: même entrée → même sortie
2. Uniformité: distribution chi-squared proche de 1.0
3. Avalanche: score > 0.4 pour bonnes fonctions
4. Collision: démonstration du birthday paradox
5. Benchmark: temps < 100ns par hash pour djb2/FNV-1a

---

### Exercice A2 : `universal_perfect_hashing` (Couvre 1.2.3.a-g, 1.2.4.a-h = 15 concepts)

**Concepts couverts:**
- [1.2.3.a-g] Universal Hashing - Famille de fonctions, propriétés, construction
- [1.2.4.a-h] Perfect Hashing - FKS scheme, two-level, minimal perfect

**Description:**
Implémenter le hashing universel et le perfect hashing.

**Rust:**
```rust
// src/lib.rs
use rand::Rng;

/// Universal hash family: h_{a,b}(x) = ((ax + b) mod p) mod m
pub struct UniversalHashFamily {
    p: u64,  // Prime > universe size
    m: u64,  // Table size
}

impl UniversalHashFamily {
    pub fn new(p: u64, m: u64) -> Self;

    /// Generate random hash function from family
    pub fn generate(&self) -> UniversalHash;

    /// Probability of collision for any two distinct keys
    pub fn collision_probability(&self) -> f64;
}

pub struct UniversalHash {
    a: u64,
    b: u64,
    p: u64,
    m: u64,
}

impl UniversalHash {
    pub fn hash(&self, x: u64) -> u64 {
        (((self.a.wrapping_mul(x).wrapping_add(self.b)) % self.p) % self.m)
    }
}

/// Perfect Hash Table using FKS scheme
pub struct PerfectHashTable<V> {
    primary_table: Vec<Option<SecondaryTable<V>>>,
    primary_hash: UniversalHash,
}

struct SecondaryTable<V> {
    entries: Vec<Option<(u64, V)>>,
    hash: UniversalHash,
}

impl<V: Clone> PerfectHashTable<V> {
    /// Build perfect hash table from keys (static set)
    pub fn build(entries: &[(u64, V)]) -> Self;

    /// O(1) worst-case lookup
    pub fn get(&self, key: u64) -> Option<&V>;

    /// Space used
    pub fn space_usage(&self) -> usize;
}

/// Minimal Perfect Hash Function (maps n keys to [0, n-1])
pub struct MinimalPerfectHash {
    // CHD algorithm or similar
}

impl MinimalPerfectHash {
    pub fn build(keys: &[u64]) -> Self;
    pub fn hash(&self, key: u64) -> usize;
}
```

**Python:**
```python
# universal_perfect_hashing.py
import random
from typing import TypeVar, Generic, Optional, List, Tuple

V = TypeVar('V')

class UniversalHashFamily:
    """Famille de fonctions de hashing universelles"""

    def __init__(self, p: int, m: int):
        """
        p: nombre premier > taille de l'univers
        m: taille de la table
        """
        self.p = p
        self.m = m

    def generate(self) -> 'UniversalHash':
        """Génère une fonction aléatoire de la famille"""
        a = random.randint(1, self.p - 1)
        b = random.randint(0, self.p - 1)
        return UniversalHash(a, b, self.p, self.m)

    def collision_probability(self) -> float:
        """Probabilité de collision ≤ 1/m"""
        return 1.0 / self.m

class UniversalHash:
    """h_{a,b}(x) = ((ax + b) mod p) mod m"""

    def __init__(self, a: int, b: int, p: int, m: int):
        self.a = a
        self.b = b
        self.p = p
        self.m = m

    def __call__(self, x: int) -> int:
        return ((self.a * x + self.b) % self.p) % self.m

class PerfectHashTable(Generic[V]):
    """Table de hashing parfait (FKS scheme)"""

    def __init__(self, entries: list[tuple[int, V]]):
        """Construit la table à partir d'entrées statiques"""
        pass

    def get(self, key: int) -> Optional[V]:
        """Recherche en O(1) pire cas"""
        pass

    def space_usage(self) -> int:
        """Espace utilisé en O(n)"""
        pass

class MinimalPerfectHash:
    """Fonction de hashing parfait minimal"""

    def __init__(self, keys: list[int]):
        """Construit MPHF pour l'ensemble de clés"""
        pass

    def __call__(self, key: int) -> int:
        """Retourne index dans [0, n-1]"""
        pass
```

---

## SÉRIE B : Tables de Hachage (48 concepts)

### Exercice B1 : `hash_table_chaining` (Couvre 1.2.5.a-k = 11 concepts)

**Concepts couverts:**
- [1.2.5.a-k] Chaining - Principe, structure, opérations, load factor, analyse

**Rust:**
```rust
// src/lib.rs
use std::collections::LinkedList;

pub struct HashTableChaining<K: Hash + Eq, V> {
    buckets: Vec<LinkedList<(K, V)>>,
    size: usize,
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> HashTableChaining<K, V> {
    pub fn new() -> Self;
    pub fn with_capacity(capacity: usize) -> Self;

    pub fn insert(&mut self, key: K, value: V) -> Option<V>;
    pub fn get(&self, key: &K) -> Option<&V>;
    pub fn remove(&mut self, key: &K) -> Option<V>;
    pub fn contains(&self, key: &K) -> bool;

    pub fn len(&self) -> usize;
    pub fn load_factor(&self) -> f64;
    pub fn resize(&mut self, new_capacity: usize);

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)>;
    pub fn statistics(&self) -> ChainStats;
}

pub struct ChainStats {
    pub bucket_count: usize,
    pub non_empty_buckets: usize,
    pub max_chain_length: usize,
    pub avg_chain_length: f64,
}
```

---

### Exercice B2 : `hash_table_open_addressing` (Couvre 1.2.6.a-l = 12 concepts)

**Concepts couverts:**
- [1.2.6.a-l] Open Addressing - Linear, quadratic, double hashing, tombstones

**Rust:**
```rust
// src/lib.rs

#[derive(Clone)]
enum Slot<K, V> {
    Empty,
    Occupied(K, V),
    Deleted,  // Tombstone
}

pub struct HashTableOpenAddressing<K: Hash + Eq, V> {
    slots: Vec<Slot<K, V>>,
    size: usize,
    deleted_count: usize,
    probing: ProbingStrategy,
}

pub enum ProbingStrategy {
    Linear,
    Quadratic,
    DoubleHashing,
}

impl<K: Hash + Eq + Clone, V: Clone> HashTableOpenAddressing<K, V> {
    pub fn new(strategy: ProbingStrategy) -> Self;

    pub fn insert(&mut self, key: K, value: V) -> Option<V>;
    pub fn get(&self, key: &K) -> Option<&V>;
    pub fn remove(&mut self, key: &K) -> Option<V>;

    pub fn load_factor(&self) -> f64;
    pub fn effective_load_factor(&self) -> f64;  // Compte les tombstones

    // Rehash quand trop de tombstones
    pub fn rehash(&mut self);
}
```

---

### Exercice B3 : `hash_table_advanced` (Couvre 1.2.7.a-k = 11 concepts)

**Concepts couverts:**
- [1.2.7.a-k] Advanced schemes - Cuckoo, Robin Hood, Hopscotch, Linear hashing

**Rust:**
```rust
// src/lib.rs

/// Cuckoo hashing with two tables
pub struct CuckooHashTable<K: Hash + Eq, V> {
    table1: Vec<Option<(K, V)>>,
    table2: Vec<Option<(K, V)>>,
    hash1: Box<dyn Fn(&K) -> usize>,
    hash2: Box<dyn Fn(&K) -> usize>,
    size: usize,
    max_kicks: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> CuckooHashTable<K, V> {
    pub fn new(capacity: usize) -> Self;
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, InsertError>;
    pub fn get(&self, key: &K) -> Option<&V>;  // O(1) worst case!
    pub fn remove(&mut self, key: &K) -> Option<V>;
}

/// Robin Hood hashing
pub struct RobinHoodHashTable<K: Hash + Eq, V> {
    slots: Vec<Option<(K, V, usize)>>,  // (key, value, probe_distance)
    size: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> RobinHoodHashTable<K, V> {
    pub fn new(capacity: usize) -> Self;
    pub fn insert(&mut self, key: K, value: V) -> Option<V>;
    pub fn get(&self, key: &K) -> Option<&V>;
    pub fn remove(&mut self, key: &K) -> Option<V>;
    pub fn variance(&self) -> f64;  // Should be low
}
```

---

### Exercice B4 : `hash_table_complete` (Couvre 1.2.8.a-n = 14 concepts)

**Concepts couverts:**
- [1.2.8.a-n] Implementation complète - Structure, états, toutes opérations, resize, iterator

**Description:**
Implémenter une hash table complète production-ready.

**Rust:**
```rust
// src/lib.rs

pub struct HashMap<K, V> {
    buckets: Box<[Option<Bucket<K, V>>]>,
    size: usize,
    capacity: usize,
    load_threshold: f64,
}

struct Bucket<K, V> {
    key: K,
    value: V,
    hash: u64,
}

impl<K: Hash + Eq, V> HashMap<K, V> {
    // Constructors
    pub fn new() -> Self;
    pub fn with_capacity(capacity: usize) -> Self;
    pub fn with_capacity_and_hasher(capacity: usize, hasher: impl Hasher) -> Self;

    // Core operations
    pub fn insert(&mut self, key: K, value: V) -> Option<V>;
    pub fn get(&self, key: &K) -> Option<&V>;
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V>;
    pub fn remove(&mut self, key: &K) -> Option<V>;
    pub fn contains_key(&self, key: &K) -> bool;

    // Entry API
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V>;

    // Bulk operations
    pub fn clear(&mut self);
    pub fn retain<F>(&mut self, f: F) where F: FnMut(&K, &mut V) -> bool;

    // Capacity
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn capacity(&self) -> usize;
    pub fn reserve(&mut self, additional: usize);
    pub fn shrink_to_fit(&mut self);

    // Iteration
    pub fn keys(&self) -> impl Iterator<Item = &K>;
    pub fn values(&self) -> impl Iterator<Item = &V>;
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)>;
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)>;

    // Statistics
    pub fn statistics(&self) -> HashMapStats;
}

pub enum Entry<'a, K, V> {
    Occupied(OccupiedEntry<'a, K, V>),
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K, V> Entry<'a, K, V> {
    pub fn or_insert(self, default: V) -> &'a mut V;
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V;
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Self;
}

pub struct HashMapStats {
    pub size: usize,
    pub capacity: usize,
    pub load_factor: f64,
    pub collisions: usize,
    pub max_probe_length: usize,
    pub avg_probe_length: f64,
}

// Implement standard traits
impl<K, V> Default for HashMap<K, V> { ... }
impl<K, V> Clone for HashMap<K, V> where K: Clone, V: Clone { ... }
impl<K, V> Drop for HashMap<K, V> { ... }
impl<K: Eq + Hash, V> FromIterator<(K, V)> for HashMap<K, V> { ... }
impl<K: Eq + Hash, V> Index<&K> for HashMap<K, V> { ... }
```

**Python:**
```python
# hash_table_complete.py
from typing import TypeVar, Generic, Optional, Iterator, Callable
from dataclasses import dataclass

K = TypeVar('K')
V = TypeVar('V')

@dataclass
class HashMapStats:
    size: int
    capacity: int
    load_factor: float
    collisions: int
    max_probe_length: int
    avg_probe_length: float

class HashMap(Generic[K, V]):
    """Hash table complète production-ready"""

    def __init__(self, capacity: int = 16, load_threshold: float = 0.75):
        pass

    # Core operations
    def __setitem__(self, key: K, value: V) -> None:
        pass

    def __getitem__(self, key: K) -> V:
        pass

    def __delitem__(self, key: K) -> None:
        pass

    def __contains__(self, key: K) -> bool:
        pass

    def get(self, key: K, default: V = None) -> Optional[V]:
        pass

    def pop(self, key: K, default: V = None) -> Optional[V]:
        pass

    def setdefault(self, key: K, default: V) -> V:
        pass

    def update(self, other: dict[K, V]) -> None:
        pass

    # Capacity
    def __len__(self) -> int:
        pass

    def clear(self) -> None:
        pass

    # Iteration
    def keys(self) -> Iterator[K]:
        pass

    def values(self) -> Iterator[V]:
        pass

    def items(self) -> Iterator[tuple[K, V]]:
        pass

    def __iter__(self) -> Iterator[K]:
        pass

    # Statistics
    def statistics(self) -> HashMapStats:
        pass
```

---

## SÉRIE C : Structures Probabilistes (14 concepts)

### Exercice C1 : `probabilistic_structures` (Couvre 1.2.9.a-n = 14 concepts)

**Concepts couverts:**
- [1.2.9.a-g] Bloom Filter - Structure, insert, query, false positives, counting
- [1.2.9.h-k] Count-Min Sketch - Structure, update, query
- [1.2.9.l-n] HyperLogLog - Cardinality estimation

**Rust:**
```rust
// src/lib.rs
use bit_vec::BitVec;

/// Bloom Filter for membership testing
pub struct BloomFilter {
    bits: BitVec,
    num_hashes: usize,
    size: usize,
}

impl BloomFilter {
    /// Create with expected items and false positive rate
    pub fn new(expected_items: usize, fp_rate: f64) -> Self;

    /// Optimal number of hash functions: k = (m/n) * ln(2)
    pub fn optimal_hash_count(bits: usize, items: usize) -> usize;

    pub fn insert(&mut self, item: &[u8]);
    pub fn contains(&self, item: &[u8]) -> bool;  // May have false positives
    pub fn false_positive_rate(&self) -> f64;

    // Union of two bloom filters
    pub fn union(&self, other: &BloomFilter) -> Option<BloomFilter>;
}

/// Counting Bloom Filter (supports deletion)
pub struct CountingBloomFilter {
    counters: Vec<u8>,
    num_hashes: usize,
}

impl CountingBloomFilter {
    pub fn new(size: usize, num_hashes: usize) -> Self;
    pub fn insert(&mut self, item: &[u8]);
    pub fn remove(&mut self, item: &[u8]) -> bool;
    pub fn contains(&self, item: &[u8]) -> bool;
}

/// Count-Min Sketch for frequency estimation
pub struct CountMinSketch {
    table: Vec<Vec<u32>>,
    width: usize,
    depth: usize,
}

impl CountMinSketch {
    /// Create with error bound ε and probability δ
    pub fn new(epsilon: f64, delta: f64) -> Self;

    pub fn update(&mut self, item: &[u8], count: i32);
    pub fn estimate(&self, item: &[u8]) -> u32;  // May overestimate
}

/// HyperLogLog for cardinality estimation
pub struct HyperLogLog {
    registers: Vec<u8>,
    precision: usize,  // Number of bits for bucket index
}

impl HyperLogLog {
    pub fn new(precision: usize) -> Self;  // 2^precision buckets

    pub fn add(&mut self, item: &[u8]);
    pub fn cardinality(&self) -> f64;  // Estimated unique count
    pub fn merge(&mut self, other: &HyperLogLog);
    pub fn relative_error(&self) -> f64;  // ≈ 1.04/√m
}
```

**Python:**
```python
# probabilistic_structures.py
import math
import mmh3  # MurmurHash3
from typing import List

class BloomFilter:
    """Filtre de Bloom pour test d'appartenance"""

    def __init__(self, expected_items: int, fp_rate: float = 0.01):
        # Taille optimale: m = -n*ln(p) / (ln(2))²
        self.size = int(-expected_items * math.log(fp_rate) / (math.log(2) ** 2))
        # Nombre de hash optimal: k = (m/n) * ln(2)
        self.num_hashes = int((self.size / expected_items) * math.log(2))
        self.bits = [False] * self.size

    def _hashes(self, item: bytes) -> list[int]:
        """Génère k hash différents"""
        return [mmh3.hash(item, seed=i) % self.size for i in range(self.num_hashes)]

    def insert(self, item: bytes) -> None:
        for h in self._hashes(item):
            self.bits[h] = True

    def contains(self, item: bytes) -> bool:
        return all(self.bits[h] for h in self._hashes(item))

    def false_positive_rate(self) -> float:
        ones = sum(self.bits)
        return (ones / self.size) ** self.num_hashes

class CountMinSketch:
    """Count-Min Sketch pour estimation de fréquence"""

    def __init__(self, epsilon: float = 0.01, delta: float = 0.01):
        # Width: e/ε, Depth: ln(1/δ)
        self.width = int(math.e / epsilon)
        self.depth = int(math.log(1 / delta))
        self.table = [[0] * self.width for _ in range(self.depth)]

    def update(self, item: bytes, count: int = 1) -> None:
        for i in range(self.depth):
            j = mmh3.hash(item, seed=i) % self.width
            self.table[i][j] += count

    def estimate(self, item: bytes) -> int:
        return min(
            self.table[i][mmh3.hash(item, seed=i) % self.width]
            for i in range(self.depth)
        )

class HyperLogLog:
    """HyperLogLog pour estimation de cardinalité"""

    def __init__(self, precision: int = 14):
        self.precision = precision
        self.m = 1 << precision  # 2^precision registers
        self.registers = [0] * self.m
        self.alpha = self._compute_alpha()

    def _compute_alpha(self) -> float:
        if self.m == 16:
            return 0.673
        elif self.m == 32:
            return 0.697
        elif self.m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item: bytes) -> None:
        h = mmh3.hash64(item)[0] & 0xFFFFFFFFFFFFFFFF
        # First p bits for bucket index
        bucket = h >> (64 - self.precision)
        # Remaining bits: count leading zeros + 1
        w = h & ((1 << (64 - self.precision)) - 1)
        self.registers[bucket] = max(
            self.registers[bucket],
            self._count_leading_zeros(w) + 1
        )

    def _count_leading_zeros(self, x: int) -> int:
        if x == 0:
            return 64 - self.precision
        count = 0
        while (x & (1 << (63 - self.precision - count))) == 0:
            count += 1
        return count

    def cardinality(self) -> float:
        # Harmonic mean
        z = 1.0 / sum(2.0 ** (-r) for r in self.registers)
        e = self.alpha * self.m * self.m * z

        # Small/large range corrections
        if e <= 2.5 * self.m:
            # Small range correction
            zeros = self.registers.count(0)
            if zeros > 0:
                return self.m * math.log(self.m / zeros)
        elif e > (1 << 32) / 30:
            # Large range correction
            return -(1 << 32) * math.log(1 - e / (1 << 32))

        return e

    def relative_error(self) -> float:
        return 1.04 / math.sqrt(self.m)
```

---

## SÉRIE D : String Matching Algorithms (64 concepts)

### Exercice D1 : `string_basics` (Couvre 1.2.10.a-h, 1.2.11.a-f = 14 concepts)

**Concepts:** Représentation, encodings, rolling hash, naive matching

### Exercice D2 : `kmp_algorithm` (Couvre 1.2.12.a-j = 10 concepts)

**Concepts:** KMP avec failure function, construction, recherche

### Exercice D3 : `z_algorithm` (Couvre 1.2.13.a-i = 9 concepts)

**Concepts:** Z-array, Z-box, pattern matching avec Z

### Exercice D4 : `rabin_karp` (Couvre 1.2.14.a-i = 9 concepts)

**Concepts:** Rolling hash, multiple patterns, 2D matching

### Exercice D5 : `boyer_moore` (Couvre 1.2.15.a-k = 11 concepts)

**Concepts:** Bad character rule, good suffix rule

### Exercice D6 : `aho_corasick` (Couvre 1.2.16.a-i = 9 concepts)

**Concepts:** Multi-pattern matching avec automaton

### Exercice D7 : `manacher` (Couvre 1.2.17.a-i = 9 concepts)

**Concepts:** Longest palindromic substring en O(n)

---

## SÉRIE E : Structures de Strings (49 concepts)

### Exercice E1 : `trie_complete` (Couvre 1.2.18.a-l = 12 concepts)

**Concepts:** Trie avec insert, search, delete, prefix operations, compressed trie

**Rust:**
```rust
// src/lib.rs
use std::collections::HashMap;

pub struct TrieNode {
    children: HashMap<char, TrieNode>,
    is_end: bool,
    word_count: usize,
    prefix_count: usize,
}

pub struct Trie {
    root: TrieNode,
}

impl Trie {
    pub fn new() -> Self;

    pub fn insert(&mut self, word: &str);
    pub fn search(&self, word: &str) -> bool;
    pub fn starts_with(&self, prefix: &str) -> bool;
    pub fn delete(&mut self, word: &str) -> bool;

    pub fn count_words_with_prefix(&self, prefix: &str) -> usize;
    pub fn words_with_prefix(&self, prefix: &str) -> Vec<String>;
    pub fn autocomplete(&self, prefix: &str, limit: usize) -> Vec<String>;

    pub fn longest_common_prefix(&self) -> String;
}

/// Compressed Trie (Radix Tree)
pub struct RadixTree {
    root: RadixNode,
}

struct RadixNode {
    children: HashMap<String, RadixNode>,  // Edge labels are strings
    is_end: bool,
}

impl RadixTree {
    pub fn new() -> Self;
    pub fn insert(&mut self, word: &str);
    pub fn search(&self, word: &str) -> bool;
    pub fn space_usage(&self) -> usize;
}
```

### Exercice E2 : `suffix_array` (Couvre 1.2.19.a-k = 11 concepts)

**Concepts:** Construction O(n log n), LCP array, pattern matching

**Rust:**
```rust
// src/lib.rs

pub struct SuffixArray {
    sa: Vec<usize>,
    lcp: Vec<usize>,
    text: String,
}

impl SuffixArray {
    /// Construction O(n log² n) with doubling
    pub fn build(text: &str) -> Self;

    /// Construction O(n log n) with radix sort
    pub fn build_fast(text: &str) -> Self;

    /// Get suffix array
    pub fn suffix_array(&self) -> &[usize];

    /// Build LCP array using Kasai's algorithm O(n)
    pub fn build_lcp(&mut self);

    /// Pattern matching using binary search O(m log n)
    pub fn find_all(&self, pattern: &str) -> Vec<usize>;

    /// Longest repeated substring using LCP
    pub fn longest_repeated_substring(&self) -> &str;

    /// Number of distinct substrings
    pub fn distinct_substrings(&self) -> usize;
}
```

### Exercice E3 : `suffix_tree` (Couvre 1.2.20.a-k = 11 concepts)

**Concepts:** Ukkonen's algorithm, LCS, longest repeated substring

### Exercice E4 : `suffix_automaton` (Couvre 1.2.21.a-i = 9 concepts)

**Concepts:** Construction, applications

---

## SÉRIE F : Projet Intégrateur (50 concepts)

### Exercice F1 : `text_search_engine` (Projet couvrant 1.2.PROJET, 1.2.LeetCode, 1.2.Tests)

**Concepts couverts: 36**
- PROJET (1.2.a-n): 14 concepts
- LeetCode (1.2.LeetCode.a-o): 15 concepts
- Tests (1.2.Tests.a-g): 7 concepts

**Description:**
Moteur de recherche textuel complet avec:
- Index inversé basé sur hash table
- Trie pour autocomplétion
- Pattern matching (KMP, Boyer-Moore)
- Fuzzy search avec edit distance
- Wildcard et phrase search
- Ranking TF-IDF
- CLI et benchmarks

---

## Récapitulatif de Couverture Module 1.2

| Série | Exercices | Concepts couverts |
|-------|-----------|-------------------|
| A | 2 | 36 (1.2.1-4) |
| B | 4 | 48 (1.2.5-8) |
| C | 1 | 14 (1.2.9) |
| D | 7 | 64 (1.2.10-17) |
| E | 4 | 43 (1.2.18-21) |
| F | 1 | 36 (1.2.PROJET, LeetCode, Tests) |
| **TOTAL** | **19** | **254** |

---
