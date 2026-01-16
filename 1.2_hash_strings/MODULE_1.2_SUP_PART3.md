# MODULE 1.2 - EXERCICES SUPPLÉMENTAIRES (Partie 3/5)
## Bloom Filter, Strings UTF-8, Naïve Matching

---

## Exercice SUP-7: `bloom_filter_complete`
**Couvre: 1.2.9.b-j (9 concepts, sans 1.2.9.h)**

### Concepts
- [1.2.9.b] Structure — Bit array + k hash functions
- [1.2.9.c] Insert — Set k bits à 1
- [1.2.9.d] Query — Check k bits
- [1.2.9.e] False positives — Possible, false negatives impossible
- [1.2.9.f] Optimal k — k = (m/n) × ln(2)
- [1.2.9.g] Counting Bloom — Compteurs au lieu de bits
- [1.2.9.i] HyperLogLog — Estimation cardinalité
- [1.2.9.j] Crates — `bloomfilter`, `probabilistic-collections`

### Rust
```rust
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// [1.2.9.b] Structure Bloom Filter
pub struct BloomFilter {
    bits: Vec<bool>,
    num_hashes: usize,  // k
    size: usize,        // m
}

impl BloomFilter {
    /// [1.2.9.f] Création avec paramètres optimaux
    pub fn new(expected_elements: usize, false_positive_rate: f64) -> Self {
        // m = -n × ln(p) / (ln(2))²
        let m = (-(expected_elements as f64) * false_positive_rate.ln() 
                 / (2.0_f64.ln().powi(2))).ceil() as usize;
        
        // k = (m/n) × ln(2)
        let k = ((m as f64 / expected_elements as f64) * 2.0_f64.ln()).ceil() as usize;
        
        Self {
            bits: vec![false; m],
            num_hashes: k,
            size: m,
        }
    }
    
    /// Génère k hash différents pour une clé
    fn hashes<T: Hash>(&self, item: &T) -> Vec<usize> {
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        let hash1 = h1.finish();
        
        let mut h2 = DefaultHasher::new();
        (item, 0x517cc1b727220a95u64).hash(&mut h2);
        let hash2 = h2.finish();
        
        // Double hashing: h(i) = h1 + i × h2
        (0..self.num_hashes)
            .map(|i| ((hash1.wrapping_add((i as u64).wrapping_mul(hash2))) as usize) % self.size)
            .collect()
    }
    
    /// [1.2.9.c] Insertion - set k bits
    pub fn insert<T: Hash>(&mut self, item: &T) {
        for idx in self.hashes(item) {
            self.bits[idx] = true;
        }
    }
    
    /// [1.2.9.d] Query - check k bits
    /// [1.2.9.e] Peut retourner faux positif, jamais faux négatif
    pub fn might_contain<T: Hash>(&self, item: &T) -> bool {
        self.hashes(item).iter().all(|&idx| self.bits[idx])
    }
    
    /// Taux de remplissage
    pub fn fill_ratio(&self) -> f64 {
        self.bits.iter().filter(|&&b| b).count() as f64 / self.size as f64
    }
}

/// [1.2.9.g] Counting Bloom Filter - supporte la suppression
pub struct CountingBloomFilter {
    counters: Vec<u8>,
    num_hashes: usize,
    size: usize,
}

impl CountingBloomFilter {
    pub fn new(expected_elements: usize, false_positive_rate: f64) -> Self {
        let m = (-(expected_elements as f64) * false_positive_rate.ln() 
                 / (2.0_f64.ln().powi(2))).ceil() as usize;
        let k = ((m as f64 / expected_elements as f64) * 2.0_f64.ln()).ceil() as usize;
        
        Self {
            counters: vec![0; m],
            num_hashes: k,
            size: m,
        }
    }
    
    fn hashes<T: Hash>(&self, item: &T) -> Vec<usize> {
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        let hash1 = h1.finish();
        
        let mut h2 = DefaultHasher::new();
        (item, 0x517cc1b727220a95u64).hash(&mut h2);
        let hash2 = h2.finish();
        
        (0..self.num_hashes)
            .map(|i| ((hash1.wrapping_add((i as u64).wrapping_mul(hash2))) as usize) % self.size)
            .collect()
    }
    
    pub fn insert<T: Hash>(&mut self, item: &T) {
        for idx in self.hashes(item) {
            self.counters[idx] = self.counters[idx].saturating_add(1);
        }
    }
    
    /// Suppression possible avec counting bloom
    pub fn remove<T: Hash>(&mut self, item: &T) {
        for idx in self.hashes(item) {
            self.counters[idx] = self.counters[idx].saturating_sub(1);
        }
    }
    
    pub fn might_contain<T: Hash>(&self, item: &T) -> bool {
        self.hashes(item).iter().all(|&idx| self.counters[idx] > 0)
    }
}

/// [1.2.9.i] HyperLogLog - estimation de cardinalité
pub struct HyperLogLog {
    registers: Vec<u8>,
    num_registers: usize,  // m = 2^p
    p: usize,              // précision bits
}

impl HyperLogLog {
    pub fn new(precision: usize) -> Self {
        let num_registers = 1 << precision;
        Self {
            registers: vec![0; num_registers],
            num_registers,
            p: precision,
        }
    }
    
    pub fn add<T: Hash>(&mut self, item: &T) {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Premiers p bits = index du registre
        let idx = (hash >> (64 - self.p)) as usize;
        
        // Compter les zéros leading dans les bits restants
        let remaining = hash << self.p;
        let zeros = remaining.leading_zeros() as u8 + 1;
        
        self.registers[idx] = self.registers[idx].max(zeros);
    }
    
    pub fn estimate(&self) -> f64 {
        let m = self.num_registers as f64;
        
        // Moyenne harmonique des 2^register[i]
        let sum: f64 = self.registers.iter()
            .map(|&r| 2.0_f64.powi(-(r as i32)))
            .sum();
        
        let alpha = match self.num_registers {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        
        alpha * m * m / sum
    }
}

/// [1.2.9.j] Crates disponibles
pub fn available_crates() -> &'static str {
    "
    Crates Rust pour structures probabilistes:
    - `bloomfilter`: Bloom filter simple
    - `probabilistic-collections`: Bloom, Cuckoo, Count-Min
    - `hyperloglog`: HyperLogLog
    - `streaming-algorithms`: Count-Min Sketch, etc.
    "
}
```

---

## Exercice SUP-8: `strings_utf8_complete`
**Couvre: 1.2.10.b-h (7 concepts)**

### Concepts
- [1.2.10.b] `&str` — String slice, référence
- [1.2.10.c] UTF-8 encoding — Multi-byte characters
- [1.2.10.d] `char` — Unicode scalar value (4 bytes)
- [1.2.10.e] Bytes vs chars — Différentes itérations
- [1.2.10.f] Indexing — Pas d'indexation directe
- [1.2.10.g] Slicing — Doit être sur boundary UTF-8
- [1.2.10.h] `len()` — Longueur en bytes, pas chars

### Rust
```rust
pub fn strings_complete_demo() {
    // [1.2.10.b] &str - string slice (référence vers données UTF-8)
    let s: &str = "Hello, 世界!";
    
    // [1.2.10.h] len() retourne les BYTES, pas les caractères
    println!("Bytes: {}", s.len());  // 14 bytes
    println!("Chars: {}", s.chars().count());  // 10 chars
    
    // [1.2.10.c] UTF-8 encoding
    // ASCII: 1 byte, Latin: 2 bytes, CJK: 3 bytes, Emoji: 4 bytes
    let ascii = "A";      // 1 byte
    let latin = "é";      // 2 bytes
    let cjk = "世";       // 3 bytes
    let emoji = "😀";     // 4 bytes
    
    println!("ASCII '{}': {} bytes", ascii, ascii.len());
    println!("Latin '{}': {} bytes", latin, latin.len());
    println!("CJK '{}': {} bytes", cjk, cjk.len());
    println!("Emoji '{}': {} bytes", emoji, emoji.len());
    
    // [1.2.10.d] char - Unicode scalar value (toujours 4 bytes en mémoire)
    let c: char = '世';
    println!("char size: {} bytes", std::mem::size_of::<char>());  // 4
    
    // [1.2.10.e] Bytes vs Chars
    let s = "café";
    
    // Itération par bytes
    print!("Bytes: ");
    for b in s.bytes() {
        print!("{:02x} ", b);  // 63 61 66 c3 a9
    }
    println!();
    
    // Itération par chars
    print!("Chars: ");
    for c in s.chars() {
        print!("'{}' ", c);  // 'c' 'a' 'f' 'é'
    }
    println!();
    
    // char_indices - position byte + char
    for (i, c) in s.char_indices() {
        println!("Byte {}: '{}'", i, c);
    }
    
    // [1.2.10.f] Indexing - PAS d'indexation directe
    // let c = s[0];  // ERREUR! Car UTF-8 multi-byte
    
    // Alternatives:
    let first_char = s.chars().next();  // Option<char>
    let nth_char = s.chars().nth(3);    // 'é'
    
    // [1.2.10.g] Slicing - DOIT être sur boundary UTF-8
    let slice = &s[0..4];  // "café" - OK car 4 est une boundary
    println!("Slice: {}", slice);
    
    // &s[0..3] panics! - coupe 'é' en deux
    // Pour slicer safely:
    fn safe_slice(s: &str, start: usize, end: usize) -> Option<&str> {
        if s.is_char_boundary(start) && s.is_char_boundary(end) {
            Some(&s[start..end])
        } else {
            None
        }
    }
}

/// Méthodes utiles sur les strings
pub fn string_methods() {
    let s = "  Hello, World!  ";
    
    // Trimming
    let trimmed = s.trim();           // "Hello, World!"
    let left = s.trim_start();        // "Hello, World!  "
    let right = s.trim_end();         // "  Hello, World!"
    
    // Case
    let upper = s.to_uppercase();
    let lower = s.to_lowercase();
    
    // Search
    let contains = s.contains("World");
    let starts = s.starts_with("  He");
    let ends = s.ends_with("!  ");
    let find = s.find("World");  // Option<usize> - byte position
    
    // Split
    let words: Vec<&str> = s.split_whitespace().collect();
    let parts: Vec<&str> = s.split(',').collect();
    
    // Replace
    let replaced = s.replace("World", "Rust");
    
    // Parsing
    let num: i32 = "42".parse().unwrap();
    let float: f64 = "3.14".parse().unwrap();
}

/// String vs &str
pub fn string_vs_str() -> &'static str {
    "
    &str (string slice):
    - Référence vers données UTF-8
    - Taille fixe, immuable
    - Peut pointer vers: String, &'static str, ou sous-string
    
    String:
    - Possède ses données (heap allocated)
    - Taille variable, mutable
    - Vec<u8> garanti UTF-8 valide
    
    Conversion:
    - &str → String: .to_string(), .to_owned(), String::from()
    - String → &str: &s, s.as_str(), déréférencement auto
    "
}
```

---

## Exercice SUP-9: `naive_string_matching`
**Couvre: 1.2.11.b-f (5 concepts)**

### Concepts
- [1.2.11.b] Algorithme — Comparer à chaque position
- [1.2.11.c] Implémentation — Double boucle
- [1.2.11.d] Complexité pire — O(n×m)
- [1.2.11.e] Complexité meilleur — O(n)
- [1.2.11.f] std methods — `.find()`, `.matches()`

### Rust
```rust
/// [1.2.11.b, 1.2.11.c] Naïve String Matching
pub fn naive_search(text: &str, pattern: &str) -> Vec<usize> {
    let mut matches = Vec::new();
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m > n || m == 0 {
        return matches;
    }
    
    // [1.2.11.b] Essayer chaque position de départ
    for i in 0..=(n - m) {
        let mut j = 0;
        
        // Comparer caractère par caractère
        while j < m && text[i + j] == pattern[j] {
            j += 1;
        }
        
        if j == m {
            matches.push(i);
        }
    }
    
    matches
}

/// [1.2.11.d, 1.2.11.e] Analyse de complexité
pub fn complexity_analysis() -> &'static str {
    "
    Pire cas: O(n × m)
    - text = 'AAAAAAAAAB', pattern = 'AAAAB'
    - À chaque position, compare presque tout le pattern
    
    Meilleur cas: O(n)
    - Premier caractère du pattern ne match jamais
    - Ou pattern trouvé au début
    
    Cas moyen: O(n + m) pour texte aléatoire
    - Mismatch rapide en général
    "
}

/// [1.2.11.f] Méthodes std pour string matching
pub fn std_methods_demo() {
    let text = "abracadabra";
    let pattern = "abra";
    
    // find() - première occurrence
    if let Some(pos) = text.find(pattern) {
        println!("Found at position: {}", pos);  // 0
    }
    
    // rfind() - dernière occurrence
    if let Some(pos) = text.rfind(pattern) {
        println!("Last at position: {}", pos);  // 7
    }
    
    // contains() - existence
    assert!(text.contains(pattern));
    
    // matches() - iterator sur toutes les occurrences
    let count = text.matches(pattern).count();
    println!("Number of matches: {}", count);  // 2
    
    // match_indices() - positions de toutes les occurrences
    for (pos, matched) in text.match_indices(pattern) {
        println!("'{}' found at {}", matched, pos);
    }
    
    // split() - diviser par pattern
    let parts: Vec<&str> = "a,b,c".split(',').collect();
    
    // replace() - remplacer toutes les occurrences
    let replaced = text.replace("abra", "ABRA");
    println!("{}", replaced);  // "ABRAcadABRA"
    
    // replacen() - remplacer n premières occurrences
    let replaced_one = text.replacen("abra", "ABRA", 1);
    println!("{}", replaced_one);  // "ABRAcadabra"
}

/// Recherche avec wildcards (bonus)
pub fn wildcard_search(text: &str, pattern: &str) -> Vec<usize> {
    // '?' match n'importe quel caractère
    let mut matches = Vec::new();
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m > n {
        return matches;
    }
    
    'outer: for i in 0..=(n - m) {
        for j in 0..m {
            if pattern[j] != b'?' && text[i + j] != pattern[j] {
                continue 'outer;
            }
        }
        matches.push(i);
    }
    
    matches
}
```

---

## RÉSUMÉ PARTIE 3

| Exercice | Concepts couverts | Total |
|----------|------------------|-------|
| SUP-7 bloom_filter | 1.2.9.b-g, i-j | 9 |
| SUP-8 strings_utf8 | 1.2.10.b-h | 7 |
| SUP-9 naive_matching | 1.2.11.b-f | 5 |
| **TOTAL PARTIE 3** | | **21** |
