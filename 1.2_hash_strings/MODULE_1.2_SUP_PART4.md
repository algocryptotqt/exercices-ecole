# MODULE 1.2 - EXERCICES SUPPLÉMENTAIRES (Partie 4/5)
## String Matching: KMP, Z-Algorithm, Rabin-Karp, Boyer-Moore

---

## Exercice SUP-10: `kmp_algorithm`
**Couvre: 1.2.12.b-g (6 concepts)**

### Concepts
- [1.2.12.b] Failure function π — Préfixe = suffixe
- [1.2.12.c] π[i] définition — Plus long préfixe propre = suffixe
- [1.2.12.d] Construction π — O(m)
- [1.2.12.e] Search — O(n)
- [1.2.12.f] Complexité — O(n + m) total
- [1.2.12.g] All occurrences — Continuer après match

### Rust
```rust
/// [1.2.12.b, 1.2.12.c] Failure Function (π)
/// π[i] = longueur du plus long préfixe propre de pattern[0..=i] qui est aussi suffixe

/// [1.2.12.d] Construction de π en O(m)
pub fn compute_failure_function(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    let mut pi = vec![0; m];
    
    let mut k = 0;  // Longueur du préfixe courant
    
    for i in 1..m {
        // Reculer jusqu'à trouver un match ou k = 0
        while k > 0 && pattern[k] != pattern[i] {
            k = pi[k - 1];
        }
        
        if pattern[k] == pattern[i] {
            k += 1;
        }
        
        pi[i] = k;
    }
    
    pi
}

/// [1.2.12.e, 1.2.12.g] KMP Search - O(n)
pub fn kmp_search(text: &str, pattern: &str) -> Vec<usize> {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m == 0 || m > n {
        return vec![];
    }
    
    let pi = compute_failure_function(pattern);
    let mut matches = Vec::new();
    let mut j = 0;  // Index dans pattern
    
    for i in 0..n {
        // Utiliser π pour éviter les comparaisons redondantes
        while j > 0 && pattern[j] != text[i] {
            j = pi[j - 1];
        }
        
        if pattern[j] == text[i] {
            j += 1;
        }
        
        if j == m {
            matches.push(i - m + 1);
            // [1.2.12.g] Continuer pour trouver toutes les occurrences
            j = pi[j - 1];
        }
    }
    
    matches
}

/// [1.2.12.f] Analyse de complexité
pub fn complexity_analysis() -> &'static str {
    "
    Construction π: O(m)
    - Chaque caractère visité au plus 2 fois
    
    Recherche: O(n)
    - i avance toujours
    - j peut reculer, mais total des reculs ≤ total des avances
    
    Total: O(n + m)
    
    Avantage sur naïf:
    - Ne revient jamais en arrière dans le texte
    - Utilise l'information du pattern pour sauter
    "
}

/// Exemple détaillé de π
pub fn failure_function_example() {
    let pattern = "ABABAC";
    let pi = compute_failure_function(pattern.as_bytes());
    
    // pattern: A B A B A C
    // index:   0 1 2 3 4 5
    // π:       0 0 1 2 3 0
    
    // π[0] = 0 (par définition)
    // π[1] = 0 ("AB" - pas de préfixe propre = suffixe)
    // π[2] = 1 ("ABA" - "A" est préfixe et suffixe)
    // π[3] = 2 ("ABAB" - "AB" est préfixe et suffixe)
    // π[4] = 3 ("ABABA" - "ABA" est préfixe et suffixe)
    // π[5] = 0 ("ABABAC" - pas de match)
}
```

---

## Exercice SUP-11: `z_algorithm`
**Couvre: 1.2.13.b-f (5 concepts)**

### Concepts
- [1.2.13.b] Z-box — Intervalle [l, r] avec matching préfixe
- [1.2.13.c] Algorithme — Construction Z-array en O(n)
- [1.2.13.d] Pattern matching — Concat pattern + "$" + text
- [1.2.13.e] Complexité — O(n + m)
- [1.2.13.f] Applications — LCP, string compression

### Rust
```rust
/// [1.2.13.b, 1.2.13.c] Z-Algorithm
/// Z[i] = longueur du plus long préfixe de s qui commence à position i
pub fn compute_z_array(s: &[u8]) -> Vec<usize> {
    let n = s.len();
    let mut z = vec![0; n];
    
    // [1.2.13.b] Z-box [l, r]: intervalle avec z[l] = r - l + 1
    let mut l = 0;
    let mut r = 0;
    
    for i in 1..n {
        if i < r {
            // On est dans la Z-box, on peut réutiliser l'info
            z[i] = (r - i).min(z[i - l]);
        }
        
        // Étendre naïvement si nécessaire
        while i + z[i] < n && s[z[i]] == s[i + z[i]] {
            z[i] += 1;
        }
        
        // Mettre à jour la Z-box si on a trouvé un meilleur intervalle
        if i + z[i] > r {
            l = i;
            r = i + z[i];
        }
    }
    
    z[0] = n;  // Par convention
    z
}

/// [1.2.13.d] Pattern matching avec Z-algorithm
pub fn z_search(text: &str, pattern: &str) -> Vec<usize> {
    if pattern.is_empty() {
        return vec![];
    }
    
    // Concaténer: pattern + "$" + text
    let combined = format!("{}${}", pattern, text);
    let z = compute_z_array(combined.as_bytes());
    
    let m = pattern.len();
    let mut matches = Vec::new();
    
    // Les positions où Z[i] == m sont des matches
    for (i, &zi) in z.iter().enumerate().skip(m + 1) {
        if zi == m {
            matches.push(i - m - 1);  // Position dans le texte original
        }
    }
    
    matches
}

/// [1.2.13.e] Complexité
pub fn complexity_analysis() -> &'static str {
    "
    Construction Z-array: O(n)
    - r ne fait qu'augmenter
    - Chaque caractère comparé au plus une fois naïvement
    
    Pattern matching: O(n + m)
    - Construction de la string combinée: O(n + m)
    - Z-array: O(n + m)
    "
}

/// [1.2.13.f] Applications du Z-algorithm
pub fn applications() {
    // 1. Pattern matching (vu ci-dessus)
    
    // 2. Plus petite période d'une string
    fn smallest_period(s: &str) -> usize {
        let z = compute_z_array(s.as_bytes());
        let n = s.len();
        
        for i in 1..n {
            if i + z[i] == n && n % i == 0 {
                return i;
            }
        }
        n
    }
    
    // 3. Nombre de sous-strings distinctes
    // (utilise Z-array sur chaque suffixe)
    
    // 4. String compression
    // "abcabcabc" -> "abc" répété 3 fois
}
```

---

## Exercice SUP-12: `rabin_karp`
**Couvre: 1.2.14.b-f (5 concepts)**

### Concepts
- [1.2.14.b] Rolling hash — Mise à jour O(1)
- [1.2.14.c] Polynomial hash — h = Σ s[i] × b^i mod m
- [1.2.14.d] Spurious hits — Faux positifs hash
- [1.2.14.e] Complexité — O(n + m) moyen, O(nm) pire
- [1.2.14.f] Multiple patterns — Efficace avec set de hashes

### Rust
```rust
/// [1.2.14.c] Polynomial Rolling Hash
pub struct RollingHash {
    base: u64,
    modulus: u64,
    hash: u64,
    base_pow: u64,  // base^(window_size-1) mod modulus
    window_size: usize,
}

impl RollingHash {
    pub fn new(base: u64, modulus: u64) -> Self {
        Self {
            base,
            modulus,
            hash: 0,
            base_pow: 1,
            window_size: 0,
        }
    }
    
    /// Initialiser avec une fenêtre
    pub fn init(&mut self, window: &[u8]) {
        self.hash = 0;
        self.base_pow = 1;
        self.window_size = window.len();
        
        for (i, &c) in window.iter().enumerate() {
            self.hash = (self.hash * self.base + c as u64) % self.modulus;
            if i < window.len() - 1 {
                self.base_pow = (self.base_pow * self.base) % self.modulus;
            }
        }
    }
    
    /// [1.2.14.b] Rolling update: remove old char, add new char - O(1)
    pub fn roll(&mut self, old_char: u8, new_char: u8) {
        // Remove contribution of old_char
        let old_contrib = (old_char as u64 * self.base_pow) % self.modulus;
        self.hash = (self.hash + self.modulus - old_contrib) % self.modulus;
        
        // Shift and add new_char
        self.hash = (self.hash * self.base + new_char as u64) % self.modulus;
    }
    
    pub fn value(&self) -> u64 {
        self.hash
    }
}

/// Rabin-Karp Search
pub fn rabin_karp(text: &str, pattern: &str) -> Vec<usize> {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m > n || m == 0 {
        return vec![];
    }
    
    const BASE: u64 = 256;
    const MOD: u64 = 1_000_000_007;
    
    // Hash du pattern
    let mut pattern_hash = RollingHash::new(BASE, MOD);
    pattern_hash.init(pattern);
    let target_hash = pattern_hash.value();
    
    // Hash de la première fenêtre du texte
    let mut text_hash = RollingHash::new(BASE, MOD);
    text_hash.init(&text[..m]);
    
    let mut matches = Vec::new();
    
    for i in 0..=(n - m) {
        if text_hash.value() == target_hash {
            // [1.2.14.d] Spurious hit: vérifier caractère par caractère
            if &text[i..i + m] == pattern {
                matches.push(i);
            }
        }
        
        if i + m < n {
            text_hash.roll(text[i], text[i + m]);
        }
    }
    
    matches
}

/// [1.2.14.e] Complexité
pub fn complexity_analysis() -> &'static str {
    "
    Preprocessing: O(m)
    
    Recherche:
    - Meilleur/Moyen: O(n + m) - peu de spurious hits
    - Pire: O(nm) - beaucoup de spurious hits (hash identiques)
    
    Avec bon choix de base et modulus:
    - Probabilité de collision ≈ 1/modulus
    - En pratique quasi-linéaire
    "
}

/// [1.2.14.f] Multiple patterns - efficace avec Rabin-Karp
pub fn rabin_karp_multi(text: &str, patterns: &[&str]) -> Vec<(usize, usize)> {
    use std::collections::HashSet;
    
    // Group patterns by length
    let mut by_length: std::collections::HashMap<usize, Vec<(usize, u64)>> = 
        std::collections::HashMap::new();
    
    const BASE: u64 = 256;
    const MOD: u64 = 1_000_000_007;
    
    for (idx, pattern) in patterns.iter().enumerate() {
        let mut h = RollingHash::new(BASE, MOD);
        h.init(pattern.as_bytes());
        by_length.entry(pattern.len())
            .or_default()
            .push((idx, h.value()));
    }
    
    let text = text.as_bytes();
    let n = text.len();
    let mut matches = Vec::new();
    
    // Pour chaque longueur de pattern
    for (&m, pattern_hashes) in &by_length {
        if m > n { continue; }
        
        let hash_set: HashSet<u64> = pattern_hashes.iter().map(|&(_, h)| h).collect();
        
        let mut text_hash = RollingHash::new(BASE, MOD);
        text_hash.init(&text[..m]);
        
        for i in 0..=(n - m) {
            if hash_set.contains(&text_hash.value()) {
                // Vérifier quel pattern
                for &(idx, h) in pattern_hashes {
                    if text_hash.value() == h && &text[i..i+m] == patterns[idx].as_bytes() {
                        matches.push((i, idx));
                    }
                }
            }
            
            if i + m < n {
                text_hash.roll(text[i], text[i + m]);
            }
        }
    }
    
    matches
}
```

---

## Exercice SUP-13: `boyer_moore`
**Couvre: 1.2.15.b-f (5 concepts)**

### Concepts
- [1.2.15.b] Bad character rule — Shift basé sur mismatch char
- [1.2.15.c] Good suffix rule — Shift basé sur suffixe match
- [1.2.15.d] Complexité moyenne — O(n/m) sublinéaire!
- [1.2.15.e] Complexité pire — O(nm)
- [1.2.15.f] Meilleur pour — Alphabets larges, patterns longs

### Rust
```rust
use std::collections::HashMap;

/// [1.2.15.b] Bad Character Rule
/// Pré-calcul: pour chaque caractère, sa dernière position dans le pattern
fn compute_bad_char(pattern: &[u8]) -> HashMap<u8, usize> {
    let mut bad_char = HashMap::new();
    for (i, &c) in pattern.iter().enumerate() {
        bad_char.insert(c, i);
    }
    bad_char
}

/// [1.2.15.c] Good Suffix Rule (version simplifiée)
fn compute_good_suffix(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    let mut suffix = vec![0; m];
    let mut good_suffix = vec![m; m];
    
    // Compute suffix lengths
    suffix[m - 1] = m;
    let mut g = m - 1;
    let mut f = 0;
    
    for i in (0..m - 1).rev() {
        if i > g && suffix[i + m - 1 - f] < i - g {
            suffix[i] = suffix[i + m - 1 - f];
        } else {
            if i < g { g = i; }
            f = i;
            while g > 0 && pattern[g] == pattern[g + m - 1 - f] {
                g -= 1;
            }
            suffix[i] = f - g;
        }
    }
    
    // Compute good suffix shifts
    for i in 0..m - 1 {
        good_suffix[m - 1 - suffix[i]] = m - 1 - i;
    }
    
    for i in 0..m - 1 {
        if suffix[i] == i + 1 {
            for j in 0..m - 1 - i {
                if good_suffix[j] == m {
                    good_suffix[j] = m - 1 - i;
                }
            }
        }
    }
    
    good_suffix
}

/// Boyer-Moore Search
pub fn boyer_moore(text: &str, pattern: &str) -> Vec<usize> {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m > n || m == 0 {
        return vec![];
    }
    
    let bad_char = compute_bad_char(pattern);
    let good_suffix = compute_good_suffix(pattern);
    
    let mut matches = Vec::new();
    let mut i = 0;  // Shift in text
    
    while i <= n - m {
        let mut j = m - 1;  // Compare from right to left
        
        // Find mismatch
        while pattern[j] == text[i + j] {
            if j == 0 {
                matches.push(i);
                break;
            }
            j -= 1;
        }
        
        if j == 0 && matches.last() == Some(&i) {
            // Match found, use good suffix to shift
            i += good_suffix[0];
        } else {
            // [1.2.15.b] Bad character shift
            let bad_shift = if let Some(&pos) = bad_char.get(&text[i + j]) {
                if j > pos { j - pos } else { 1 }
            } else {
                j + 1
            };
            
            // [1.2.15.c] Good suffix shift
            let good_shift = good_suffix[j];
            
            // Take maximum of both shifts
            i += bad_shift.max(good_shift);
        }
    }
    
    matches
}

/// Boyer-Moore Horspool (version simplifiée, bad char only)
pub fn boyer_moore_horspool(text: &str, pattern: &str) -> Vec<usize> {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    
    let n = text.len();
    let m = pattern.len();
    
    if m > n || m == 0 {
        return vec![];
    }
    
    // Bad character table (skip value for each char)
    let mut skip = vec![m; 256];
    for i in 0..m - 1 {
        skip[pattern[i] as usize] = m - 1 - i;
    }
    
    let mut matches = Vec::new();
    let mut i = 0;
    
    while i <= n - m {
        let mut j = m - 1;
        
        while text[i + j] == pattern[j] {
            if j == 0 {
                matches.push(i);
                break;
            }
            j -= 1;
        }
        
        i += skip[text[i + m - 1] as usize];
    }
    
    matches
}

/// [1.2.15.d, 1.2.15.e, 1.2.15.f] Analyse
pub fn boyer_moore_analysis() -> &'static str {
    "
    Complexité moyenne: O(n/m) - SUBLINÉAIRE!
    - Saute souvent m caractères à la fois
    
    Complexité pire: O(nm)
    - Pattern = 'aaa', text = 'aaaa...aaaa'
    
    Meilleur pour:
    - Alphabets larges (plus de chances de mismatch)
    - Patterns longs (plus grands sauts)
    - Recherche dans fichiers texte (ASCII 256 chars)
    
    Moins bon pour:
    - Alphabets petits (ADN: 4 chars)
    - Patterns courts
    "
}
```

---

## RÉSUMÉ PARTIE 4

| Exercice | Concepts couverts | Total |
|----------|------------------|-------|
| SUP-10 kmp | 1.2.12.b-g | 6 |
| SUP-11 z_algorithm | 1.2.13.b-f | 5 |
| SUP-12 rabin_karp | 1.2.14.b-f | 5 |
| SUP-13 boyer_moore | 1.2.15.b-f | 5 |
| **TOTAL PARTIE 4** | | **21** |
