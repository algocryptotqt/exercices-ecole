# MODULE 1.1 : Arrays, Sorting & Searching
## Plan d'Exercices Couvrant les 343 Concepts

**Objectif:** Couverture complète de tous les concepts (lettres a-z) du Module 1.1
**Langages:** Rust Edition 2024 / Python 3.14
**Standard:** 95/100 minimum en qualité pédagogique

---

## SÉRIE A : Fondations Mémoire & Pointeurs (65 concepts)

### Exercice A1 : `memory_inspector` (Couvre 1.1.1.a-h, 1.1.2.a-h = 16 concepts)

**Concepts couverts:**
- [1.1.1.a] Modèle mémoire - Vue abstraite comme tableau d'octets
- [1.1.1.b] Adresses - Numérotation, taille (32-bit vs 64-bit)
- [1.1.1.c] Segments - Text, Data, BSS, Heap, Stack
- [1.1.1.d] Layout processus - Organisation mémoire d'un programme
- [1.1.1.e] Endianness - Little-endian vs Big-endian
- [1.1.1.f] Alignement - Contraintes d'alignement par type
- [1.1.1.g] Cache hierarchy - L1, L2, L3, cache lines
- [1.1.1.h] Locality - Spatial et temporal locality
- [1.1.2.a] Arithmétique pointeurs - ptr++, ptr+n, ptr1-ptr2
- [1.1.2.b] Pointeurs et tableaux - arr[i] ≡ *(arr+i)
- [1.1.2.c] Pointeurs de pointeurs - int **ptr, matrices dynamiques
- [1.1.2.d] Pointeurs vers fonctions - Callbacks, dispatch tables
- [1.1.2.e] const correctness - const int*, int* const
- [1.1.2.f] restrict keyword - Optimisation aliasing
- [1.1.2.g] Tableaux multidimensionnels - Row-major, column-major
- [1.1.2.h] VLA (C99) - Variable Length Arrays

**Description:**
Créer un outil d'inspection mémoire qui analyse et visualise la disposition mémoire d'un programme.

**Rust:**
```rust
// src/lib.rs
pub struct MemoryInspector {
    // À implémenter
}

impl MemoryInspector {
    /// Retourne les informations sur le layout mémoire d'une variable
    pub fn inspect<T>(value: &T) -> MemoryLayout;

    /// Détecte l'endianness du système
    pub fn detect_endianness() -> Endianness;

    /// Calcule l'alignement requis pour un type
    pub fn alignment_of<T>() -> usize;

    /// Simule les accès cache pour un pattern d'accès donné
    pub fn simulate_cache_access(access_pattern: &[usize], cache_config: CacheConfig) -> CacheStats;

    /// Analyse la localité d'un pattern d'accès
    pub fn analyze_locality(access_pattern: &[usize]) -> LocalityReport;
}

pub struct MemoryLayout {
    pub address: usize,
    pub size: usize,
    pub alignment: usize,
    pub segment: Segment,
}

pub enum Segment {
    Stack,
    Heap,
    Data,
    Bss,
    Text,
}

pub enum Endianness {
    Little,
    Big,
}

pub struct CacheConfig {
    pub l1_size: usize,
    pub l1_line_size: usize,
    pub l2_size: usize,
    pub l2_line_size: usize,
}

pub struct CacheStats {
    pub l1_hits: usize,
    pub l1_misses: usize,
    pub l2_hits: usize,
    pub l2_misses: usize,
}

pub struct LocalityReport {
    pub spatial_score: f64,    // 0.0 - 1.0
    pub temporal_score: f64,   // 0.0 - 1.0
    pub recommendations: Vec<String>,
}
```

**Python:**
```python
# memory_inspector.py
from dataclasses import dataclass
from enum import Enum
from typing import Any, List

class Segment(Enum):
    STACK = "stack"
    HEAP = "heap"
    DATA = "data"

class Endianness(Enum):
    LITTLE = "little"
    BIG = "big"

@dataclass
class MemoryLayout:
    address: int
    size: int
    segment: Segment

@dataclass
class CacheConfig:
    l1_size: int
    l1_line_size: int
    l2_size: int
    l2_line_size: int

@dataclass
class CacheStats:
    l1_hits: int
    l1_misses: int
    l2_hits: int
    l2_misses: int

@dataclass
class LocalityReport:
    spatial_score: float
    temporal_score: float
    recommendations: list[str]

class MemoryInspector:
    @staticmethod
    def inspect(value: Any) -> MemoryLayout:
        """Retourne les informations sur le layout mémoire"""
        pass

    @staticmethod
    def detect_endianness() -> Endianness:
        """Détecte l'endianness du système"""
        pass

    @staticmethod
    def simulate_cache_access(access_pattern: list[int], config: CacheConfig) -> CacheStats:
        """Simule les accès cache"""
        pass

    @staticmethod
    def analyze_locality(access_pattern: list[int]) -> LocalityReport:
        """Analyse la localité d'un pattern d'accès"""
        pass
```

**Tests obligatoires:**
1. Détection correcte de l'endianness
2. Calcul correct de l'alignement pour différents types
3. Simulation de cache avec patterns row-major vs column-major
4. Score de localité pour accès séquentiel vs aléatoire

**Critères moulinette:**
- Compilation sans warnings
- Tous les tests passent
- Performance: simulation cache < 100ms pour 1M accès

---

### Exercice A2 : `arena_allocator` (Couvre 1.1.3.a-h, 1.1.A.a-f = 14 concepts)

**Concepts couverts:**
- [1.1.3.a] malloc/calloc/realloc/free - Rappel et best practices
- [1.1.3.b] Memory pools - Pré-allocation pour performance
- [1.1.3.c] Arena allocators - Allocation linéaire rapide
- [1.1.3.d] Fragmentation - Interne vs externe
- [1.1.3.e] Custom allocators - Interface et implémentation
- [1.1.3.f] Memory alignment - posix_memalign, aligned_alloc
- [1.1.3.g] Valgrind mastery - Détection de fuites et erreurs
- [1.1.3.h] AddressSanitizer - Détection runtime
- [1.1.A.a] Arena structure - Conception de la structure
- [1.1.A.b] arena_alloc - Allocation dans l'arène
- [1.1.A.c] arena_reset - Réinitialisation sans libération
- [1.1.A.d] arena_destroy - Libération complète
- [1.1.A.e] Alignment - Gestion de l'alignement
- [1.1.A.f] Benchmark - Comparaison avec malloc

**Description:**
Implémenter un arena allocator complet avec gestion de l'alignement et support pour reset rapide.

**Rust:**
```rust
// src/lib.rs
use std::alloc::{alloc, dealloc, Layout};

pub struct Arena {
    // À implémenter
}

impl Arena {
    /// Crée une nouvelle arène avec la capacité spécifiée
    pub fn new(capacity: usize) -> Self;

    /// Alloue un bloc de mémoire aligné
    pub fn alloc<T>(&self) -> Option<&mut T>;

    /// Alloue un tableau
    pub fn alloc_slice<T>(&self, count: usize) -> Option<&mut [T]>;

    /// Alloue avec alignement personnalisé
    pub fn alloc_aligned(&self, size: usize, align: usize) -> Option<*mut u8>;

    /// Réinitialise l'arène (ne libère pas la mémoire)
    pub fn reset(&mut self);

    /// Retourne les statistiques d'utilisation
    pub fn stats(&self) -> ArenaStats;
}

pub struct ArenaStats {
    pub capacity: usize,
    pub used: usize,
    pub peak_usage: usize,
    pub allocation_count: usize,
    pub fragmentation_ratio: f64,
}

impl Drop for Arena {
    fn drop(&mut self) {
        // Libération propre
    }
}

// Pool allocator pour objets de taille fixe
pub struct Pool<T> {
    // À implémenter
}

impl<T> Pool<T> {
    pub fn new(capacity: usize) -> Self;
    pub fn allocate(&self) -> Option<&mut T>;
    pub fn deallocate(&self, ptr: &mut T);
    pub fn stats(&self) -> PoolStats;
}
```

**Python:**
```python
# arena_allocator.py
from dataclasses import dataclass
import ctypes
from typing import TypeVar, Generic, Optional

T = TypeVar('T')

@dataclass
class ArenaStats:
    capacity: int
    used: int
    peak_usage: int
    allocation_count: int
    fragmentation_ratio: float

class Arena:
    def __init__(self, capacity: int):
        """Crée une nouvelle arène"""
        pass

    def alloc(self, size: int, align: int = 8) -> Optional[int]:
        """Alloue un bloc de mémoire, retourne l'offset"""
        pass

    def reset(self) -> None:
        """Réinitialise l'arène"""
        pass

    def stats(self) -> ArenaStats:
        """Retourne les statistiques"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        """Libération automatique"""
        pass

class Pool(Generic[T]):
    def __init__(self, item_size: int, capacity: int):
        pass

    def allocate(self) -> Optional[int]:
        pass

    def deallocate(self, index: int) -> None:
        pass
```

**Tests obligatoires:**
1. Allocation et désallocation correctes
2. Alignement respecté pour tous les types
3. Reset préserve la capacité mais libère l'usage
4. Pas de fuites mémoire (Valgrind clean)
5. Performance: 10x plus rapide que malloc pour petites allocations

---

## SÉRIE B : Analyse de Complexité (53 concepts)

### Exercice B1 : `complexity_analyzer` (Couvre 1.1.4.a-h, 1.1.5.a-n = 22 concepts)

**Concepts couverts:**
- [1.1.4.a] Motivation - Pourquoi analyser la complexité
- [1.1.4.b] Croissance asymptotique - Comportement quand n → ∞
- [1.1.4.c] Big-O définition - Borne supérieure
- [1.1.4.d] Big-Ω définition - Borne inférieure
- [1.1.4.e] Big-Θ définition - Borne exacte
- [1.1.4.f] Little-o, little-ω - Bornes strictes
- [1.1.4.g] Définitions formelles - Avec constantes et n₀
- [1.1.4.h] Preuves - Démontrer une complexité
- [1.1.5.a] Règle de la somme - O(f) + O(g) = O(max(f,g))
- [1.1.5.b] Règle du produit - O(f) * O(g) = O(f*g)
- [1.1.5.c] Constantes - Ignorées dans Big-O
- [1.1.5.d] Termes dominants - Seul le plus grand compte
- [1.1.5.e] O(1) - Temps constant
- [1.1.5.f] O(log n) - Logarithmique
- [1.1.5.g] O(n) - Linéaire
- [1.1.5.h] O(n log n) - Linéarithmique
- [1.1.5.i] O(n²) - Quadratique
- [1.1.5.j] O(n³) - Cubique
- [1.1.5.k] O(2ⁿ) - Exponentiel
- [1.1.5.l] O(n!) - Factoriel
- [1.1.5.m] Comparaison graphique - Visualisation
- [1.1.5.n] Temps réels - Ordres de grandeur pratiques

**Description:**
Créer un analyseur de complexité qui peut évaluer empiriquement et théoriquement la complexité d'algorithmes.

**Rust:**
```rust
// src/lib.rs
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Complexity {
    Constant,           // O(1)
    Logarithmic,        // O(log n)
    Linear,             // O(n)
    Linearithmic,       // O(n log n)
    Quadratic,          // O(n²)
    Cubic,              // O(n³)
    Exponential,        // O(2ⁿ)
    Factorial,          // O(n!)
    Custom(String),     // Expression personnalisée
}

pub struct ComplexityAnalyzer;

impl ComplexityAnalyzer {
    /// Analyse empiriquement la complexité d'une fonction
    pub fn analyze_empirical<F>(f: F, sizes: &[usize]) -> ComplexityReport
    where
        F: Fn(usize) -> ();

    /// Vérifie si une complexité théorique correspond aux mesures
    pub fn verify_complexity<F>(
        f: F,
        expected: Complexity,
        sizes: &[usize]
    ) -> VerificationResult
    where
        F: Fn(usize) -> ();

    /// Compare deux complexités
    pub fn compare(c1: &Complexity, c2: &Complexity) -> Ordering;

    /// Simplifie une expression de complexité
    pub fn simplify(expr: &str) -> Complexity;
}

pub struct ComplexityReport {
    pub detected: Complexity,
    pub confidence: f64,        // 0.0 - 1.0
    pub measurements: Vec<Measurement>,
    pub r_squared: f64,         // Coefficient de détermination
}

pub struct Measurement {
    pub size: usize,
    pub time: Duration,
    pub operations: Option<usize>,
}

pub struct VerificationResult {
    pub matches: bool,
    pub actual: Complexity,
    pub expected: Complexity,
    pub deviation: f64,
}

// Fonctions de démonstration avec complexités connues
pub mod examples {
    pub fn constant_time(_n: usize) -> i32 { 42 }
    pub fn logarithmic(n: usize) -> i32 { /* binary search simulation */ }
    pub fn linear(n: usize) -> i32 { /* sum array */ }
    pub fn linearithmic(n: usize) -> i32 { /* merge sort */ }
    pub fn quadratic(n: usize) -> i32 { /* bubble sort */ }
    pub fn cubic(n: usize) -> i32 { /* matrix multiplication naive */ }
}
```

**Python:**
```python
# complexity_analyzer.py
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List
import time
import math

class Complexity(Enum):
    CONSTANT = "O(1)"
    LOGARITHMIC = "O(log n)"
    LINEAR = "O(n)"
    LINEARITHMIC = "O(n log n)"
    QUADRATIC = "O(n²)"
    CUBIC = "O(n³)"
    EXPONENTIAL = "O(2ⁿ)"
    FACTORIAL = "O(n!)"

@dataclass
class Measurement:
    size: int
    time_seconds: float
    operations: int | None = None

@dataclass
class ComplexityReport:
    detected: Complexity
    confidence: float
    measurements: list[Measurement]
    r_squared: float

@dataclass
class VerificationResult:
    matches: bool
    actual: Complexity
    expected: Complexity
    deviation: float

class ComplexityAnalyzer:
    @staticmethod
    def analyze_empirical(
        func: Callable[[int], None],
        sizes: list[int]
    ) -> ComplexityReport:
        """Analyse empiriquement la complexité d'une fonction"""
        pass

    @staticmethod
    def verify_complexity(
        func: Callable[[int], None],
        expected: Complexity,
        sizes: list[int]
    ) -> VerificationResult:
        """Vérifie si la complexité attendue correspond"""
        pass

    @staticmethod
    def compare(c1: Complexity, c2: Complexity) -> int:
        """Compare deux complexités (-1, 0, 1)"""
        pass

    @staticmethod
    def simplify(expr: str) -> Complexity:
        """Simplifie une expression comme '3n² + 2n + 1' en O(n²)"""
        pass

# Exemples de fonctions avec complexités connues
def constant_time(n: int) -> int:
    return 42

def logarithmic(n: int) -> int:
    count = 0
    while n > 0:
        n //= 2
        count += 1
    return count

def linear(n: int) -> int:
    return sum(range(n))

def quadratic(n: int) -> int:
    return sum(i * j for i in range(n) for j in range(n))
```

**Tests obligatoires:**
1. Détection correcte de O(1), O(log n), O(n), O(n²)
2. Confidence > 0.9 pour fonctions bien définies
3. Simplification de `5n³ + 100n² + n` → O(n³)
4. Comparaison correcte des complexités

---

### Exercice B2 : `loop_analyzer` (Couvre 1.1.6.a-i = 9 concepts)

**Concepts couverts:**
- [1.1.6.a] Boucle simple - for i in 0..n
- [1.1.6.b] Boucles imbriquées indépendantes - O(n*m)
- [1.1.6.c] Boucles imbriquées dépendantes - O(n*(n-1)/2)
- [1.1.6.d] Boucle logarithmique - while n > 0 { n /= 2 }
- [1.1.6.e] Boucle racine - for i in 0..sqrt(n)
- [1.1.6.f] Boucles consécutives - O(f) + O(g)
- [1.1.6.g] Boucles avec break - Meilleur/pire cas
- [1.1.6.h] Boucles avec conditions - Analyse probabiliste
- [1.1.6.i] 15 exercices variés - Pratique intensive

**Description:**
Créer un analyseur statique de boucles qui détermine leur complexité à partir du code source.

**Rust:**
```rust
// src/lib.rs

/// Représentation d'une structure de boucle
#[derive(Debug, Clone)]
pub enum LoopStructure {
    Simple { iterations: IterationExpr },
    Nested { outer: Box<LoopStructure>, inner: Box<LoopStructure>, dependent: bool },
    Logarithmic { base: u32 },
    Consecutive(Vec<LoopStructure>),
    WithBreak { base: Box<LoopStructure>, break_probability: f64 },
    WithCondition { base: Box<LoopStructure>, condition_probability: f64 },
}

#[derive(Debug, Clone)]
pub enum IterationExpr {
    N,                    // n iterations
    Constant(usize),      // fixed number
    Sqrt,                 // sqrt(n)
    Log(u32),            // log_base(n)
    NMinusI,             // n-i for dependent loops
    Expression(String),   // custom expression
}

pub struct LoopAnalyzer;

impl LoopAnalyzer {
    /// Analyse une structure de boucle et retourne sa complexité
    pub fn analyze(loop_structure: &LoopStructure) -> Complexity;

    /// Génère des exercices de complexité de boucle
    pub fn generate_exercise(difficulty: Difficulty) -> LoopExercise;

    /// Vérifie une réponse d'exercice
    pub fn check_answer(exercise: &LoopExercise, answer: &Complexity) -> bool;
}

pub struct LoopExercise {
    pub code_snippet: String,
    pub structure: LoopStructure,
    pub correct_answer: Complexity,
    pub hints: Vec<String>,
}

pub enum Difficulty {
    Easy,      // Single loops
    Medium,    // Nested independent
    Hard,      // Nested dependent, with breaks
    Expert,    // Complex combinations
}
```

**Python:**
```python
# loop_analyzer.py
from dataclasses import dataclass
from enum import Enum
from typing import List

class IterationExpr(Enum):
    N = "n"
    CONSTANT = "constant"
    SQRT = "sqrt(n)"
    LOG = "log(n)"
    N_MINUS_I = "n-i"

@dataclass
class SimpleLoop:
    iterations: IterationExpr
    constant_value: int | None = None

@dataclass
class NestedLoop:
    outer: 'LoopStructure'
    inner: 'LoopStructure'
    dependent: bool

@dataclass
class ConsecutiveLoops:
    loops: list['LoopStructure']

@dataclass
class LoopWithBreak:
    base: 'LoopStructure'
    break_probability: float

LoopStructure = SimpleLoop | NestedLoop | ConsecutiveLoops | LoopWithBreak

class Difficulty(Enum):
    EASY = 1
    MEDIUM = 2
    HARD = 3
    EXPERT = 4

@dataclass
class LoopExercise:
    code_snippet: str
    structure: LoopStructure
    correct_answer: str  # Complexity string
    hints: list[str]

class LoopAnalyzer:
    @staticmethod
    def analyze(loop_structure: LoopStructure) -> str:
        """Analyse une structure de boucle"""
        pass

    @staticmethod
    def generate_exercise(difficulty: Difficulty) -> LoopExercise:
        """Génère un exercice"""
        pass

    @staticmethod
    def check_answer(exercise: LoopExercise, answer: str) -> bool:
        """Vérifie une réponse"""
        pass

# 15 exercices intégrés
LOOP_EXERCISES = [
    # Easy
    LoopExercise(
        code_snippet="for i in range(n): x += 1",
        structure=SimpleLoop(IterationExpr.N),
        correct_answer="O(n)",
        hints=["Combien de fois la boucle s'exécute-t-elle?"]
    ),
    # ... 14 autres exercices
]
```

**Tests obligatoires:**
1. Analyse correcte de boucles simples
2. Analyse correcte de boucles imbriquées dépendantes (triangle)
3. Détection de complexité logarithmique
4. Génération d'exercices valides pour chaque difficulté

---

### Exercice B3 : `recurrence_solver` (Couvre 1.1.7.a-l = 12 concepts)

**Concepts couverts:**
- [1.1.7.a] Relations de récurrence - T(n) = aT(n/b) + f(n)
- [1.1.7.b] Méthode de substitution - Deviner et prouver
- [1.1.7.c] Méthode de l'arbre - Visualiser la récurrence
- [1.1.7.d] Somme géométrique - Σ aⁱ formules
- [1.1.7.e] Master Theorem - Cas généraux
- [1.1.7.f] Master Cas 1 - f(n) polynomialement plus petit
- [1.1.7.g] Master Cas 2 - f(n) = Θ(n^log_b(a))
- [1.1.7.h] Master Cas 3 - f(n) polynomialement plus grand
- [1.1.7.i] Preuves Master - Démonstrations
- [1.1.7.j] Cas non-couverts - Quand Master ne s'applique pas
- [1.1.7.k] Akra-Bazzi - Généralisation du Master
- [1.1.7.l] 10 exercices - Pratique intensive

**Description:**
Implémenter un solveur de récurrences algorithmiques avec support du Master Theorem.

**Rust:**
```rust
// src/lib.rs
use num_rational::Rational64;

/// Représentation d'une relation de récurrence
/// T(n) = a * T(n/b) + f(n)
#[derive(Debug, Clone)]
pub struct Recurrence {
    pub a: u64,           // Nombre de sous-problèmes
    pub b: u64,           // Facteur de division
    pub f: ComplexityExpr, // Travail hors récurrence
}

#[derive(Debug, Clone)]
pub enum ComplexityExpr {
    Constant,                      // O(1)
    Power(Rational64),            // n^k
    NLogN(Rational64),            // n^k * log(n)
    Logarithmic(Rational64),      // log^k(n)
    Custom(String),
}

#[derive(Debug, Clone)]
pub enum MasterCase {
    Case1,  // f(n) = O(n^(log_b(a) - ε))
    Case2,  // f(n) = Θ(n^log_b(a))
    Case3,  // f(n) = Ω(n^(log_b(a) + ε))
    NotApplicable(String),
}

pub struct RecurrenceSolver;

impl RecurrenceSolver {
    /// Résout une récurrence avec le Master Theorem
    pub fn solve_master(rec: &Recurrence) -> RecurrenceSolution;

    /// Détermine quel cas du Master Theorem s'applique
    pub fn determine_case(rec: &Recurrence) -> MasterCase;

    /// Calcule log_b(a)
    pub fn critical_exponent(rec: &Recurrence) -> f64;

    /// Génère l'arbre de récurrence
    pub fn generate_tree(rec: &Recurrence, depth: usize) -> RecurrenceTree;

    /// Résout par substitution (retourne les étapes)
    pub fn solve_substitution(rec: &Recurrence) -> Vec<SubstitutionStep>;
}

pub struct RecurrenceSolution {
    pub complexity: Complexity,
    pub case_used: MasterCase,
    pub proof_steps: Vec<String>,
}

pub struct RecurrenceTree {
    pub levels: Vec<TreeLevel>,
    pub total_work: ComplexityExpr,
}

pub struct TreeLevel {
    pub depth: usize,
    pub nodes: usize,
    pub work_per_node: ComplexityExpr,
    pub total_work: ComplexityExpr,
}

pub struct SubstitutionStep {
    pub description: String,
    pub expression: String,
}
```

**Python:**
```python
# recurrence_solver.py
from dataclasses import dataclass
from fractions import Fraction
from enum import Enum
from typing import List
import math

@dataclass
class ComplexityExpr:
    """Expression de complexité: coefficient * n^power * log(n)^log_power"""
    coefficient: float = 1.0
    power: Fraction = Fraction(0)
    log_power: int = 0

    def __str__(self) -> str:
        if self.power == 0 and self.log_power == 0:
            return "O(1)"
        parts = []
        if self.power != 0:
            if self.power == 1:
                parts.append("n")
            else:
                parts.append(f"n^{self.power}")
        if self.log_power != 0:
            if self.log_power == 1:
                parts.append("log(n)")
            else:
                parts.append(f"log^{self.log_power}(n)")
        return f"O({' * '.join(parts)})"

@dataclass
class Recurrence:
    """T(n) = a * T(n/b) + f(n)"""
    a: int          # Nombre de sous-problèmes
    b: int          # Facteur de division
    f: ComplexityExpr  # Travail hors récurrence

class MasterCase(Enum):
    CASE_1 = "Case 1: f(n) = O(n^(log_b(a) - ε))"
    CASE_2 = "Case 2: f(n) = Θ(n^log_b(a))"
    CASE_3 = "Case 3: f(n) = Ω(n^(log_b(a) + ε))"
    NOT_APPLICABLE = "Master Theorem does not apply"

@dataclass
class RecurrenceSolution:
    complexity: str
    case_used: MasterCase
    proof_steps: list[str]

@dataclass
class TreeLevel:
    depth: int
    nodes: int
    work_per_node: str
    total_work: str

@dataclass
class RecurrenceTree:
    levels: list[TreeLevel]
    total_work: str

class RecurrenceSolver:
    @staticmethod
    def solve_master(rec: Recurrence) -> RecurrenceSolution:
        """Résout avec le Master Theorem"""
        pass

    @staticmethod
    def determine_case(rec: Recurrence) -> MasterCase:
        """Détermine le cas applicable"""
        pass

    @staticmethod
    def critical_exponent(rec: Recurrence) -> float:
        """Calcule log_b(a)"""
        return math.log(rec.a) / math.log(rec.b)

    @staticmethod
    def generate_tree(rec: Recurrence, depth: int) -> RecurrenceTree:
        """Génère l'arbre de récurrence"""
        pass

# 10 exercices de récurrence intégrés
RECURRENCE_EXERCISES = [
    # Binary Search: T(n) = T(n/2) + O(1)
    {"recurrence": Recurrence(1, 2, ComplexityExpr()), "answer": "O(log n)"},
    # Merge Sort: T(n) = 2T(n/2) + O(n)
    {"recurrence": Recurrence(2, 2, ComplexityExpr(power=Fraction(1))), "answer": "O(n log n)"},
    # etc...
]
```

**Tests obligatoires:**
1. Résolution correcte des 3 cas du Master Theorem
2. Détection quand Master ne s'applique pas
3. Génération d'arbre de récurrence correcte
4. Les 10 exercices intégrés avec solutions

---

### Exercice B4 : `amortized_analyzer` (Couvre 1.1.8.a-j = 10 concepts)

**Concepts couverts:**
- [1.1.8.a] Concept - Coût moyen sur séquence d'opérations
- [1.1.8.b] Méthode agrégat - Coût total / nombre opérations
- [1.1.8.c] Méthode comptable - Crédits et débits
- [1.1.8.d] Méthode potentiel - Fonction potentiel Φ
- [1.1.8.e] Définition potentiel - Φ: État → ℝ
- [1.1.8.f] Coût amorti - ĉᵢ = cᵢ + Φ(Dᵢ) - Φ(Dᵢ₋₁)
- [1.1.8.g] Exemple Dynamic Array - Push amorti O(1)
- [1.1.8.h] Exemple Stack avec Multipop - Pop amorti O(1)
- [1.1.8.i] Exemple Compteur binaire - Increment amorti O(1)
- [1.1.8.j] Applications - Quand utiliser l'analyse amortie

**Description:**
Implémenter des structures de données avec analyse amortie complète.

**Rust:**
```rust
// src/lib.rs

/// Analyseur d'analyse amortie
pub struct AmortizedAnalyzer<T> {
    operations: Vec<Operation<T>>,
    potential_history: Vec<f64>,
}

pub struct Operation<T> {
    pub name: String,
    pub actual_cost: usize,
    pub state_before: T,
    pub state_after: T,
}

impl<T: Clone> AmortizedAnalyzer<T> {
    pub fn new() -> Self;

    /// Enregistre une opération
    pub fn record_operation(&mut self, op: Operation<T>, potential_fn: impl Fn(&T) -> f64);

    /// Calcule le coût amorti de chaque opération
    pub fn amortized_costs(&self) -> Vec<f64>;

    /// Génère un rapport avec les trois méthodes
    pub fn generate_report(&self) -> AmortizedReport;
}

pub struct AmortizedReport {
    pub aggregate_analysis: AggregateAnalysis,
    pub accounting_analysis: AccountingAnalysis,
    pub potential_analysis: PotentialAnalysis,
}

pub struct AggregateAnalysis {
    pub total_operations: usize,
    pub total_actual_cost: usize,
    pub amortized_cost_per_op: f64,
}

pub struct AccountingAnalysis {
    pub credits_assigned: Vec<usize>,
    pub credits_used: Vec<usize>,
    pub balance_history: Vec<i64>,
}

pub struct PotentialAnalysis {
    pub potential_function: String,
    pub potential_history: Vec<f64>,
    pub amortized_costs: Vec<f64>,
}

// Exemples de structures avec analyse amortie
pub mod examples {
    /// Dynamic Array avec analyse amortie
    pub struct DynamicArray<T> {
        data: Vec<T>,
        capacity: usize,
        resize_count: usize,
    }

    impl<T: Clone> DynamicArray<T> {
        pub fn new() -> Self;
        pub fn push(&mut self, value: T) -> OperationCost;
        pub fn potential(&self) -> f64;  // Φ = 2n - capacity
    }

    /// Stack avec multipop
    pub struct MultipopStack<T> {
        data: Vec<T>,
    }

    impl<T> MultipopStack<T> {
        pub fn push(&mut self, value: T) -> OperationCost;
        pub fn pop(&mut self) -> Option<(T, OperationCost)>;
        pub fn multipop(&mut self, k: usize) -> (Vec<T>, OperationCost);
        pub fn potential(&self) -> f64;  // Φ = |stack|
    }

    /// Compteur binaire
    pub struct BinaryCounter {
        bits: Vec<bool>,
    }

    impl BinaryCounter {
        pub fn increment(&mut self) -> OperationCost;
        pub fn potential(&self) -> f64;  // Φ = nombre de 1
    }

    pub struct OperationCost {
        pub actual: usize,
        pub amortized: f64,
    }
}
```

**Python:**
```python
# amortized_analyzer.py
from dataclasses import dataclass, field
from typing import List, Callable, TypeVar, Generic

T = TypeVar('T')

@dataclass
class Operation:
    name: str
    actual_cost: int
    state_before: any
    state_after: any

@dataclass
class AggregateAnalysis:
    total_operations: int
    total_actual_cost: int
    amortized_cost_per_op: float

@dataclass
class AccountingAnalysis:
    credits_assigned: list[int]
    credits_used: list[int]
    balance_history: list[int]

@dataclass
class PotentialAnalysis:
    potential_function: str
    potential_history: list[float]
    amortized_costs: list[float]

@dataclass
class AmortizedReport:
    aggregate: AggregateAnalysis
    accounting: AccountingAnalysis
    potential: PotentialAnalysis

class AmortizedAnalyzer(Generic[T]):
    def __init__(self):
        self.operations: list[Operation] = []
        self.potential_history: list[float] = []

    def record_operation(
        self,
        op: Operation,
        potential_fn: Callable[[T], float]
    ) -> None:
        pass

    def amortized_costs(self) -> list[float]:
        pass

    def generate_report(self) -> AmortizedReport:
        pass

# Exemples avec analyse amortie

class DynamicArray:
    """Dynamic array avec potentiel Φ = 2n - capacity"""

    def __init__(self):
        self._data: list = []
        self._capacity: int = 1

    def push(self, value) -> tuple[int, float]:
        """Retourne (coût réel, coût amorti)"""
        pass

    def potential(self) -> float:
        return 2 * len(self._data) - self._capacity

class MultipopStack:
    """Stack avec multipop, potentiel Φ = |stack|"""

    def __init__(self):
        self._data: list = []

    def push(self, value) -> tuple[int, float]:
        pass

    def multipop(self, k: int) -> tuple[list, int, float]:
        """Retourne (éléments, coût réel, coût amorti)"""
        pass

    def potential(self) -> float:
        return len(self._data)

class BinaryCounter:
    """Compteur binaire avec potentiel Φ = nombre de 1"""

    def __init__(self, bits: int = 8):
        self._bits: list[bool] = [False] * bits

    def increment(self) -> tuple[int, float]:
        """Retourne (coût réel = flips, coût amorti)"""
        pass

    def potential(self) -> float:
        return sum(self._bits)
```

**Tests obligatoires:**
1. DynamicArray: coût amorti de push = O(1)
2. MultipopStack: coût amorti de multipop = O(1) par élément
3. BinaryCounter: coût amorti d'increment = O(1)
4. Rapport complet avec les 3 méthodes d'analyse

---

## SÉRIE C : Vector & Structures Dynamiques (25 concepts)

### Exercice C1 : `generic_vector` (Couvre 1.1.9.a-n, 1.1.10.a-k = 25 concepts)

**Concepts couverts:**
- [1.1.9.a] Structure - data, size, capacity
- [1.1.9.b] Invariants - size ≤ capacity, data valid
- [1.1.9.c] Constructeur - Initialisation
- [1.1.9.d] Destructeur - Libération mémoire
- [1.1.9.e] push_back - Ajout en fin
- [1.1.9.f] pop_back - Retrait en fin
- [1.1.9.g] get/set - Accès par index
- [1.1.9.h] insert - Insertion à position
- [1.1.9.i] remove - Suppression à position
- [1.1.9.j] Resize strategy - Quand agrandir
- [1.1.9.k] Preuve amortie - Push est O(1) amorti
- [1.1.9.l] Shrink strategy - Quand réduire
- [1.1.9.m] reserve - Pré-allocation
- [1.1.9.n] clear - Vider sans désallouer
- [1.1.10.a] Généricité - Support tous types
- [1.1.10.b] Comparateurs - Fonctions de comparaison
- [1.1.10.c] Deep copy - Clone complet
- [1.1.10.d] Swap - Échange efficace
- [1.1.10.e] Reverse - Inversion
- [1.1.10.f] Iterator pattern - Parcours
- [1.1.10.g] for_each - Application fonction
- [1.1.10.h] find - Recherche linéaire
- [1.1.10.i] Binary search - Recherche dichotomique
- [1.1.10.j] Sort wrapper - Tri intégré
- [1.1.10.k] Stable sort - Tri stable

**Description:**
Implémenter un vecteur générique complet avec toutes les opérations standard.

**Rust:**
```rust
// src/lib.rs
use std::cmp::Ordering;

pub struct Vector<T> {
    data: *mut T,
    size: usize,
    capacity: usize,
}

impl<T> Vector<T> {
    // Construction
    pub fn new() -> Self;
    pub fn with_capacity(capacity: usize) -> Self;
    pub fn from_slice(slice: &[T]) -> Self where T: Clone;

    // Propriétés
    pub fn len(&self) -> usize;
    pub fn capacity(&self) -> usize;
    pub fn is_empty(&self) -> bool;

    // Accès
    pub fn get(&self, index: usize) -> Option<&T>;
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T>;

    // Modification
    pub fn push(&mut self, value: T);
    pub fn pop(&mut self) -> Option<T>;
    pub fn insert(&mut self, index: usize, value: T);
    pub fn remove(&mut self, index: usize) -> Option<T>;
    pub fn clear(&mut self);

    // Capacité
    pub fn reserve(&mut self, additional: usize);
    pub fn shrink_to_fit(&mut self);

    // Algorithmes
    pub fn reverse(&mut self);
    pub fn swap(&mut self, i: usize, j: usize);

    // Recherche
    pub fn find(&self, predicate: impl Fn(&T) -> bool) -> Option<usize>;
    pub fn binary_search(&self, value: &T) -> Result<usize, usize>
    where T: Ord;
    pub fn binary_search_by<F>(&self, f: F) -> Result<usize, usize>
    where F: FnMut(&T) -> Ordering;

    // Tri
    pub fn sort(&mut self) where T: Ord;
    pub fn sort_by<F>(&mut self, compare: F) where F: FnMut(&T, &T) -> Ordering;
    pub fn sort_stable(&mut self) where T: Ord;

    // Itération
    pub fn iter(&self) -> VectorIter<'_, T>;
    pub fn iter_mut(&mut self) -> VectorIterMut<'_, T>;
    pub fn for_each<F>(&self, f: F) where F: FnMut(&T);
    pub fn map<U, F>(&self, f: F) -> Vector<U> where F: FnMut(&T) -> U;
    pub fn filter<F>(&self, predicate: F) -> Vector<T> where F: FnMut(&T) -> bool, T: Clone;
}

impl<T: Clone> Clone for Vector<T> {
    fn clone(&self) -> Self;
}

impl<T> Drop for Vector<T> {
    fn drop(&mut self);
}

impl<T> std::ops::Index<usize> for Vector<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output;
}

impl<T> std::ops::IndexMut<usize> for Vector<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output;
}

pub struct VectorIter<'a, T> { /* ... */ }
pub struct VectorIterMut<'a, T> { /* ... */ }

impl<'a, T> Iterator for VectorIter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item>;
}

impl<'a, T> Iterator for VectorIterMut<'a, T> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<Self::Item>;
}
```

**Python:**
```python
# generic_vector.py
from typing import TypeVar, Generic, Callable, Iterator, Optional, List
from dataclasses import dataclass

T = TypeVar('T')
U = TypeVar('U')

class Vector(Generic[T]):
    def __init__(self, initial_capacity: int = 8):
        self._data: list[T | None] = [None] * initial_capacity
        self._size: int = 0
        self._capacity: int = initial_capacity

    @classmethod
    def from_list(cls, items: list[T]) -> 'Vector[T]':
        pass

    # Propriétés
    def __len__(self) -> int:
        return self._size

    def capacity(self) -> int:
        return self._capacity

    def is_empty(self) -> bool:
        return self._size == 0

    # Accès
    def __getitem__(self, index: int) -> T:
        pass

    def __setitem__(self, index: int, value: T) -> None:
        pass

    def get(self, index: int) -> Optional[T]:
        pass

    # Modification
    def push(self, value: T) -> None:
        pass

    def pop(self) -> Optional[T]:
        pass

    def insert(self, index: int, value: T) -> None:
        pass

    def remove(self, index: int) -> Optional[T]:
        pass

    def clear(self) -> None:
        pass

    # Capacité
    def reserve(self, additional: int) -> None:
        pass

    def shrink_to_fit(self) -> None:
        pass

    # Algorithmes
    def reverse(self) -> None:
        pass

    def swap(self, i: int, j: int) -> None:
        pass

    # Recherche
    def find(self, predicate: Callable[[T], bool]) -> Optional[int]:
        pass

    def binary_search(self, value: T) -> tuple[bool, int]:
        """Retourne (found, index/insertion_point)"""
        pass

    # Tri
    def sort(self, key: Callable[[T], any] = None, reverse: bool = False) -> None:
        pass

    def sort_stable(self, key: Callable[[T], any] = None) -> None:
        pass

    # Itération
    def __iter__(self) -> Iterator[T]:
        pass

    def for_each(self, f: Callable[[T], None]) -> None:
        pass

    def map(self, f: Callable[[T], U]) -> 'Vector[U]':
        pass

    def filter(self, predicate: Callable[[T], bool]) -> 'Vector[T]':
        pass

    # Clone
    def clone(self) -> 'Vector[T]':
        pass
```

**Tests obligatoires:**
1. Toutes les opérations de base fonctionnent
2. Resize automatique correcte (doubling strategy)
3. Pas de fuites mémoire
4. Itérateurs fonctionnels
5. Tri stable préserve l'ordre des égaux
6. Binary search correct sur vecteur trié

---

## SÉRIE D : Techniques de Tableaux (49 concepts)

### Exercice D1 : `two_pointers_master` (Couvre 1.1.11.a-n = 14 concepts)

**Concepts couverts:**
- [1.1.11.a] Concept - Deux indices parcourant le tableau
- [1.1.11.b] Opposés - Un au début, un à la fin
- [1.1.11.c] Same direction - Deux au début
- [1.1.11.d] Fast/Slow - Vitesses différentes
- [1.1.11.e] Two Sum (sorted) - Trouver paire avec somme
- [1.1.11.f] 3Sum - Trouver triplet
- [1.1.11.g] Container with most water - Maximiser aire
- [1.1.11.h] Trapping rain water - Calculer eau piégée
- [1.1.11.i] Remove duplicates - Suppression in-place
- [1.1.11.j] Palindrome check - Vérification symétrie
- [1.1.11.k] Merge sorted arrays - Fusion
- [1.1.11.l] Partition - Séparation par pivot
- [1.1.11.m] Dutch National Flag - 3-way partition
- [1.1.11.n] Complexité typique - O(n) avec 2 pointeurs

**Description:**
Implémenter une bibliothèque complète de techniques two-pointers.

**Rust:**
```rust
// src/lib.rs
pub struct TwoPointers;

impl TwoPointers {
    // Technique: pointeurs opposés

    /// Trouve deux éléments dont la somme égale target (tableau trié)
    pub fn two_sum_sorted(arr: &[i32], target: i32) -> Option<(usize, usize)>;

    /// Trouve tous les triplets dont la somme égale target
    pub fn three_sum(arr: &mut [i32], target: i32) -> Vec<[i32; 3]>;

    /// Calcule l'aire maximale entre deux lignes
    pub fn container_with_most_water(heights: &[i32]) -> i64;

    /// Calcule l'eau piégée entre les barres
    pub fn trapping_rain_water(heights: &[i32]) -> i64;

    /// Vérifie si un slice est un palindrome
    pub fn is_palindrome<T: Eq>(arr: &[T]) -> bool;

    // Technique: même direction

    /// Supprime les duplicats in-place, retourne nouvelle longueur
    pub fn remove_duplicates(arr: &mut [i32]) -> usize;

    /// Fusionne deux tableaux triés
    pub fn merge_sorted(arr1: &[i32], arr2: &[i32]) -> Vec<i32>;

    // Technique: partition

    /// Partitionne autour d'un pivot, retourne index pivot
    pub fn partition(arr: &mut [i32], pivot_idx: usize) -> usize;

    /// Dutch National Flag: tri 0, 1, 2
    pub fn dutch_national_flag(arr: &mut [i32]);

    // Technique: fast/slow

    /// Détecte un cycle dans une linked list (Floyd's algorithm)
    pub fn detect_cycle(head: Option<&ListNode>) -> bool;

    /// Trouve le milieu d'une linked list
    pub fn find_middle(head: Option<&ListNode>) -> Option<&ListNode>;
}

// Pour les problèmes de linked list
pub struct ListNode {
    pub val: i32,
    pub next: Option<Box<ListNode>>,
}
```

**Python:**
```python
# two_pointers_master.py
from typing import List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ListNode:
    val: int
    next: Optional['ListNode'] = None

class TwoPointers:
    # Pointeurs opposés

    @staticmethod
    def two_sum_sorted(arr: list[int], target: int) -> Optional[tuple[int, int]]:
        """Trouve indices de deux éléments sommant à target"""
        pass

    @staticmethod
    def three_sum(arr: list[int], target: int = 0) -> list[list[int]]:
        """Trouve tous les triplets uniques sommant à target"""
        pass

    @staticmethod
    def container_with_most_water(heights: list[int]) -> int:
        """Aire maximale entre deux lignes"""
        pass

    @staticmethod
    def trapping_rain_water(heights: list[int]) -> int:
        """Eau piégée entre les barres"""
        pass

    @staticmethod
    def is_palindrome(s: str) -> bool:
        """Vérifie si palindrome (ignore non-alphanumériques)"""
        pass

    # Même direction

    @staticmethod
    def remove_duplicates(arr: list[int]) -> int:
        """Supprime duplicats in-place, retourne nouvelle longueur"""
        pass

    @staticmethod
    def merge_sorted(arr1: list[int], arr2: list[int]) -> list[int]:
        """Fusionne deux tableaux triés"""
        pass

    # Partition

    @staticmethod
    def partition(arr: list[int], pivot_idx: int) -> int:
        """Partitionne autour du pivot, retourne nouvel index"""
        pass

    @staticmethod
    def dutch_national_flag(arr: list[int]) -> None:
        """Trie in-place un tableau de 0, 1, 2"""
        pass

    # Fast/Slow

    @staticmethod
    def detect_cycle(head: Optional[ListNode]) -> bool:
        """Détecte un cycle (Floyd's algorithm)"""
        pass

    @staticmethod
    def find_middle(head: Optional[ListNode]) -> Optional[ListNode]:
        """Trouve le milieu de la liste"""
        pass
```

**Tests obligatoires:**
1. two_sum_sorted trouve la paire correcte
2. three_sum trouve tous les triplets uniques
3. container_with_most_water: [1,8,6,2,5,4,8,3,7] → 49
4. trapping_rain_water: [0,1,0,2,1,0,1,3,2,1,2,1] → 6
5. dutch_national_flag trie correctement [2,0,1,2,0,1]
6. Détection de cycle correcte

---

### Exercice D2 : `sliding_window_master` (Couvre 1.1.12.a-n = 14 concepts)

**Concepts couverts:**
- [1.1.12.a] Concept - Fenêtre glissante sur tableau
- [1.1.12.b] Fixed size window - Taille constante
- [1.1.12.c] Variable size window - Taille variable
- [1.1.12.d] Window expansion - Agrandir la fenêtre
- [1.1.12.e] Window contraction - Réduire la fenêtre
- [1.1.12.f] Template fixed - Pattern pour taille fixe
- [1.1.12.g] Template variable - Pattern pour taille variable
- [1.1.12.h] Maximum sum subarray size k - Somme max taille k
- [1.1.12.i] Longest substring without repeat - Plus longue sans répétition
- [1.1.12.j] Minimum window substring - Plus petite contenant pattern
- [1.1.12.k] Maximum of all subarrays size k - Max par fenêtre
- [1.1.12.l] Count subarrays with sum - Compter sous-tableaux
- [1.1.12.m] Anagram search - Trouver anagrammes
- [1.1.12.n] Complexité typique - O(n) avec sliding window

**Description:**
Implémenter une bibliothèque complète de techniques sliding window.

**Rust:**
```rust
// src/lib.rs
use std::collections::{HashMap, VecDeque};

pub struct SlidingWindow;

impl SlidingWindow {
    // Fenêtre de taille fixe

    /// Somme maximale d'un sous-tableau de taille k
    pub fn max_sum_subarray_k(arr: &[i32], k: usize) -> Option<i32>;

    /// Moyenne de chaque sous-tableau de taille k
    pub fn averages_k(arr: &[i32], k: usize) -> Vec<f64>;

    /// Maximum de chaque fenêtre de taille k (monotonic deque)
    pub fn max_sliding_window(arr: &[i32], k: usize) -> Vec<i32>;

    /// Trouve tous les anagrammes de pattern dans text
    pub fn find_anagrams(text: &str, pattern: &str) -> Vec<usize>;

    // Fenêtre de taille variable

    /// Plus longue sous-chaîne sans caractère répété
    pub fn longest_substring_without_repeat(s: &str) -> usize;

    /// Plus petite sous-chaîne contenant tous les caractères de pattern
    pub fn minimum_window_substring(s: &str, t: &str) -> String;

    /// Plus long sous-tableau avec somme ≤ target
    pub fn longest_subarray_sum_at_most(arr: &[i32], target: i32) -> usize;

    /// Plus court sous-tableau avec somme ≥ target
    pub fn shortest_subarray_sum_at_least(arr: &[i32], target: i32) -> usize;

    /// Compte les sous-tableaux avec somme = target
    pub fn count_subarrays_with_sum(arr: &[i32], target: i32) -> usize;

    /// Plus long sous-tableau avec au plus k éléments distincts
    pub fn longest_subarray_k_distinct(arr: &[i32], k: usize) -> usize;
}
```

**Python:**
```python
# sliding_window_master.py
from collections import defaultdict, deque
from typing import List

class SlidingWindow:
    # Fenêtre fixe

    @staticmethod
    def max_sum_subarray_k(arr: list[int], k: int) -> int | None:
        """Somme maximale d'un sous-tableau de taille k"""
        pass

    @staticmethod
    def averages_k(arr: list[int], k: int) -> list[float]:
        """Moyenne de chaque fenêtre de taille k"""
        pass

    @staticmethod
    def max_sliding_window(arr: list[int], k: int) -> list[int]:
        """Maximum de chaque fenêtre (monotonic deque)"""
        pass

    @staticmethod
    def find_anagrams(text: str, pattern: str) -> list[int]:
        """Indices de tous les anagrammes de pattern"""
        pass

    # Fenêtre variable

    @staticmethod
    def longest_substring_without_repeat(s: str) -> int:
        """Longueur de la plus longue sous-chaîne sans répétition"""
        pass

    @staticmethod
    def minimum_window_substring(s: str, t: str) -> str:
        """Plus petite sous-chaîne contenant tous les caractères de t"""
        pass

    @staticmethod
    def longest_subarray_sum_at_most(arr: list[int], target: int) -> int:
        """Plus long sous-tableau avec somme ≤ target"""
        pass

    @staticmethod
    def shortest_subarray_sum_at_least(arr: list[int], target: int) -> int:
        """Plus court sous-tableau avec somme ≥ target"""
        pass

    @staticmethod
    def count_subarrays_with_sum(arr: list[int], target: int) -> int:
        """Nombre de sous-tableaux avec somme = target"""
        pass

    @staticmethod
    def longest_subarray_k_distinct(arr: list[int], k: int) -> int:
        """Plus long sous-tableau avec au plus k distincts"""
        pass
```

**Tests obligatoires:**
1. max_sliding_window: [1,3,-1,-3,5,3,6,7], k=3 → [3,3,5,5,6,7]
2. longest_substring_without_repeat: "abcabcbb" → 3
3. minimum_window_substring: "ADOBECODEBANC", "ABC" → "BANC"
4. find_anagrams: "cbaebabacd", "abc" → [0, 6]
5. Performance O(n) pour tous

---

### Exercice D3 : `prefix_sums` (Couvre 1.1.13.a-l = 12 concepts)

**Concepts couverts:**
- [1.1.13.a] Prefix sum 1D - Sommes cumulées
- [1.1.13.b] Range sum query - Somme d'intervalle
- [1.1.13.c] Construction - O(n)
- [1.1.13.d] Query - O(1)
- [1.1.13.e] Prefix sum 2D - Matrices
- [1.1.13.f] 2D construction - Inclusion-exclusion
- [1.1.13.g] 2D range query - Requête rectangulaire
- [1.1.13.h] Difference array - Tableau de différences
- [1.1.13.i] Difference construction - Création
- [1.1.13.j] Range add - Addition sur intervalle
- [1.1.13.k] Reconstruct - Reconstruction depuis différences
- [1.1.13.l] Applications - Cas d'usage

**Rust:**
```rust
// src/lib.rs

/// Prefix sum 1D
pub struct PrefixSum1D {
    prefix: Vec<i64>,
}

impl PrefixSum1D {
    pub fn new(arr: &[i64]) -> Self;
    pub fn range_sum(&self, left: usize, right: usize) -> i64;
    pub fn total(&self) -> i64;
}

/// Prefix sum 2D
pub struct PrefixSum2D {
    prefix: Vec<Vec<i64>>,
}

impl PrefixSum2D {
    pub fn new(matrix: &[Vec<i64>]) -> Self;
    pub fn range_sum(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64;
}

/// Difference array
pub struct DifferenceArray {
    diff: Vec<i64>,
}

impl DifferenceArray {
    pub fn new(size: usize) -> Self;
    pub fn from_array(arr: &[i64]) -> Self;
    pub fn range_add(&mut self, left: usize, right: usize, value: i64);
    pub fn build(&self) -> Vec<i64>;
}
```

**Python:**
```python
# prefix_sums.py

class PrefixSum1D:
    def __init__(self, arr: list[int]):
        pass

    def range_sum(self, left: int, right: int) -> int:
        """Somme de arr[left:right+1]"""
        pass

    def total(self) -> int:
        pass

class PrefixSum2D:
    def __init__(self, matrix: list[list[int]]):
        pass

    def range_sum(self, r1: int, c1: int, r2: int, c2: int) -> int:
        """Somme du rectangle [r1,c1] à [r2,c2]"""
        pass

class DifferenceArray:
    def __init__(self, size: int):
        pass

    @classmethod
    def from_array(cls, arr: list[int]) -> 'DifferenceArray':
        pass

    def range_add(self, left: int, right: int, value: int) -> None:
        """Ajoute value à tous les éléments de [left, right]"""
        pass

    def build(self) -> list[int]:
        """Reconstruit le tableau"""
        pass
```

---

### Exercice D4 : `coordinate_compression` (Couvre 1.1.14.a-i = 9 concepts)

**Concepts couverts:**
- [1.1.14.a] Problème - Valeurs sparse dans grand espace
- [1.1.14.b] Technique - Mapper vers [0, n-1]
- [1.1.14.c] Algorithme - Trier, dédupliquer, indexer
- [1.1.14.d] Implémentation - Structure de mapping
- [1.1.14.e] Implémentation - Compression avec bijection
- [1.1.14.f-h] Applications - BIT, segment tree, DP
- [1.1.14.i] Complexité - O(n log n) construction

**Rust:**
```rust
// src/lib.rs
use std::collections::HashMap;

pub struct CoordinateCompressor<T: Ord + Clone> {
    sorted: Vec<T>,
    rank: HashMap<T, usize>,
}

impl<T: Ord + Clone + std::hash::Hash> CoordinateCompressor<T> {
    pub fn new(values: &[T]) -> Self;
    pub fn compress(&self, value: &T) -> Option<usize>;
    pub fn decompress(&self, rank: usize) -> Option<&T>;
    pub fn size(&self) -> usize;
    pub fn compress_all(&self, values: &[T]) -> Vec<usize>;
}
```

**Python:**
```python
# coordinate_compression.py
from typing import TypeVar, Generic, List, Optional, Dict

T = TypeVar('T')

class CoordinateCompressor(Generic[T]):
    def __init__(self, values: list[T]):
        pass

    def compress(self, value: T) -> int | None:
        pass

    def decompress(self, rank: int) -> T | None:
        pass

    def size(self) -> int:
        pass

    def compress_all(self, values: list[T]) -> list[int]:
        pass
```

---

## SÉRIE E : Algorithmes de Tri (74 concepts)

### Exercice E1 : `sort_quadratic` (Couvre 1.1.15.a-k = 11 concepts)

**Concepts:** Bubble Sort, Selection Sort, Insertion Sort, Shell Sort

### Exercice E2 : `sort_merge` (Couvre 1.1.16.a-m = 13 concepts)

**Concepts:** Merge Sort et variantes (bottom-up, natural, in-place, linked list, counting inversions)

### Exercice E3 : `sort_quick` (Couvre 1.1.17.a-p = 16 concepts)

**Concepts:** Quick Sort avec Lomuto, Hoare, pivot strategies, 3-way, dual pivot, intro sort, PDQ sort

### Exercice E4 : `sort_heap` (Couvre 1.1.18.a-k = 11 concepts)

**Concepts:** Heap Sort avec heapify, build_heap O(n) proof

### Exercice E5 : `sort_lower_bound` (Couvre 1.1.19.a-h = 8 concepts)

**Concepts:** Preuve Ω(n log n) avec arbre de décision

### Exercice E6 : `sort_non_comparison` (Couvre 1.1.20.a-o = 15 concepts)

**Concepts:** Counting Sort, Radix Sort (LSD/MSD), Bucket Sort

### Exercice E7 : `sort_external` (Couvre 1.1.21.a-i = 9 concepts)

**Concepts:** External sorting avec k-way merge, replacement selection

---

## SÉRIE F : Recherche (51 concepts)

### Exercice F1 : `search_binary` (Couvre 1.1.22.a-k, 1.1.23.a-n = 25 concepts)

**Concepts:** Binary Search fondamentaux et toutes variantes

### Exercice F2 : `search_on_answer` (Couvre 1.1.24.a-i = 9 concepts)

**Concepts:** Binary Search on Answer avec templates minimize/maximize

### Exercice F3 : `search_ternary` (Couvre 1.1.25.a-h = 8 concepts)

**Concepts:** Ternary Search pour fonctions unimodales

### Exercice F4 : `search_other` (Couvre 1.1.26.a-i = 9 concepts)

**Concepts:** Interpolation, Exponential, Jump, Fibonacci search

---

## SÉRIE G : Projet Intégrateur & Tests (58 concepts)

### Exercice G1 : `odyssey_algo_lib` (Projet final couvrant 1.1.A, 1.1.Benchmark, 1.1.Tests, 1.1.LeetCode)

**Concepts couverts: 58**
- Mini-projet complet (1.1.A): 23 concepts
- Benchmark (1.1.Benchmark): 9 concepts
- Tests (1.1.Tests): 6 concepts
- LeetCode (1.1.LeetCode): 20 concepts

**Description:**
Créer une bibliothèque complète `odyssey_algo_lib` intégrant tous les algorithmes du Module 1.1 avec:
- Arena allocator
- Generic vector
- Tous les algorithmes de tri
- Tous les algorithmes de recherche
- Two pointers et sliding window
- Prefix sums et coordinate compression
- Suite de tests complète
- Benchmarks comparatifs
- Solutions aux 20 problèmes LeetCode

---

## Récapitulatif de Couverture

| Série | Exercices | Concepts couverts |
|-------|-----------|-------------------|
| A | 2 | 30 (1.1.1-3, 1.1.A partiellement) |
| B | 4 | 53 (1.1.4-8) |
| C | 1 | 25 (1.1.9-10) |
| D | 4 | 49 (1.1.11-14) |
| E | 7 | 83 (1.1.15-21) |
| F | 4 | 51 (1.1.22-26) |
| G | 1 | 58 (1.1.A, Benchmark, Tests, LeetCode) |
| **TOTAL** | **23** | **343** |

---

## Notes d'implémentation

1. **Qualité pédagogique**: Chaque exercice progresse du simple au complexe
2. **Testabilité**: Tous les exercices ont des tests automatisés
3. **Originalité**: Aucune copie des exercices 42 - concepts similaires, implémentation originale
4. **Bilinguisme**: Rust 2024 + Python 3.14 pour chaque exercice
