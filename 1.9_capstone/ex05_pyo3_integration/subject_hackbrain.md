# Exercice 1.9.05 - PyO3 Rust-Python Integration

## Metadata
- **Nom de code:** the_translator
- **Tier:** 3 (Synthesis - Advanced FFI and Language Interoperability)
- **Complexité estimée:** Expert (35-45h)
- **Prérequis:** Modules 1.1-1.8, Rust ownership model, Python C API basics

---

# Section 1: Prototype & Consigne

## 1.1 Version Culture Pop

> *"Lost in Translation"* (2003) - Deux mondes qui ne se comprennent pas... jusqu'à ce qu'un traducteur arrive.

Python domine le machine learning et la data science. Rust domine la performance et la safety. Dans le monde réel, ils doivent cohabiter. Votre mission: construire le pont ultime entre ces deux univers.

Imaginez pouvoir écrire vos algorithmes critiques en Rust pur, puis les appeler depuis Python avec la même facilité que n'importe quel module natif. C'est exactement ce que fait PyO3, et c'est exactement ce que vous allez maîtriser.

**Le défi:** Créer une bibliothèque Rust haute performance exposant des structures de données et algorithmes, accessible depuis Python avec une interface idiomatique.

## 1.2 Version Académique

### Contexte Formel

L'interopérabilité entre langages constitue un domaine fondamental du génie logiciel moderne. PyO3 implémente les Python FFI (Foreign Function Interface) bindings pour Rust, permettant:
- L'exposition de fonctions Rust comme modules Python natifs
- La manipulation d'objets Python depuis Rust
- La conversion automatique de types entre les deux langages
- Le respect des garanties de sécurité mémoire de Rust

### Spécification Formelle

Soit I = (R, P, C) un système d'interopérabilité où:
- R : Ensemble des types Rust {i32, String, Vec<T>, struct, enum, ...}
- P : Ensemble des types Python {int, str, list, dict, class, ...}
- C : Fonction de conversion C: R ↔ P respectant la sémantique

### Objectifs Pédagogiques

1. Maîtriser PyO3 pour créer des extensions Python en Rust
2. Comprendre le GIL (Global Interpreter Lock) et ses implications
3. Implémenter des conversions de types sûres et efficaces
4. Optimiser les performances cross-language

### Fonctions à Implémenter (Rust avec PyO3)

```rust
// ============================================================
// PARTIE A: Types Primitifs et Conversions de Base
// ============================================================

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

/// Module Python principal
#[pymodule]
fn hackbrain_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(fibonacci, m)?)?;
    m.add_function(wrap_pyfunction!(prime_sieve, m)?)?;
    m.add_class::<RustVec>()?;
    m.add_class::<RustHashMap>()?;
    m.add_class::<BinarySearchTree>()?;
    m.add_class::<Graph>()?;
    Ok(())
}

/// Calcule le n-ième nombre de Fibonacci
/// Exposé à Python comme: hackbrain_rust.fibonacci(n)
///
/// Complexité: O(n) temps, O(1) espace (version itérative)
#[pyfunction]
pub fn fibonacci(n: u64) -> PyResult<u64> {
    if n > 93 {
        return Err(PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
            "Fibonacci overflow for n > 93 with u64"
        ));
    }
    // TODO: Implémenter
    Ok(0)
}

/// Crible d'Ératosthène optimisé
/// Retourne tous les nombres premiers jusqu'à limit
///
/// Complexité: O(n log log n) temps, O(n) espace
#[pyfunction]
pub fn prime_sieve(limit: usize) -> PyResult<Vec<usize>> {
    // TODO: Implémenter
    Ok(vec![])
}

/// Tri rapide avec statistiques
/// Retourne (sorted_array, comparisons, swaps)
#[pyfunction]
pub fn quicksort_with_stats(arr: Vec<i64>) -> PyResult<(Vec<i64>, usize, usize)> {
    // TODO: Implémenter
    Ok((vec![], 0, 0))
}

// ============================================================
// PARTIE B: Structures de Données Exposées à Python
// ============================================================

/// Vec<T> Rust exposé à Python avec interface pythonique
///
/// Supporte: indexing, iteration, len(), append(), extend()
#[pyclass]
pub struct RustVec {
    inner: Vec<i64>,
}

#[pymethods]
impl RustVec {
    #[new]
    pub fn new() -> Self {
        RustVec { inner: Vec::new() }
    }

    /// Crée depuis une liste Python
    #[staticmethod]
    pub fn from_list(list: Vec<i64>) -> Self {
        RustVec { inner: list }
    }

    /// Ajoute un élément
    pub fn push(&mut self, value: i64) {
        self.inner.push(value);
    }

    /// Retire et retourne le dernier élément
    pub fn pop(&mut self) -> PyResult<i64> {
        self.inner.pop().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyIndexError, _>("pop from empty vector")
        })
    }

    /// Accès par index (Python: vec[i])
    pub fn __getitem__(&self, idx: isize) -> PyResult<i64> {
        let len = self.inner.len() as isize;
        let actual_idx = if idx < 0 { len + idx } else { idx } as usize;

        self.inner.get(actual_idx).copied().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyIndexError, _>("index out of range")
        })
    }

    /// Modification par index (Python: vec[i] = val)
    pub fn __setitem__(&mut self, idx: isize, value: i64) -> PyResult<()> {
        let len = self.inner.len() as isize;
        let actual_idx = if idx < 0 { len + idx } else { idx } as usize;

        if actual_idx < self.inner.len() {
            self.inner[actual_idx] = value;
            Ok(())
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyIndexError, _>("index out of range"))
        }
    }

    /// Longueur (Python: len(vec))
    pub fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Itération (Python: for x in vec)
    pub fn __iter__(slf: PyRef<'_, Self>) -> PyResult<RustVecIterator> {
        Ok(RustVecIterator {
            inner: slf.inner.clone().into_iter(),
        })
    }

    /// Représentation string (Python: repr(vec))
    pub fn __repr__(&self) -> String {
        format!("RustVec({:?})", self.inner)
    }

    /// Tri sur place
    pub fn sort(&mut self) {
        self.inner.sort();
    }

    /// Recherche binaire (requiert vec trié)
    pub fn binary_search(&self, target: i64) -> PyResult<Option<usize>> {
        match self.inner.binary_search(&target) {
            Ok(idx) => Ok(Some(idx)),
            Err(_) => Ok(None),
        }
    }

    /// Conversion vers liste Python
    pub fn to_list(&self) -> Vec<i64> {
        self.inner.clone()
    }
}

#[pyclass]
pub struct RustVecIterator {
    inner: std::vec::IntoIter<i64>,
}

#[pymethods]
impl RustVecIterator {
    pub fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    pub fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<i64> {
        slf.inner.next()
    }
}

// ============================================================
// PARTIE C: HashMap Rust avec Interface Pythonique
// ============================================================

use std::collections::HashMap;

/// HashMap Rust exposé à Python
///
/// Supporte: dict-like access, iteration, keys(), values(), items()
#[pyclass]
pub struct RustHashMap {
    inner: HashMap<String, i64>,
}

#[pymethods]
impl RustHashMap {
    #[new]
    pub fn new() -> Self {
        RustHashMap { inner: HashMap::new() }
    }

    /// Crée depuis un dict Python
    #[staticmethod]
    pub fn from_dict(dict: HashMap<String, i64>) -> Self {
        RustHashMap { inner: dict }
    }

    /// Insertion (Python: map[key] = value)
    pub fn __setitem__(&mut self, key: String, value: i64) {
        self.inner.insert(key, value);
    }

    /// Accès (Python: map[key])
    pub fn __getitem__(&self, key: &str) -> PyResult<i64> {
        self.inner.get(key).copied().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyKeyError, _>(key.to_string())
        })
    }

    /// Suppression (Python: del map[key])
    pub fn __delitem__(&mut self, key: &str) -> PyResult<()> {
        self.inner.remove(key).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyKeyError, _>(key.to_string())
        })?;
        Ok(())
    }

    /// Appartenance (Python: key in map)
    pub fn __contains__(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Longueur
    pub fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Retourne les clés
    pub fn keys(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }

    /// Retourne les valeurs
    pub fn values(&self) -> Vec<i64> {
        self.inner.values().copied().collect()
    }

    /// Retourne les paires (key, value)
    pub fn items(&self) -> Vec<(String, i64)> {
        self.inner.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// get() avec valeur par défaut
    pub fn get(&self, key: &str, default: Option<i64>) -> Option<i64> {
        self.inner.get(key).copied().or(default)
    }

    pub fn __repr__(&self) -> String {
        format!("RustHashMap({:?})", self.inner)
    }
}

// ============================================================
// PARTIE D: Binary Search Tree
// ============================================================

/// Noeud BST interne
struct BstNode {
    value: i64,
    left: Option<Box<BstNode>>,
    right: Option<Box<BstNode>>,
}

/// Binary Search Tree exposé à Python
#[pyclass]
pub struct BinarySearchTree {
    root: Option<Box<BstNode>>,
    size: usize,
}

#[pymethods]
impl BinarySearchTree {
    #[new]
    pub fn new() -> Self {
        BinarySearchTree { root: None, size: 0 }
    }

    /// Insère une valeur
    /// Complexité: O(h) où h = hauteur
    pub fn insert(&mut self, value: i64) {
        // TODO: Implémenter insertion BST
    }

    /// Recherche une valeur
    /// Complexité: O(h)
    pub fn contains(&self, value: i64) -> bool {
        // TODO: Implémenter recherche BST
        false
    }

    /// Supprime une valeur
    /// Complexité: O(h)
    pub fn remove(&mut self, value: i64) -> bool {
        // TODO: Implémenter suppression BST
        false
    }

    /// Parcours in-order (retourne liste triée)
    pub fn inorder(&self) -> Vec<i64> {
        // TODO: Implémenter parcours
        vec![]
    }

    /// Parcours level-order (BFS)
    pub fn levelorder(&self) -> Vec<i64> {
        // TODO: Implémenter BFS
        vec![]
    }

    /// Hauteur de l'arbre
    pub fn height(&self) -> usize {
        // TODO: Implémenter
        0
    }

    /// Nombre d'éléments
    pub fn __len__(&self) -> usize {
        self.size
    }

    /// Test d'appartenance
    pub fn __contains__(&self, value: i64) -> bool {
        self.contains(value)
    }

    /// Minimum
    pub fn min(&self) -> PyResult<i64> {
        // TODO: Implémenter
        Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("empty tree"))
    }

    /// Maximum
    pub fn max(&self) -> PyResult<i64> {
        // TODO: Implémenter
        Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("empty tree"))
    }
}

// ============================================================
// PARTIE E: Graph avec Algorithmes
// ============================================================

/// Graphe orienté pondéré exposé à Python
#[pyclass]
pub struct Graph {
    adjacency: HashMap<usize, Vec<(usize, f64)>>,
    node_count: usize,
}

#[pymethods]
impl Graph {
    #[new]
    pub fn new() -> Self {
        Graph {
            adjacency: HashMap::new(),
            node_count: 0,
        }
    }

    /// Ajoute un noeud
    pub fn add_node(&mut self, node: usize) {
        if !self.adjacency.contains_key(&node) {
            self.adjacency.insert(node, Vec::new());
            self.node_count += 1;
        }
    }

    /// Ajoute une arête pondérée
    pub fn add_edge(&mut self, from: usize, to: usize, weight: f64) {
        self.add_node(from);
        self.add_node(to);
        self.adjacency.get_mut(&from).unwrap().push((to, weight));
    }

    /// Ajoute une arête non-orientée
    pub fn add_undirected_edge(&mut self, a: usize, b: usize, weight: f64) {
        self.add_edge(a, b, weight);
        self.add_edge(b, a, weight);
    }

    /// BFS depuis un noeud source
    /// Retourne l'ordre de visite
    pub fn bfs(&self, start: usize) -> PyResult<Vec<usize>> {
        // TODO: Implémenter BFS
        Ok(vec![])
    }

    /// DFS depuis un noeud source
    /// Retourne l'ordre de visite
    pub fn dfs(&self, start: usize) -> PyResult<Vec<usize>> {
        // TODO: Implémenter DFS
        Ok(vec![])
    }

    /// Dijkstra: plus court chemin
    /// Retourne (distances, predecessors)
    pub fn dijkstra(&self, start: usize) -> PyResult<(HashMap<usize, f64>, HashMap<usize, usize>)> {
        // TODO: Implémenter Dijkstra
        Ok((HashMap::new(), HashMap::new()))
    }

    /// Reconstruit le chemin depuis Dijkstra
    pub fn shortest_path(&self, start: usize, end: usize) -> PyResult<Option<Vec<usize>>> {
        // TODO: Utiliser dijkstra pour reconstruire
        Ok(None)
    }

    /// Détection de cycle (DFS)
    pub fn has_cycle(&self) -> bool {
        // TODO: Implémenter
        false
    }

    /// Tri topologique (pour DAG)
    pub fn topological_sort(&self) -> PyResult<Vec<usize>> {
        // TODO: Implémenter Kahn ou DFS-based
        Ok(vec![])
    }

    /// Composantes fortement connexes (Kosaraju)
    pub fn strongly_connected_components(&self) -> Vec<Vec<usize>> {
        // TODO: Implémenter Kosaraju
        vec![]
    }

    /// Nombre de noeuds
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Nombre d'arêtes
    pub fn edge_count(&self) -> usize {
        self.adjacency.values().map(|v| v.len()).sum()
    }

    pub fn __repr__(&self) -> String {
        format!("Graph(nodes={}, edges={})", self.node_count(), self.edge_count())
    }
}

// ============================================================
// PARTIE F: Parallélisme et GIL
// ============================================================

use pyo3::Python;
use rayon::prelude::*;

/// Tri parallèle avec release du GIL
///
/// Libère le GIL pendant le calcul Rust pour permettre
/// à d'autres threads Python de s'exécuter
#[pyfunction]
pub fn parallel_sort(py: Python<'_>, arr: Vec<i64>) -> PyResult<Vec<i64>> {
    // Release GIL pour le calcul parallèle
    py.allow_threads(|| {
        let mut sorted = arr;
        sorted.par_sort();
        Ok(sorted)
    })
}

/// Map parallèle avec fonction Python
///
/// Note: Doit acquérir le GIL pour chaque appel Python
#[pyfunction]
pub fn parallel_map(
    py: Python<'_>,
    items: Vec<i64>,
    func: PyObject,
) -> PyResult<Vec<PyObject>> {
    // Pour chaque item, on doit appeler Python
    // donc pas de parallélisme réel ici (GIL required)
    items
        .into_iter()
        .map(|item| func.call1(py, (item,)))
        .collect()
}

/// Calcul intensif en Rust (libère GIL)
#[pyfunction]
pub fn compute_intensive(py: Python<'_>, n: u64) -> PyResult<u64> {
    py.allow_threads(|| {
        // Simulation d'un calcul lourd
        let mut result: u64 = 0;
        for i in 0..n {
            result = result.wrapping_add(i.wrapping_mul(i));
        }
        Ok(result)
    })
}

// ============================================================
// PARTIE G: Gestion d'Erreurs Cross-Language
// ============================================================

/// Exception personnalisée Rust → Python
use pyo3::create_exception;

create_exception!(hackbrain_rust, RustError, pyo3::exceptions::PyException);
create_exception!(hackbrain_rust, GraphCycleError, pyo3::exceptions::PyValueError);
create_exception!(hackbrain_rust, EmptyStructureError, pyo3::exceptions::PyIndexError);

/// Fonction démontrant la propagation d'erreurs
#[pyfunction]
pub fn may_fail(should_fail: bool) -> PyResult<String> {
    if should_fail {
        Err(RustError::new_err("Intentional failure from Rust"))
    } else {
        Ok("Success!".to_string())
    }
}

/// Division sécurisée avec erreur explicite
#[pyfunction]
pub fn safe_divide(a: f64, b: f64) -> PyResult<f64> {
    if b == 0.0 {
        Err(PyErr::new::<pyo3::exceptions::PyZeroDivisionError, _>(
            "division by zero"
        ))
    } else {
        Ok(a / b)
    }
}
```

### Fonctions à Implémenter (C - Python C API pour comparaison)

```c
// ============================================================
// Extension Python en C (pour comparaison avec PyO3)
// ============================================================

#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Structure pour un vecteur
typedef struct {
    PyObject_HEAD
    int64_t* data;
    size_t size;
    size_t capacity;
} CVec;

// Méthodes du type CVec
static PyObject* CVec_new(PyTypeObject* type, PyObject* args, PyObject* kwds);
static int CVec_init(CVec* self, PyObject* args, PyObject* kwds);
static void CVec_dealloc(CVec* self);
static PyObject* CVec_push(CVec* self, PyObject* args);
static PyObject* CVec_pop(CVec* self, PyObject* args);
static Py_ssize_t CVec_length(CVec* self);
static PyObject* CVec_getitem(CVec* self, Py_ssize_t index);
static int CVec_setitem(CVec* self, Py_ssize_t index, PyObject* value);

// Sequence protocol
static PySequenceMethods CVec_as_sequence = {
    .sq_length = (lenfunc)CVec_length,
    .sq_item = (ssizeargfunc)CVec_getitem,
    .sq_ass_item = (ssizeobjargproc)CVec_setitem,
};

// Définition des méthodes
static PyMethodDef CVec_methods[] = {
    {"push", (PyCFunction)CVec_push, METH_VARARGS, "Add element"},
    {"pop", (PyCFunction)CVec_pop, METH_NOARGS, "Remove and return last"},
    {NULL}
};

// Type definition
static PyTypeObject CVecType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "hackbrain_c.CVec",
    .tp_doc = "C Vector type",
    .tp_basicsize = sizeof(CVec),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = CVec_new,
    .tp_init = (initproc)CVec_init,
    .tp_dealloc = (destructor)CVec_dealloc,
    .tp_methods = CVec_methods,
    .tp_as_sequence = &CVec_as_sequence,
};

// Implémentations

static PyObject* CVec_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
    CVec* self = (CVec*)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->data = NULL;
        self->size = 0;
        self->capacity = 0;
    }
    return (PyObject*)self;
}

static int CVec_init(CVec* self, PyObject* args, PyObject* kwds) {
    self->capacity = 16;
    self->data = (int64_t*)malloc(self->capacity * sizeof(int64_t));
    if (self->data == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    self->size = 0;
    return 0;
}

static void CVec_dealloc(CVec* self) {
    free(self->data);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* CVec_push(CVec* self, PyObject* args) {
    int64_t value;
    if (!PyArg_ParseTuple(args, "L", &value)) {
        return NULL;
    }

    // Resize si nécessaire
    if (self->size >= self->capacity) {
        self->capacity *= 2;
        int64_t* new_data = realloc(self->data, self->capacity * sizeof(int64_t));
        if (new_data == NULL) {
            PyErr_NoMemory();
            return NULL;
        }
        self->data = new_data;
    }

    self->data[self->size++] = value;
    Py_RETURN_NONE;
}

static PyObject* CVec_pop(CVec* self, PyObject* args) {
    if (self->size == 0) {
        PyErr_SetString(PyExc_IndexError, "pop from empty vector");
        return NULL;
    }
    return PyLong_FromLongLong(self->data[--self->size]);
}

static Py_ssize_t CVec_length(CVec* self) {
    return (Py_ssize_t)self->size;
}

static PyObject* CVec_getitem(CVec* self, Py_ssize_t index) {
    if (index < 0) index += self->size;
    if (index < 0 || (size_t)index >= self->size) {
        PyErr_SetString(PyExc_IndexError, "index out of range");
        return NULL;
    }
    return PyLong_FromLongLong(self->data[index]);
}

static int CVec_setitem(CVec* self, Py_ssize_t index, PyObject* value) {
    if (index < 0) index += self->size;
    if (index < 0 || (size_t)index >= self->size) {
        PyErr_SetString(PyExc_IndexError, "index out of range");
        return -1;
    }

    int64_t val = PyLong_AsLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }

    self->data[index] = val;
    return 0;
}

// Module definition
static PyModuleDef hackbrain_c_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "hackbrain_c",
    .m_doc = "C extension for comparison with PyO3",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit_hackbrain_c(void) {
    PyObject* m;

    if (PyType_Ready(&CVecType) < 0) {
        return NULL;
    }

    m = PyModule_Create(&hackbrain_c_module);
    if (m == NULL) {
        return NULL;
    }

    Py_INCREF(&CVecType);
    if (PyModule_AddObject(m, "CVec", (PyObject*)&CVecType) < 0) {
        Py_DECREF(&CVecType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
```

---

# Section 2: Le Saviez-Vous ?

## Faits Techniques

1. **PyO3 Origins**: PyO3 a commencé comme un fork de rust-cpython en 2017, visant une API plus ergonomique et une meilleure intégration avec l'écosystème Rust.

2. **GIL Performance**: Le GIL de Python permet ~100M opérations bytecode par seconde, mais avec PyO3/Rust vous pouvez atteindre des milliards d'opérations par seconde en libérant le GIL.

3. **Memory Layout**: Les objets Python ont un overhead de 16-28 bytes minimum. Les types Rust wrappés par PyO3 ajoutent ~8 bytes supplémentaires pour le refcount.

4. **Adoption**: Des projets majeurs utilisent PyO3: Polars (DataFrame library), Pydantic v2, Ruff (Python linter), cryptography, orjson.

5. **Compilation**: PyO3 supporte maturin pour le packaging, permettant la distribution via pip avec des wheels pré-compilés pour toutes les plateformes.

## Anecdotes

- **Polars vs Pandas**: Polars (écrit en Rust avec PyO3) est 10-100x plus rapide que Pandas pour certaines opérations, tout en utilisant moins de mémoire.

- **Le cas orjson**: orjson (JSON parser en Rust/PyO3) est 3x plus rapide que ujson et 10x plus rapide que le json standard.

---

# Section 2.5: Dans la Vraie Vie

## Applications Industrielles

### 1. Data Science Performance
- **Polars**: DataFrame library rivale de Pandas
- **Lance**: Format de données pour ML, 10x plus rapide que Parquet

### 2. Sécurité et Cryptographie
- **cryptography**: Bibliothèque crypto Python avec backend Rust
- **PyNaCl**: Bindings pour libsodium via Rust

### 3. Outils de Développement
- **Ruff**: Linter Python 100x plus rapide que flake8
- **uv**: Package manager Python plus rapide que pip

---

# Section 3: Exemple d'Utilisation

```bash
$ cd hackbrain_rust
$ maturin develop --release

$ python3
>>> import hackbrain_rust as hr

>>> hr.fibonacci(10)
55

>>> hr.fibonacci(50)
12586269025

>>> hr.fibonacci(94)
Traceback (most recent call last):
  ...
OverflowError: Fibonacci overflow for n > 93 with u64

>>> primes = hr.prime_sieve(100)
>>> primes
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

>>> v = hr.RustVec()
>>> v.push(10)
>>> v.push(20)
>>> v.push(30)
>>> len(v)
3
>>> v[0]
10
>>> v[-1]
30
>>> v[1] = 25
>>> list(v)
[10, 25, 30]
>>> v.sort()
>>> v.to_list()
[10, 25, 30]

>>> m = hr.RustHashMap()
>>> m["alice"] = 100
>>> m["bob"] = 200
>>> "alice" in m
True
>>> m["alice"]
100
>>> m.keys()
['alice', 'bob']
>>> m.get("charlie", -1)
-1

>>> bst = hr.BinarySearchTree()
>>> for x in [5, 3, 7, 1, 4, 6, 8]:
...     bst.insert(x)
>>> bst.inorder()
[1, 3, 4, 5, 6, 7, 8]
>>> 4 in bst
True
>>> bst.height()
3
>>> bst.min()
1
>>> bst.max()
8

>>> g = hr.Graph()
>>> g.add_edge(0, 1, 4.0)
>>> g.add_edge(0, 2, 1.0)
>>> g.add_edge(2, 1, 2.0)
>>> g.add_edge(1, 3, 1.0)
>>> g.add_edge(2, 3, 5.0)
>>> g.bfs(0)
[0, 1, 2, 3]
>>> distances, _ = g.dijkstra(0)
>>> distances
{0: 0.0, 1: 3.0, 2: 1.0, 3: 4.0}
>>> g.shortest_path(0, 3)
[0, 2, 1, 3]

>>> import time
>>> arr = list(range(10_000_000, 0, -1))
>>> start = time.time()
>>> sorted_arr = hr.parallel_sort(arr)
>>> print(f"Time: {time.time() - start:.3f}s")
Time: 0.312s
>>> sorted_arr[:5]
[1, 2, 3, 4, 5]
```

---

# Section 3.1: Bonus Avancé

## Bonus 1: Custom Numpy Integration (200 XP)

```rust
use numpy::{PyArray1, PyReadonlyArray1};

/// Opération vectorielle sur numpy arrays
#[pyfunction]
pub fn numpy_add_scalar<'py>(
    py: Python<'py>,
    arr: PyReadonlyArray1<'py, f64>,
    scalar: f64,
) -> &'py PyArray1<f64> {
    let result: Vec<f64> = arr.as_array()
        .iter()
        .map(|&x| x + scalar)
        .collect();
    PyArray1::from_vec(py, result)
}

/// Dot product optimisé
#[pyfunction]
pub fn fast_dot(
    a: PyReadonlyArray1<'_, f64>,
    b: PyReadonlyArray1<'_, f64>,
) -> PyResult<f64> {
    // TODO: Implémenter avec SIMD si disponible
    Ok(0.0)
}
```

## Bonus 2: Async Python Integration (250 XP)

```rust
use pyo3_asyncio::tokio::future_into_py;

/// Fonction async Rust exposée à Python asyncio
#[pyfunction]
pub fn async_fetch(py: Python<'_>, url: String) -> PyResult<&PyAny> {
    future_into_py(py, async move {
        // Simulation d'I/O async
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(format!("Fetched: {}", url))
    })
}
```

## Bonus 3: Benchmark Suite (150 XP)

```rust
/// Compare les performances Rust vs Python natif
#[pyfunction]
pub fn benchmark_fibonacci(n: u64, iterations: u32) -> PyResult<(f64, f64)> {
    // TODO: Mesurer temps Rust
    // TODO: Appeler impl Python et mesurer
    // Retourner (rust_time_ms, python_time_ms)
    Ok((0.0, 0.0))
}
```

---

# Section 4: Zone Correction

## 4.1 Tests Unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_base_cases() {
        pyo3::prepare_freethreaded_python();
        assert_eq!(fibonacci(0).unwrap(), 0);
        assert_eq!(fibonacci(1).unwrap(), 1);
        assert_eq!(fibonacci(2).unwrap(), 1);
    }

    #[test]
    fn test_fibonacci_known_values() {
        pyo3::prepare_freethreaded_python();
        assert_eq!(fibonacci(10).unwrap(), 55);
        assert_eq!(fibonacci(20).unwrap(), 6765);
        assert_eq!(fibonacci(50).unwrap(), 12586269025);
    }

    #[test]
    fn test_fibonacci_overflow() {
        pyo3::prepare_freethreaded_python();
        assert!(fibonacci(94).is_err());
    }

    #[test]
    fn test_prime_sieve() {
        pyo3::prepare_freethreaded_python();
        let primes = prime_sieve(30).unwrap();
        assert_eq!(primes, vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29]);
    }

    #[test]
    fn test_prime_sieve_edge() {
        pyo3::prepare_freethreaded_python();
        assert_eq!(prime_sieve(0).unwrap(), vec![]);
        assert_eq!(prime_sieve(1).unwrap(), vec![]);
        assert_eq!(prime_sieve(2).unwrap(), vec![2]);
    }

    #[test]
    fn test_rust_vec_basic() {
        let mut v = RustVec::new();
        v.push(1);
        v.push(2);
        v.push(3);
        assert_eq!(v.__len__(), 3);
        assert_eq!(v.__getitem__(0).unwrap(), 1);
        assert_eq!(v.__getitem__(-1).unwrap(), 3);
    }

    #[test]
    fn test_rust_vec_indexing() {
        let v = RustVec::from_list(vec![10, 20, 30]);
        assert_eq!(v.__getitem__(0).unwrap(), 10);
        assert_eq!(v.__getitem__(1).unwrap(), 20);
        assert_eq!(v.__getitem__(2).unwrap(), 30);
        assert_eq!(v.__getitem__(-1).unwrap(), 30);
        assert_eq!(v.__getitem__(-3).unwrap(), 10);
    }

    #[test]
    fn test_rust_vec_out_of_bounds() {
        let v = RustVec::from_list(vec![1, 2, 3]);
        assert!(v.__getitem__(5).is_err());
        assert!(v.__getitem__(-10).is_err());
    }

    #[test]
    fn test_rust_hashmap() {
        let mut m = RustHashMap::new();
        m.__setitem__("a".to_string(), 1);
        m.__setitem__("b".to_string(), 2);
        assert_eq!(m.__getitem__("a").unwrap(), 1);
        assert!(m.__contains__("a"));
        assert!(!m.__contains__("c"));
    }

    #[test]
    fn test_bst_operations() {
        let mut bst = BinarySearchTree::new();
        bst.insert(5);
        bst.insert(3);
        bst.insert(7);
        bst.insert(1);
        bst.insert(4);

        assert!(bst.contains(5));
        assert!(bst.contains(3));
        assert!(!bst.contains(10));
        assert_eq!(bst.__len__(), 5);
        assert_eq!(bst.inorder(), vec![1, 3, 4, 5, 7]);
    }

    #[test]
    fn test_graph_bfs() {
        let mut g = Graph::new();
        g.add_edge(0, 1, 1.0);
        g.add_edge(0, 2, 1.0);
        g.add_edge(1, 3, 1.0);
        g.add_edge(2, 3, 1.0);

        let order = g.bfs(0).unwrap();
        assert_eq!(order[0], 0);
        assert!(order.contains(&1));
        assert!(order.contains(&2));
        assert!(order.contains(&3));
    }

    #[test]
    fn test_dijkstra() {
        let mut g = Graph::new();
        g.add_edge(0, 1, 4.0);
        g.add_edge(0, 2, 1.0);
        g.add_edge(2, 1, 2.0);
        g.add_edge(1, 3, 1.0);
        g.add_edge(2, 3, 5.0);

        let (distances, _) = g.dijkstra(0).unwrap();
        assert_eq!(distances[&0], 0.0);
        assert_eq!(distances[&1], 3.0);  // 0->2->1
        assert_eq!(distances[&2], 1.0);
        assert_eq!(distances[&3], 4.0);  // 0->2->1->3
    }
}
```

## 4.2 Tests Python

```python
# test_hackbrain_rust.py
import pytest
import hackbrain_rust as hr

class TestFibonacci:
    def test_base_cases(self):
        assert hr.fibonacci(0) == 0
        assert hr.fibonacci(1) == 1

    def test_known_values(self):
        assert hr.fibonacci(10) == 55
        assert hr.fibonacci(20) == 6765

    def test_overflow(self):
        with pytest.raises(OverflowError):
            hr.fibonacci(94)

class TestRustVec:
    def test_push_pop(self):
        v = hr.RustVec()
        v.push(1)
        v.push(2)
        assert v.pop() == 2
        assert v.pop() == 1

    def test_indexing(self):
        v = hr.RustVec.from_list([10, 20, 30])
        assert v[0] == 10
        assert v[-1] == 30

    def test_iteration(self):
        v = hr.RustVec.from_list([1, 2, 3])
        assert list(v) == [1, 2, 3]

    def test_len(self):
        v = hr.RustVec.from_list([1, 2, 3, 4, 5])
        assert len(v) == 5

class TestRustHashMap:
    def test_basic_operations(self):
        m = hr.RustHashMap()
        m["key"] = 42
        assert m["key"] == 42
        assert "key" in m

    def test_keys_values(self):
        m = hr.RustHashMap.from_dict({"a": 1, "b": 2})
        assert set(m.keys()) == {"a", "b"}
        assert set(m.values()) == {1, 2}

class TestBST:
    def test_insert_contains(self):
        bst = hr.BinarySearchTree()
        for x in [5, 3, 7, 1, 4]:
            bst.insert(x)
        assert 5 in bst
        assert 10 not in bst

    def test_inorder(self):
        bst = hr.BinarySearchTree()
        for x in [5, 3, 7, 1, 4, 6, 8]:
            bst.insert(x)
        assert bst.inorder() == [1, 3, 4, 5, 6, 7, 8]

class TestGraph:
    def test_dijkstra(self):
        g = hr.Graph()
        g.add_edge(0, 1, 4.0)
        g.add_edge(0, 2, 1.0)
        g.add_edge(2, 1, 2.0)
        distances, _ = g.dijkstra(0)
        assert distances[0] == 0.0
        assert distances[1] == 3.0
        assert distances[2] == 1.0

class TestPerformance:
    def test_parallel_sort(self):
        import random
        arr = list(range(100000, 0, -1))
        sorted_arr = hr.parallel_sort(arr)
        assert sorted_arr == list(range(1, 100001))
```

## 4.3 Solution de Référence

```rust
// fibonacci - solution de référence
pub fn fibonacci_reference(n: u64) -> PyResult<u64> {
    if n > 93 {
        return Err(PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
            "Fibonacci overflow for n > 93 with u64"
        ));
    }

    if n <= 1 {
        return Ok(n);
    }

    let mut prev = 0u64;
    let mut curr = 1u64;

    for _ in 2..=n {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }

    Ok(curr)
}

// prime_sieve - solution de référence
pub fn prime_sieve_reference(limit: usize) -> PyResult<Vec<usize>> {
    if limit < 2 {
        return Ok(vec![]);
    }

    let mut is_prime = vec![true; limit + 1];
    is_prime[0] = false;
    is_prime[1] = false;

    let sqrt_limit = (limit as f64).sqrt() as usize;
    for i in 2..=sqrt_limit {
        if is_prime[i] {
            for j in (i * i..=limit).step_by(i) {
                is_prime[j] = false;
            }
        }
    }

    Ok(is_prime.iter()
        .enumerate()
        .filter_map(|(i, &prime)| if prime { Some(i) } else { None })
        .collect())
}

// BST insert - solution de référence
impl BinarySearchTree {
    pub fn insert_reference(&mut self, value: i64) {
        fn insert_node(node: &mut Option<Box<BstNode>>, value: i64) {
            match node {
                None => {
                    *node = Some(Box::new(BstNode {
                        value,
                        left: None,
                        right: None,
                    }));
                }
                Some(n) => {
                    if value < n.value {
                        insert_node(&mut n.left, value);
                    } else if value > n.value {
                        insert_node(&mut n.right, value);
                    }
                    // Ignore duplicates
                }
            }
        }
        insert_node(&mut self.root, value);
        self.size += 1;
    }

    pub fn inorder_reference(&self) -> Vec<i64> {
        fn traverse(node: &Option<Box<BstNode>>, result: &mut Vec<i64>) {
            if let Some(n) = node {
                traverse(&n.left, result);
                result.push(n.value);
                traverse(&n.right, result);
            }
        }
        let mut result = Vec::new();
        traverse(&self.root, &mut result);
        result
    }
}

// Dijkstra - solution de référence
impl Graph {
    pub fn dijkstra_reference(&self, start: usize) -> PyResult<(HashMap<usize, f64>, HashMap<usize, usize>)> {
        use std::cmp::Ordering;
        use std::collections::BinaryHeap;

        #[derive(PartialEq)]
        struct State {
            cost: f64,
            node: usize,
        }

        impl Eq for State {}

        impl Ord for State {
            fn cmp(&self, other: &Self) -> Ordering {
                other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
            }
        }

        impl PartialOrd for State {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut distances: HashMap<usize, f64> = HashMap::new();
        let mut predecessors: HashMap<usize, usize> = HashMap::new();
        let mut heap = BinaryHeap::new();

        distances.insert(start, 0.0);
        heap.push(State { cost: 0.0, node: start });

        while let Some(State { cost, node }) = heap.pop() {
            if cost > *distances.get(&node).unwrap_or(&f64::INFINITY) {
                continue;
            }

            if let Some(neighbors) = self.adjacency.get(&node) {
                for &(next, weight) in neighbors {
                    let next_cost = cost + weight;
                    if next_cost < *distances.get(&next).unwrap_or(&f64::INFINITY) {
                        distances.insert(next, next_cost);
                        predecessors.insert(next, node);
                        heap.push(State { cost: next_cost, node: next });
                    }
                }
            }
        }

        Ok((distances, predecessors))
    }
}
```

## 4.4 Mutants

```rust
// MUTANT 1: Off-by-one dans fibonacci
pub fn fibonacci_mutant1(n: u64) -> PyResult<u64> {
    if n <= 1 { return Ok(n); }
    let mut prev = 0u64;
    let mut curr = 1u64;
    for _ in 2..n {  // BUG: should be 2..=n
        let next = prev + curr;
        prev = curr;
        curr = next;
    }
    Ok(curr)
}

// MUTANT 2: Wrong sieve initialization
pub fn prime_sieve_mutant2(limit: usize) -> PyResult<Vec<usize>> {
    let mut is_prime = vec![false; limit + 1];  // BUG: should be true
    is_prime[0] = false;
    is_prime[1] = false;
    // ... rest same
    Ok(vec![])
}

// MUTANT 3: BST insert without size update
impl BinarySearchTree {
    pub fn insert_mutant3(&mut self, value: i64) {
        // ... insert logic ...
        // BUG: Missing self.size += 1;
    }
}

// MUTANT 4: Dijkstra with wrong comparison
impl Graph {
    pub fn dijkstra_mutant4(&self, start: usize) -> PyResult<(HashMap<usize, f64>, HashMap<usize, usize>)> {
        // ... setup ...
        // BUG: cost >= instead of cost >
        // if cost >= *distances.get(&node).unwrap_or(&f64::INFINITY)
        Ok((HashMap::new(), HashMap::new()))
    }
}

// MUTANT 5: RustVec negative index wrong
impl RustVec {
    pub fn __getitem___mutant5(&self, idx: isize) -> PyResult<i64> {
        let len = self.inner.len() as isize;
        let actual_idx = if idx < 0 { len - idx } else { idx } as usize;  // BUG: should be len + idx
        self.inner.get(actual_idx).copied().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyIndexError, _>("index out of range")
        })
    }
}
```

---

# Section 5: Comprendre

## 5.1 Architecture PyO3

```
┌────────────────────────────────────────────────────────────────────┐
│                         Python Interpreter                          │
├────────────────────────────────────────────────────────────────────┤
│  Python Code                                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ import hackbrain_rust                                        │   │
│  │ v = hackbrain_rust.RustVec()                                │   │
│  │ v.push(42)                                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────────────┤
│                         PyO3 Layer                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Type Conversion: Python objects <-> Rust types              │   │
│  │ GIL Management: acquire/release                              │   │
│  │ Error Handling: PyResult <-> Python exceptions              │   │
│  │ Memory: Python refcounting + Rust ownership                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────────────┤
│                         Rust Code                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ #[pyclass] struct RustVec { inner: Vec<i64> }              │   │
│  │ #[pymethods] impl RustVec { fn push(&mut self, v: i64) }   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

## 5.2 Le GIL (Global Interpreter Lock)

```
AVEC GIL (comportement par défaut)
──────────────────────────────────
Thread 1: [====Python====][====Python====][====Python====]
Thread 2:                 [====Python====]
Thread 3:                                 [====Python====]
          ↑ Un seul thread exécute Python à la fois

SANS GIL (py.allow_threads)
──────────────────────────
Thread 1: [Python][====Rust====][Python]
Thread 2: [Python][====Rust====][Python]
Thread 3: [Python][====Rust====][Python]
                  ↑ Rust s'exécute en parallèle
```

### Quand libérer le GIL

```rust
// BON: Calcul pur Rust, pas d'accès Python
#[pyfunction]
fn compute_intensive(py: Python<'_>, n: u64) -> PyResult<u64> {
    py.allow_threads(|| {
        let mut sum = 0u64;
        for i in 0..n { sum += i; }
        Ok(sum)
    })
}

// MAUVAIS: Accès à des objets Python
#[pyfunction]
fn bad_gil_release(py: Python<'_>, list: &PyList) -> PyResult<()> {
    py.allow_threads(|| {
        // CRASH: list requires GIL
        list.len()  // Undefined behavior!
    });
    Ok(())
}
```

## 5.3 Conversion de Types

| Python | Rust (auto-convert) | Notes |
|--------|---------------------|-------|
| `int` | `i32, i64, u32, u64, ...` | Overflow check |
| `float` | `f32, f64` | |
| `str` | `String, &str` | UTF-8 validated |
| `bool` | `bool` | |
| `list` | `Vec<T>` | Copies data |
| `dict` | `HashMap<K, V>` | Copies data |
| `bytes` | `Vec<u8>, &[u8]` | |
| `None` | `Option<T>` | |

## 5.4 Gestion Mémoire

```
Python Object                Rust Wrapper
┌─────────────────┐         ┌─────────────────┐
│ PyObject Header │         │ #[pyclass]      │
│ - refcount      │◀────────│ struct RustVec  │
│ - type pointer  │         │ {               │
├─────────────────┤         │   inner: Vec<T> │
│ RustVec data    │         │ }               │
│ (embedded)      │         └─────────────────┘
└─────────────────┘

Cycle de vie:
1. Python crée l'objet via __new__
2. Rust initialise via __init__
3. Python gère le refcount
4. Quand refcount = 0, Rust drop() est appelé
```

---

# Section 6: Pièges

## 6.1 Piège: Copie Implicite

```rust
// PIÈGE: Cette fonction copie toute la liste!
#[pyfunction]
fn sum_list(list: Vec<i64>) -> i64 {
    list.iter().sum()
}

// MIEUX: Utiliser une référence
#[pyfunction]
fn sum_list_better(list: &PyList) -> PyResult<i64> {
    let mut sum = 0i64;
    for item in list.iter() {
        sum += item.extract::<i64>()?;
    }
    Ok(sum)
}
```

## 6.2 Piège: GIL Deadlock

```rust
// PIÈGE: Deadlock potentiel
#[pyfunction]
fn dangerous(py: Python<'_>) -> PyResult<()> {
    py.allow_threads(|| {
        // Dans un autre thread...
        Python::with_gil(|py2| {
            // Essaie de réacquérir le GIL
            // DEADLOCK si le thread principal attend ce thread
        });
    });
    Ok(())
}
```

## 6.3 Piège: Lifetime Mismatch

```rust
// PIÈGE: Le lifetime de la référence
#[pyfunction]
fn get_string_ref<'py>(py: Python<'py>, s: &'py str) -> &'py str {
    s  // OK: même lifetime
}

// PIÈGE: Retourner une référence à des données locales
#[pyfunction]
fn bad_return() -> PyResult<&str> {
    let s = String::from("hello");
    Ok(&s)  // ERREUR: s est droppé à la fin de la fonction
}
```

## 6.4 Piège: Exceptions Non Gérées

```rust
// PIÈGE: Panic en Rust = crash Python
#[pyfunction]
fn may_panic(x: i64) -> i64 {
    if x < 0 {
        panic!("negative!");  // Crash tout le processus Python!
    }
    x
}

// CORRECT: Utiliser PyResult
#[pyfunction]
fn proper_error(x: i64) -> PyResult<i64> {
    if x < 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "negative value not allowed"
        ));
    }
    Ok(x)
}
```

---

# Section 7: QCM

## Question 1
Quel attribut PyO3 expose une struct Rust comme classe Python?

- A) `#[pymodule]`
- B) `#[pyclass]`
- C) `#[pyfunction]`
- D) `#[pymethods]`

## Question 2
Que fait `py.allow_threads(|| { ... })`?

- A) Crée un nouveau thread Python
- B) Libère le GIL pendant l'exécution du closure
- C) Exécute le code sur le thread principal
- D) Bloque tous les autres threads

## Question 3
Quelle est la bonne façon de retourner une erreur Python depuis Rust?

- A) `panic!("error")`
- B) `return Err(String::from("error"))`
- C) `return Err(PyErr::new::<PyValueError, _>("error"))`
- D) `throw PyException("error")`

## Question 4
Quand une `Vec<i64>` Python est passée à une fonction Rust, que se passe-t-il?

- A) Les données sont partagées sans copie
- B) Les données sont copiées de Python vers Rust
- C) Une référence est créée
- D) Une erreur est levée

## Question 5
Quel outil est recommandé pour builder et packager des extensions PyO3?

- A) cargo build
- B) pip install
- C) maturin
- D) setuptools

## Question 6
Comment implémenter `len()` pour une classe PyO3?

- A) `fn len(&self) -> usize`
- B) `fn __len__(&self) -> usize`
- C) `fn size(&self) -> usize`
- D) `fn length(&self) -> usize`

## Question 7
Quel est le maximum de Fibonacci calculable avec u64 sans overflow?

- A) F(50)
- B) F(75)
- C) F(93)
- D) F(100)

## Question 8
Pour supporter l'indexation négative Python (v[-1]), que faut-il?

- A) Rien, c'est automatique
- B) Convertir: `if idx < 0 { len + idx }`
- C) Lever une exception
- D) Utiliser un type signé

---

## Réponses

1. **B) `#[pyclass]`** - Définit une struct comme classe Python.

2. **B) Libère le GIL** - Permet à d'autres threads Python de s'exécuter pendant le calcul Rust.

3. **C) `PyErr::new`** - La façon standard de créer des exceptions Python depuis Rust.

4. **B) Les données sont copiées** - PyO3 copie les données lors de la conversion de types.

5. **C) maturin** - L'outil officiel pour builder des extensions Python en Rust.

6. **B) `fn __len__`** - Les protocoles Python utilisent les noms dunder.

7. **C) F(93)** - F(93) = 12200160415121876738, F(94) overflow u64.

8. **B) Convertir manuellement** - Python permet les indices négatifs, Rust non par défaut.

---

# Section 8: Récapitulatif

## Compétences Acquises

| Compétence | Description | Niveau |
|------------|-------------|--------|
| PyO3 Basics | Créer des modules Python en Rust | Avancé |
| Type Conversion | Convertir entre types Python/Rust | Avancé |
| GIL Management | Gérer le GIL pour la performance | Intermédiaire |
| Error Handling | Propager les erreurs cross-language | Avancé |
| Python Protocols | Implémenter `__len__`, `__getitem__`, etc. | Avancé |

## Complexités

| Opération | Temps | Espace | Notes |
|-----------|-------|--------|-------|
| fibonacci(n) | O(n) | O(1) | Itératif |
| prime_sieve(n) | O(n log log n) | O(n) | Ératosthène |
| RustVec.push | O(1) amorti | O(1) | Vec standard |
| BST.insert | O(h) | O(1) | h = hauteur |
| Graph.dijkstra | O((V+E) log V) | O(V) | Binary heap |

## Prochaines Étapes

1. **Immédiat**: Implémenter toutes les fonctions TODO
2. **Court terme**: Ajouter les bonus numpy et async
3. **Long terme**: Créer votre propre bibliothèque PyO3

---

# Section 9: Deployment Pack

```json
{
  "exercise_id": "1.9.05",
  "code_name": "the_translator",
  "version": "1.0.0",
  "tier": 3,
  "estimated_hours": 40,
  "languages": ["rust", "c", "python"],

  "concepts_covered": [
    "pyo3_basics",
    "ffi",
    "type_conversion",
    "gil_management",
    "python_protocols",
    "error_handling_cross_language",
    "memory_management",
    "parallel_computing"
  ],

  "learning_objectives": [
    "Create Python extensions with PyO3",
    "Understand GIL and release patterns",
    "Implement Python protocols in Rust",
    "Handle errors across language boundaries"
  ],

  "prerequisites": [
    "module_1.1_through_1.8",
    "rust_ownership_model",
    "python_basics"
  ],

  "dependencies": {
    "rust": {
      "pyo3": "0.20",
      "rayon": "1.8",
      "numpy": "0.20"
    },
    "python": {
      "pytest": ">=7.0",
      "numpy": ">=1.24"
    },
    "build": {
      "maturin": ">=1.3"
    }
  },

  "grading": {
    "tests_weight": 0.35,
    "code_quality_weight": 0.20,
    "completeness_weight": 0.25,
    "documentation_weight": 0.10,
    "bonus_weight": 0.10
  },

  "files": {
    "rust": {
      "lib.rs": "src/lib.rs",
      "vec.rs": "src/vec.rs",
      "hashmap.rs": "src/hashmap.rs",
      "bst.rs": "src/bst.rs",
      "graph.rs": "src/graph.rs"
    },
    "c": {
      "hackbrain_c.c": "c_ext/hackbrain_c.c"
    },
    "python": {
      "test_hackbrain.py": "tests/test_hackbrain.py"
    }
  },

  "test_commands": {
    "rust": "cargo test",
    "python": "pytest tests/ -v",
    "build": "maturin develop --release"
  },

  "metadata": {
    "author": "HACKBRAIN",
    "created": "2025-01-17",
    "difficulty": "expert",
    "tags": ["capstone", "ffi", "interop", "python", "rust"]
  }
}
```

---

*"The limits of my language mean the limits of my world."* — Ludwig Wittgenstein

**Avec PyO3, vos limites s'effacent.** Le monde Rust et le monde Python ne font plus qu'un.
