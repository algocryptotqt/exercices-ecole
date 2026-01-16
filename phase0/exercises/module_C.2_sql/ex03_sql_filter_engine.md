# Exercice C.2.3 : sql_filter_engine

**Module :**
C.2 - SQL Fundamentals

**Concept :**
c - Filter Operations (=, <>, BETWEEN, IN, LIKE, %, _, IS NULL)

**Difficulte :**
3/10

**Type :**
code

**Tiers :**
1 - Concept isole

**Langage :**
Python 3.14 + SQL (SQLite)

**Prerequis :**
- Syntaxe Python de base
- Module C.2.2 (Query Builder)
- Operateurs de comparaison

**Domaines :**
DB, SQL, Filter

**Duree estimee :**
30 min

**XP Base :**
75

**Complexite :**
T2 O(n) scan x S1 O(k) resultset

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `filter_engine.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | =, <>, <, >, <=, >=, BETWEEN, IN, LIKE, IS NULL, IS NOT NULL |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | ORM, regex pour filtrage SQL |

---

### 1.2 Consigne

#### Section Culture : "The One"

**MATRIX - "There's a difference between knowing the path and walking the path."**

Dans la Matrix, Neo doit apprendre a filtrer la realite - voir au-dela des apparences pour trouver la verite. En SQL, les filtres sont tes lunettes de Neo : ils te permettent de voir exactement ce que tu cherches.

*"You have to let it all go, Neo. Fear, doubt, and disbelief. Free your data."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `FilterEngine` qui permet de construire des conditions WHERE complexes :

1. **Comparaisons** : =, <>, <, >, <=, >=
2. **Intervalles** : BETWEEN
3. **Listes** : IN, NOT IN
4. **Patterns** : LIKE avec % et _
5. **Nullite** : IS NULL, IS NOT NULL

**Entree (Python) :**

```python
class FilterEngine:
    def __init__(self):
        """Initialise le moteur de filtres."""
        pass

    def equals(self, column: str, value: any) -> 'FilterEngine':
        """Filtre: column = value."""
        pass

    def not_equals(self, column: str, value: any) -> 'FilterEngine':
        """Filtre: column <> value."""
        pass

    def greater_than(self, column: str, value: any) -> 'FilterEngine':
        """Filtre: column > value."""
        pass

    def less_than(self, column: str, value: any) -> 'FilterEngine':
        """Filtre: column < value."""
        pass

    def between(self, column: str, low: any, high: any) -> 'FilterEngine':
        """Filtre: column BETWEEN low AND high."""
        pass

    def in_list(self, column: str, values: list) -> 'FilterEngine':
        """Filtre: column IN (values)."""
        pass

    def not_in_list(self, column: str, values: list) -> 'FilterEngine':
        """Filtre: column NOT IN (values)."""
        pass

    def like(self, column: str, pattern: str) -> 'FilterEngine':
        """Filtre: column LIKE pattern."""
        pass

    def starts_with(self, column: str, prefix: str) -> 'FilterEngine':
        """Filtre: column LIKE 'prefix%'."""
        pass

    def ends_with(self, column: str, suffix: str) -> 'FilterEngine':
        """Filtre: column LIKE '%suffix'."""
        pass

    def contains(self, column: str, substring: str) -> 'FilterEngine':
        """Filtre: column LIKE '%substring%'."""
        pass

    def is_null(self, column: str) -> 'FilterEngine':
        """Filtre: column IS NULL."""
        pass

    def is_not_null(self, column: str) -> 'FilterEngine':
        """Filtre: column IS NOT NULL."""
        pass

    def and_(self) -> 'FilterEngine':
        """Combine avec AND."""
        pass

    def or_(self) -> 'FilterEngine':
        """Combine avec OR."""
        pass

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL WHERE et les parametres."""
        pass
```

**Sortie :**
- Clause WHERE SQL valide
- Parametres pour requete preparee

**Wildcards LIKE :**

| Wildcard | Description | Exemple |
|----------|-------------|---------|
| % | Zero ou plusieurs caracteres | 'A%' match 'Alice', 'Albert' |
| _ | Exactement un caractere | 'A_ice' match 'Alice' mais pas 'Aliceee' |

---

### 1.3 Prototype

**Python :**
```python
from typing import Any

class FilterEngine:
    def __init__(self):
        self._conditions: list[str] = []
        self._params: list[Any] = []
        self._operators: list[str] = []

    def equals(self, column: str, value: Any) -> 'FilterEngine': pass
    def not_equals(self, column: str, value: Any) -> 'FilterEngine': pass
    def greater_than(self, column: str, value: Any) -> 'FilterEngine': pass
    def less_than(self, column: str, value: Any) -> 'FilterEngine': pass
    def between(self, column: str, low: Any, high: Any) -> 'FilterEngine': pass
    def in_list(self, column: str, values: list) -> 'FilterEngine': pass
    def not_in_list(self, column: str, values: list) -> 'FilterEngine': pass
    def like(self, column: str, pattern: str) -> 'FilterEngine': pass
    def starts_with(self, column: str, prefix: str) -> 'FilterEngine': pass
    def ends_with(self, column: str, suffix: str) -> 'FilterEngine': pass
    def contains(self, column: str, substring: str) -> 'FilterEngine': pass
    def is_null(self, column: str) -> 'FilterEngine': pass
    def is_not_null(self, column: str) -> 'FilterEngine': pass
    def and_(self) -> 'FilterEngine': pass
    def or_(self) -> 'FilterEngine': pass
    def build(self) -> tuple[str, tuple]: pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**NULL n'est jamais egal a rien - meme pas a lui-meme !**

```sql
SELECT * FROM users WHERE age = NULL;     -- Ne retourne RIEN !
SELECT * FROM users WHERE age IS NULL;    -- Correct
SELECT * FROM users WHERE NULL = NULL;    -- Retourne... rien !
```

**LIKE est case-insensitive en SQLite par defaut**

En SQLite, `'Alice' LIKE 'alice'` retourne TRUE. Pour du case-sensitive, il faut `PRAGMA case_sensitive_like = ON;`

**BETWEEN inclut les bornes**

`BETWEEN 10 AND 20` inclut 10 et 20. C'est equivalent a `>= 10 AND <= 20`.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Data Analyst** | Filtrage complexe de datasets |
| **Backend Dev** | Recherche utilisateurs, produits |
| **DBA** | Diagnostic et maintenance |
| **Security** | Detection d'anomalies |
| **BI Engineer** | Rapports et dashboards |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python filter_engine.py

>>> from filter_engine import FilterEngine
>>>
>>> # Exemple 1: Egalite simple
>>> f = FilterEngine()
>>> f.equals("status", "active").build()
('status = ?', ('active',))
>>>
>>> # Exemple 2: Comparaisons
>>> f = FilterEngine()
>>> f.greater_than("age", 18).and_().less_than("age", 65).build()
('age > ? AND age < ?', (18, 65))
>>>
>>> # Exemple 3: BETWEEN
>>> f = FilterEngine()
>>> f.between("price", 10, 100).build()
('price BETWEEN ? AND ?', (10, 100))
>>>
>>> # Exemple 4: IN
>>> f = FilterEngine()
>>> f.in_list("city", ["Paris", "Lyon", "Marseille"]).build()
('city IN (?, ?, ?)', ('Paris', 'Lyon', 'Marseille'))
>>>
>>> # Exemple 5: LIKE patterns
>>> f = FilterEngine()
>>> f.starts_with("name", "Al").build()
("name LIKE ?", ('Al%',))
>>>
>>> f = FilterEngine()
>>> f.contains("email", "@gmail").build()
("email LIKE ?", ('%@gmail%',))
>>>
>>> # Exemple 6: NULL checks
>>> f = FilterEngine()
>>> f.is_null("deleted_at").build()
('deleted_at IS NULL', ())
>>>
>>> # Exemple 7: Combinaison complexe
>>> f = FilterEngine()
>>> sql, params = f.equals("active", 1) \
...                .and_() \
...                .between("age", 18, 35) \
...                .and_() \
...                .in_list("role", ["user", "admin"]) \
...                .build()
>>> print(sql)
active = ? AND age BETWEEN ? AND ? AND role IN (?, ?)
>>> print(params)
(1, 18, 35, 'user', 'admin')
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | equals | equals("a", 1) | a = ? | 5 | Basic |
| 2 | not_equals | not_equals("a", 1) | a <> ? | 5 | Basic |
| 3 | greater_than | greater_than("a", 5) | a > ? | 5 | Comparison |
| 4 | less_than | less_than("a", 5) | a < ? | 5 | Comparison |
| 5 | between | between("a", 1, 10) | BETWEEN ? AND ? | 10 | Range |
| 6 | in_list | in_list("a", [1,2,3]) | IN (?, ?, ?) | 10 | List |
| 7 | not_in_list | not_in_list("a", [1,2]) | NOT IN (?, ?) | 5 | List |
| 8 | like | like("a", "%test%") | LIKE ? | 5 | Pattern |
| 9 | starts_with | starts_with("a", "pre") | LIKE 'pre%' | 10 | Pattern |
| 10 | ends_with | ends_with("a", "suf") | LIKE '%suf' | 5 | Pattern |
| 11 | contains | contains("a", "mid") | LIKE '%mid%' | 5 | Pattern |
| 12 | is_null | is_null("a") | IS NULL | 10 | Null |
| 13 | is_not_null | is_not_null("a") | IS NOT NULL | 5 | Null |
| 14 | and_combination | .and_() | AND | 5 | Combinator |
| 15 | or_combination | .or_() | OR | 5 | Combinator |
| 16 | complex_filter | Multi conditions | Correct | 5 | Integration |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
from filter_engine import FilterEngine


def test_equals():
    """Test filtre egalite."""
    f = FilterEngine()
    sql, params = f.equals("name", "Alice").build()
    assert "name = ?" in sql
    assert "Alice" in params


def test_not_equals():
    """Test filtre non-egalite."""
    f = FilterEngine()
    sql, params = f.not_equals("status", "deleted").build()
    assert "status <> ?" in sql or "status != ?" in sql


def test_greater_than():
    """Test filtre superieur."""
    f = FilterEngine()
    sql, params = f.greater_than("age", 18).build()
    assert "age > ?" in sql
    assert 18 in params


def test_less_than():
    """Test filtre inferieur."""
    f = FilterEngine()
    sql, params = f.less_than("price", 100).build()
    assert "price < ?" in sql


def test_between():
    """Test filtre BETWEEN."""
    f = FilterEngine()
    sql, params = f.between("age", 18, 65).build()
    assert "BETWEEN" in sql
    assert 18 in params
    assert 65 in params


def test_in_list():
    """Test filtre IN."""
    f = FilterEngine()
    sql, params = f.in_list("city", ["Paris", "Lyon"]).build()
    assert "IN" in sql
    assert "Paris" in params
    assert "Lyon" in params


def test_not_in_list():
    """Test filtre NOT IN."""
    f = FilterEngine()
    sql, params = f.not_in_list("status", ["deleted", "banned"]).build()
    assert "NOT IN" in sql


def test_like():
    """Test filtre LIKE."""
    f = FilterEngine()
    sql, params = f.like("name", "A%").build()
    assert "LIKE" in sql
    assert "A%" in params


def test_starts_with():
    """Test filtre starts_with."""
    f = FilterEngine()
    sql, params = f.starts_with("name", "Al").build()
    assert "LIKE" in sql
    assert "Al%" in params


def test_ends_with():
    """Test filtre ends_with."""
    f = FilterEngine()
    sql, params = f.ends_with("email", ".com").build()
    assert "LIKE" in sql
    assert "%.com" in params


def test_contains():
    """Test filtre contains."""
    f = FilterEngine()
    sql, params = f.contains("bio", "developer").build()
    assert "LIKE" in sql
    assert "%developer%" in params


def test_is_null():
    """Test filtre IS NULL."""
    f = FilterEngine()
    sql, params = f.is_null("deleted_at").build()
    assert "IS NULL" in sql
    assert "?" not in sql  # Pas de parametre pour IS NULL


def test_is_not_null():
    """Test filtre IS NOT NULL."""
    f = FilterEngine()
    sql, params = f.is_not_null("email").build()
    assert "IS NOT NULL" in sql


def test_and_combination():
    """Test combinaison AND."""
    f = FilterEngine()
    sql, _ = f.equals("a", 1).and_().equals("b", 2).build()
    assert "AND" in sql


def test_or_combination():
    """Test combinaison OR."""
    f = FilterEngine()
    sql, _ = f.equals("a", 1).or_().equals("b", 2).build()
    assert "OR" in sql


def test_complex_filter():
    """Test filtre complexe."""
    f = FilterEngine()
    sql, params = f.equals("active", 1) \
                   .and_() \
                   .between("age", 18, 35) \
                   .and_() \
                   .is_not_null("email") \
                   .build()

    assert "active = ?" in sql
    assert "BETWEEN" in sql
    assert "IS NOT NULL" in sql
    assert 1 in params
    assert 18 in params
    assert 35 in params
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour FilterEngine.
Module C.2.3 - SQL Filter Engine
"""

from typing import Any


class FilterEngine:
    """Moteur de construction de filtres SQL WHERE."""

    def __init__(self):
        self._parts: list[str] = []
        self._params: list[Any] = []

    def _add_condition(self, condition: str, *params):
        """Ajoute une condition avec ses parametres."""
        self._parts.append(condition)
        self._params.extend(params)
        return self

    def equals(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column = value."""
        return self._add_condition(f"{column} = ?", value)

    def not_equals(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column <> value."""
        return self._add_condition(f"{column} <> ?", value)

    def greater_than(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column > value."""
        return self._add_condition(f"{column} > ?", value)

    def less_than(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column < value."""
        return self._add_condition(f"{column} < ?", value)

    def greater_or_equal(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column >= value."""
        return self._add_condition(f"{column} >= ?", value)

    def less_or_equal(self, column: str, value: Any) -> 'FilterEngine':
        """Filtre: column <= value."""
        return self._add_condition(f"{column} <= ?", value)

    def between(self, column: str, low: Any, high: Any) -> 'FilterEngine':
        """Filtre: column BETWEEN low AND high."""
        return self._add_condition(f"{column} BETWEEN ? AND ?", low, high)

    def in_list(self, column: str, values: list) -> 'FilterEngine':
        """Filtre: column IN (values)."""
        placeholders = ", ".join("?" * len(values))
        return self._add_condition(f"{column} IN ({placeholders})", *values)

    def not_in_list(self, column: str, values: list) -> 'FilterEngine':
        """Filtre: column NOT IN (values)."""
        placeholders = ", ".join("?" * len(values))
        return self._add_condition(f"{column} NOT IN ({placeholders})", *values)

    def like(self, column: str, pattern: str) -> 'FilterEngine':
        """Filtre: column LIKE pattern."""
        return self._add_condition(f"{column} LIKE ?", pattern)

    def starts_with(self, column: str, prefix: str) -> 'FilterEngine':
        """Filtre: column LIKE 'prefix%'."""
        return self._add_condition(f"{column} LIKE ?", f"{prefix}%")

    def ends_with(self, column: str, suffix: str) -> 'FilterEngine':
        """Filtre: column LIKE '%suffix'."""
        return self._add_condition(f"{column} LIKE ?", f"%{suffix}")

    def contains(self, column: str, substring: str) -> 'FilterEngine':
        """Filtre: column LIKE '%substring%'."""
        return self._add_condition(f"{column} LIKE ?", f"%{substring}%")

    def is_null(self, column: str) -> 'FilterEngine':
        """Filtre: column IS NULL."""
        self._parts.append(f"{column} IS NULL")
        return self

    def is_not_null(self, column: str) -> 'FilterEngine':
        """Filtre: column IS NOT NULL."""
        self._parts.append(f"{column} IS NOT NULL")
        return self

    def and_(self) -> 'FilterEngine':
        """Combine avec AND."""
        self._parts.append("AND")
        return self

    def or_(self) -> 'FilterEngine':
        """Combine avec OR."""
        self._parts.append("OR")
        return self

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL WHERE et les parametres."""
        sql = " ".join(self._parts)
        return sql, tuple(self._params)

    def reset(self) -> 'FilterEngine':
        """Reinitialise le filtre."""
        self._parts = []
        self._params = []
        return self


# Exemple d'utilisation
if __name__ == "__main__":
    # Test simple
    f = FilterEngine()
    sql, params = f.equals("status", "active") \
                   .and_() \
                   .between("age", 18, 65) \
                   .and_() \
                   .in_list("role", ["user", "admin"]) \
                   .build()

    print("SQL:", sql)
    print("Params:", params)

    # Test avec patterns
    f = FilterEngine()
    sql, params = f.starts_with("email", "admin") \
                   .or_() \
                   .ends_with("email", "@company.com") \
                   .build()

    print("\nSQL:", sql)
    print("Params:", params)
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (NULL) : Utiliser = au lieu de IS pour NULL**

```python
# Mutant A (NULL) : Comparaison incorrecte avec NULL
def is_null(self, column: str) -> 'FilterEngine':
    return self._add_condition(f"{column} = NULL")  # FAUX !

# Genere: column = NULL
# Ne trouve jamais rien car NULL != NULL
```

**Mutant B (IN) : Mauvais nombre de placeholders**

```python
# Mutant B (IN) : Un seul placeholder pour tous
def in_list(self, column: str, values: list) -> 'FilterEngine':
    return self._add_condition(f"{column} IN (?)", values)  # FAUX !

# Genere: column IN (?)
# Ne peut pas binder une liste a un seul placeholder
```

**Mutant C (LIKE) : Oubli des wildcards**

```python
# Mutant C (LIKE) : Pas de % ajoute
def starts_with(self, column: str, prefix: str) -> 'FilterEngine':
    return self._add_condition(f"{column} LIKE ?", prefix)  # Manque %

# Genere: LIKE 'Al' au lieu de LIKE 'Al%'
# Ne match que les valeurs exactes
```

**Mutant D (BETWEEN) : Ordre incorrect des bornes**

```python
# Mutant D (BETWEEN) : Bornes inversees
def between(self, column: str, low: Any, high: Any) -> 'FilterEngine':
    return self._add_condition(f"{column} BETWEEN ? AND ?", high, low)  # Inverse !

# Genere: BETWEEN 100 AND 10
# Ne retourne rien si low < high
```

**Mutant E (AND/OR) : Operateur manquant**

```python
# Mutant E (AND/OR) : Pas d'espace ou operateur mal place
def and_(self) -> 'FilterEngine':
    self._parts.append("AND")  # OK mais...
    return self

def build(self) -> tuple[str, tuple]:
    sql = "".join(self._parts)  # Pas d'espace ! FAUX !
    return sql, tuple(self._params)

# Genere: column = ?ANDcolumn2 = ?
# Syntaxe invalide
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| = / <> | Egalite et difference | Fondamental |
| BETWEEN | Intervalle inclusif | Important |
| IN / NOT IN | Appartenance a une liste | Important |
| LIKE | Recherche par pattern | Important |
| % / _ | Wildcards | Important |
| IS NULL | Test de nullite | Fondamental |

---

### 5.2 Visualisation ASCII

**Operateurs de comparaison :**

```
Valeur: 50

    0    25    50    75    100
    |-----|-----|-----|-----|
          ^           ^
    < 50  |   = 50   |  > 50
          |           |
    <= 50 +-----------+ >= 50
          |           |
          +--BETWEEN--+
             25 - 75
```

**Wildcards LIKE :**

```
Pattern: 'A%'        Matches: 'Alice', 'Albert', 'A', 'Aardvark'
Pattern: '%e'        Matches: 'Alice', 'Steve', 'e'
Pattern: 'A_ice'     Matches: 'Alice' (exactement 5 chars commencant par A, finissant par ice)
Pattern: '%test%'    Matches: 'test', 'testing', 'attest', 'untested'
```

**NULL comparisons :**

```
Expression          | Result
--------------------|--------
NULL = NULL         | NULL (not TRUE!)
NULL <> NULL        | NULL
NULL IS NULL        | TRUE
5 = NULL            | NULL
5 IS NULL           | FALSE
```

---

### 5.3 Les pieges en detail

#### Piege 1 : NULL avec =

```sql
-- FAUX : Ne trouve jamais rien
SELECT * FROM users WHERE middle_name = NULL;

-- CORRECT : Utiliser IS NULL
SELECT * FROM users WHERE middle_name IS NULL;
```

#### Piege 2 : LIKE avec caracteres speciaux

```sql
-- Si on cherche un '%' litteral
SELECT * FROM products WHERE name LIKE '%50\%%' ESCAPE '\';
-- Trouve '50% off'
```

#### Piege 3 : IN avec liste vide

```sql
-- PROBLEME : IN () est invalide en SQL
SELECT * FROM users WHERE id IN ();  -- ERREUR !

-- SOLUTION : Verifier la liste avant
-- En Python: if values: ... else: return "1=0"
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | = NULL | Jamais de match | IS NULL |
| 2 | LIKE case | SQLite insensible | PRAGMA ou collation |
| 3 | % litteral | Match incorrect | ESCAPE |
| 4 | IN () vide | Erreur SQL | Gerer le cas |
| 5 | BETWEEN ordre | Pas de resultat | Verifier low <= high |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Comment tester si une colonne est NULL ?

- A) column = NULL
- B) column == NULL
- C) column IS NULL
- D) column EQUALS NULL

**Reponse : C** - IS NULL est la seule syntaxe correcte.

---

### Question 2 (3 points)
Que match le pattern 'A_B' avec LIKE ?

- A) 'AB'
- B) 'ACB'
- C) 'ACCB'
- D) Toutes ces valeurs

**Reponse : B** - _ match exactement un caractere.

---

### Question 3 (4 points)
BETWEEN 10 AND 20 est equivalent a ?

- A) > 10 AND < 20
- B) >= 10 AND < 20
- C) > 10 AND <= 20
- D) >= 10 AND <= 20

**Reponse : D** - BETWEEN inclut les deux bornes.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.3 |
| **Nom** | sql_filter_engine |
| **Difficulte** | 3/10 |
| **Duree** | 30 min |
| **XP Base** | 75 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | Operateurs, BETWEEN, IN, LIKE, IS NULL |

---

*Document genere selon HACKBRAIN v5.5.2*
