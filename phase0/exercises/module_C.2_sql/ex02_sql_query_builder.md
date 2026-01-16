# Exercice C.2.2 : sql_query_builder

**Module :**
C.2 - SQL Fundamentals

**Concept :**
b - Query Building (SELECT, FROM, WHERE, AND/OR, ORDER BY, LIMIT, DISTINCT)

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
- Module C.2.1 (Schema Builder)
- Logique booleenne

**Domaines :**
DB, SQL, Query

**Duree estimee :**
35 min

**XP Base :**
80

**Complexite :**
T2 O(n) scan x S1 O(k) resultset

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `query_builder.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | SELECT, FROM, WHERE, ORDER BY, LIMIT, DISTINCT |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | ORM, pandas.read_sql |
| SQL | Sous-requetes (pour cet exercice) |

---

### 1.2 Consigne

#### Section Culture : "The Oracle"

**MATRIX - "I can only show you the door. You're the one that has to walk through it."**

L'Oracle dans la Matrix peut voir et chercher dans toutes les donnees de la simulation. Elle filtre, trie, et ne revele que ce qui est pertinent. Tu vas construire ton propre Oracle - un Query Builder.

*"What's really going to bake your noodle later on is: would the data have been there if you hadn't looked for it?"*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `QueryBuilder` qui permet de construire des requetes SELECT de maniere fluide :

1. **Selection** : Choisir les colonnes a recuperer
2. **Filtrage** : Conditions WHERE avec AND/OR
3. **Tri** : ORDER BY ascendant ou descendant
4. **Limitation** : LIMIT et OFFSET
5. **Deduplication** : DISTINCT

**Entree (Python) :**

```python
class QueryBuilder:
    def __init__(self, connection: sqlite3.Connection):
        """Initialise le builder avec une connexion DB."""
        pass

    def select(self, *columns: str) -> 'QueryBuilder':
        """Definit les colonnes a selectionner (defaut: *)."""
        pass

    def distinct(self) -> 'QueryBuilder':
        """Ajoute DISTINCT a la requete."""
        pass

    def from_table(self, table: str) -> 'QueryBuilder':
        """Definit la table source."""
        pass

    def where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition WHERE (premiere condition)."""
        pass

    def and_where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition AND."""
        pass

    def or_where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition OR."""
        pass

    def order_by(self, column: str, direction: str = "ASC") -> 'QueryBuilder':
        """Ajoute un tri (ASC ou DESC)."""
        pass

    def limit(self, count: int) -> 'QueryBuilder':
        """Limite le nombre de resultats."""
        pass

    def offset(self, count: int) -> 'QueryBuilder':
        """Definit l'offset pour la pagination."""
        pass

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        pass

    def execute(self) -> list[tuple]:
        """Execute la requete et retourne les resultats."""
        pass

    def fetch_one(self) -> tuple | None:
        """Execute et retourne un seul resultat."""
        pass
```

**Sortie :**
- Requetes SQL parametrees (protection injection)
- Resultats sous forme de liste de tuples

**Exemples :**

| Methode Chain | SQL Genere |
|---------------|------------|
| `.select("name").from_table("users")` | `SELECT name FROM users` |
| `.where("age > ?", 18)` | `WHERE age > 18` |
| `.and_where("active = ?", 1)` | `AND active = 1` |
| `.order_by("name", "DESC")` | `ORDER BY name DESC` |
| `.limit(10).offset(20)` | `LIMIT 10 OFFSET 20` |
| `.distinct()` | `SELECT DISTINCT ...` |

---

### 1.3 Prototype

**Python :**
```python
import sqlite3
from typing import Any

class QueryBuilder:
    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._columns: list[str] = ["*"]
        self._distinct: bool = False
        self._table: str = ""
        self._where_clauses: list[str] = []
        self._params: list[Any] = []
        self._order_by: list[str] = []
        self._limit: int | None = None
        self._offset: int | None = None

    def select(self, *columns: str) -> 'QueryBuilder': pass
    def distinct(self) -> 'QueryBuilder': pass
    def from_table(self, table: str) -> 'QueryBuilder': pass
    def where(self, condition: str, *params) -> 'QueryBuilder': pass
    def and_where(self, condition: str, *params) -> 'QueryBuilder': pass
    def or_where(self, condition: str, *params) -> 'QueryBuilder': pass
    def order_by(self, column: str, direction: str = "ASC") -> 'QueryBuilder': pass
    def limit(self, count: int) -> 'QueryBuilder': pass
    def offset(self, count: int) -> 'QueryBuilder': pass
    def build(self) -> tuple[str, tuple]: pass
    def execute(self) -> list[tuple]: pass
    def fetch_one(self) -> tuple | None: pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**SELECT * est (presque) toujours une mauvaise idee**

En production, specifier les colonnes explicitement est crucial :
- Moins de donnees transferees
- Requete plus lisible
- Protection contre les changements de schema

**L'ordre des clauses SQL est fixe**

SQL exige cet ordre : SELECT -> FROM -> WHERE -> GROUP BY -> HAVING -> ORDER BY -> LIMIT. Inverser provoque une erreur de syntaxe !

**LIMIT sans ORDER BY est non-deterministe**

La base peut retourner n'importe quelles lignes. Toujours combiner LIMIT avec ORDER BY pour des resultats reproductibles.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Backend Developer** | APIs avec filtres et pagination |
| **Data Analyst** | Exploration de donnees |
| **DevOps** | Monitoring et alertes |
| **QA Engineer** | Verification de donnees |
| **Product Manager** | Tableaux de bord |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python query_builder.py

>>> import sqlite3
>>> from query_builder import QueryBuilder
>>>
>>> # Setup: creer une base de test
>>> conn = sqlite3.connect(":memory:")
>>> conn.execute('''CREATE TABLE users (
...     id INTEGER PRIMARY KEY,
...     name TEXT,
...     age INTEGER,
...     city TEXT,
...     active INTEGER
... )''')
>>> conn.execute("INSERT INTO users VALUES (1, 'Alice', 25, 'Paris', 1)")
>>> conn.execute("INSERT INTO users VALUES (2, 'Bob', 30, 'Lyon', 1)")
>>> conn.execute("INSERT INTO users VALUES (3, 'Charlie', 35, 'Paris', 0)")
>>> conn.execute("INSERT INTO users VALUES (4, 'Diana', 28, 'Lyon', 1)")
>>> conn.commit()
>>>
>>> # Exemple 1: Selection simple
>>> qb = QueryBuilder(conn)
>>> qb.select("name", "age").from_table("users").execute()
[('Alice', 25), ('Bob', 30), ('Charlie', 35), ('Diana', 28)]
>>>
>>> # Exemple 2: Avec filtres
>>> qb = QueryBuilder(conn)
>>> qb.select("name").from_table("users") \
...   .where("city = ?", "Paris") \
...   .and_where("active = ?", 1) \
...   .execute()
[('Alice',)]
>>>
>>> # Exemple 3: Tri et limite
>>> qb = QueryBuilder(conn)
>>> qb.select("name", "age").from_table("users") \
...   .order_by("age", "DESC") \
...   .limit(2) \
...   .execute()
[('Charlie', 35), ('Bob', 30)]
>>>
>>> # Exemple 4: DISTINCT
>>> qb = QueryBuilder(conn)
>>> qb.select("city").distinct().from_table("users").execute()
[('Paris',), ('Lyon',)]
>>>
>>> # Exemple 5: Pagination
>>> qb = QueryBuilder(conn)
>>> qb.select("name").from_table("users") \
...   .order_by("id") \
...   .limit(2).offset(1) \
...   .execute()
[('Bob',), ('Charlie',)]
>>>
>>> # Voir le SQL genere
>>> qb = QueryBuilder(conn)
>>> sql, params = qb.select("name").from_table("users") \
...                 .where("age > ?", 20).build()
>>> print(sql)
SELECT name FROM users WHERE age > ?
>>> print(params)
(20,)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | select_all | select() defaut | SELECT * | 5 | Basic |
| 2 | select_columns | select("a", "b") | SELECT a, b | 10 | Basic |
| 3 | distinct | distinct() | SELECT DISTINCT | 10 | Modifier |
| 4 | from_table | from_table("t") | FROM t | 5 | Basic |
| 5 | where_simple | where("x = ?", 1) | WHERE x = 1 | 10 | Filter |
| 6 | and_where | and_where(...) | AND ... | 10 | Filter |
| 7 | or_where | or_where(...) | OR ... | 10 | Filter |
| 8 | order_asc | order_by("x") | ORDER BY x ASC | 5 | Sort |
| 9 | order_desc | order_by("x", "DESC") | ORDER BY x DESC | 5 | Sort |
| 10 | limit_only | limit(10) | LIMIT 10 | 5 | Pagination |
| 11 | limit_offset | limit(10).offset(5) | LIMIT 10 OFFSET 5 | 10 | Pagination |
| 12 | build_returns_tuple | build() | (sql, params) | 5 | Output |
| 13 | execute_returns_list | execute() | list[tuple] | 5 | Output |
| 14 | params_injection_safe | where avec '; DROP | Pas d'injection | 5 | Security |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
import sqlite3
from query_builder import QueryBuilder


@pytest.fixture
def db_connection():
    """Cree une base de test."""
    conn = sqlite3.connect(":memory:")
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        name TEXT,
        age INTEGER,
        city TEXT,
        active INTEGER
    )''')
    conn.executemany(
        "INSERT INTO users (name, age, city, active) VALUES (?, ?, ?, ?)",
        [
            ("Alice", 25, "Paris", 1),
            ("Bob", 30, "Lyon", 1),
            ("Charlie", 35, "Paris", 0),
            ("Diana", 28, "Lyon", 1),
        ]
    )
    conn.commit()
    return conn


def test_select_all_default(db_connection):
    """Test selection par defaut (*)."""
    qb = QueryBuilder(db_connection)
    sql, _ = qb.from_table("users").build()
    assert "SELECT *" in sql or "SELECT * " in sql


def test_select_specific_columns(db_connection):
    """Test selection de colonnes specifiques."""
    qb = QueryBuilder(db_connection)
    sql, _ = qb.select("name", "age").from_table("users").build()
    assert "name" in sql
    assert "age" in sql


def test_distinct(db_connection):
    """Test DISTINCT."""
    qb = QueryBuilder(db_connection)
    results = qb.select("city").distinct().from_table("users").execute()
    assert len(results) == 2  # Paris et Lyon


def test_where_clause(db_connection):
    """Test clause WHERE."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .where("age > ?", 27).execute()
    names = [r[0] for r in results]
    assert "Bob" in names
    assert "Charlie" in names
    assert "Diana" in names
    assert "Alice" not in names


def test_and_where(db_connection):
    """Test AND WHERE."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .where("city = ?", "Paris") \
                .and_where("active = ?", 1).execute()
    assert len(results) == 1
    assert results[0][0] == "Alice"


def test_or_where(db_connection):
    """Test OR WHERE."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .where("name = ?", "Alice") \
                .or_where("name = ?", "Bob").execute()
    assert len(results) == 2


def test_order_by_asc(db_connection):
    """Test ORDER BY ASC."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .order_by("age").execute()
    assert results[0][0] == "Alice"  # 25 ans


def test_order_by_desc(db_connection):
    """Test ORDER BY DESC."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .order_by("age", "DESC").execute()
    assert results[0][0] == "Charlie"  # 35 ans


def test_limit(db_connection):
    """Test LIMIT."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users").limit(2).execute()
    assert len(results) == 2


def test_limit_offset(db_connection):
    """Test LIMIT avec OFFSET."""
    qb = QueryBuilder(db_connection)
    results = qb.select("name").from_table("users") \
                .order_by("id").limit(2).offset(1).execute()
    assert len(results) == 2
    assert results[0][0] == "Bob"  # Commence au 2eme


def test_build_returns_tuple(db_connection):
    """Test que build() retourne (sql, params)."""
    qb = QueryBuilder(db_connection)
    result = qb.select("name").from_table("users") \
               .where("age > ?", 20).build()
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], str)
    assert isinstance(result[1], tuple)


def test_params_are_safe(db_connection):
    """Test que les parametres sont utilises (pas de concatenation)."""
    qb = QueryBuilder(db_connection)
    sql, params = qb.select("name").from_table("users") \
                    .where("name = ?", "'; DROP TABLE users; --").build()
    assert "DROP" not in sql
    assert "'; DROP TABLE users; --" in params


def test_fetch_one(db_connection):
    """Test fetch_one()."""
    qb = QueryBuilder(db_connection)
    result = qb.select("name").from_table("users") \
               .where("name = ?", "Alice").fetch_one()
    assert result is not None
    assert result[0] == "Alice"
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour QueryBuilder.
Module C.2.2 - SQL Query Builder
"""

import sqlite3
from typing import Any


class QueryBuilder:
    """Builder pour construire des requetes SELECT SQL."""

    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._columns: list[str] = []
        self._distinct: bool = False
        self._table: str = ""
        self._where_clauses: list[tuple[str, str]] = []  # (operator, condition)
        self._params: list[Any] = []
        self._order_by: list[tuple[str, str]] = []
        self._limit: int | None = None
        self._offset: int | None = None

    def select(self, *columns: str) -> 'QueryBuilder':
        """Definit les colonnes a selectionner."""
        self._columns = list(columns) if columns else []
        return self

    def distinct(self) -> 'QueryBuilder':
        """Ajoute DISTINCT a la requete."""
        self._distinct = True
        return self

    def from_table(self, table: str) -> 'QueryBuilder':
        """Definit la table source."""
        self._table = table
        return self

    def where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition WHERE (premiere condition)."""
        self._where_clauses.append(("WHERE", condition))
        self._params.extend(params)
        return self

    def and_where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition AND."""
        self._where_clauses.append(("AND", condition))
        self._params.extend(params)
        return self

    def or_where(self, condition: str, *params) -> 'QueryBuilder':
        """Ajoute une condition OR."""
        self._where_clauses.append(("OR", condition))
        self._params.extend(params)
        return self

    def order_by(self, column: str, direction: str = "ASC") -> 'QueryBuilder':
        """Ajoute un tri."""
        direction = direction.upper()
        if direction not in ("ASC", "DESC"):
            direction = "ASC"
        self._order_by.append((column, direction))
        return self

    def limit(self, count: int) -> 'QueryBuilder':
        """Limite le nombre de resultats."""
        self._limit = count
        return self

    def offset(self, count: int) -> 'QueryBuilder':
        """Definit l'offset pour la pagination."""
        self._offset = count
        return self

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        parts = []

        # SELECT
        select_clause = "SELECT"
        if self._distinct:
            select_clause += " DISTINCT"

        columns = ", ".join(self._columns) if self._columns else "*"
        parts.append(f"{select_clause} {columns}")

        # FROM
        if self._table:
            parts.append(f"FROM {self._table}")

        # WHERE
        for i, (operator, condition) in enumerate(self._where_clauses):
            if i == 0:
                parts.append(f"WHERE {condition}")
            else:
                parts.append(f"{operator} {condition}")

        # ORDER BY
        if self._order_by:
            order_parts = [f"{col} {dir}" for col, dir in self._order_by]
            parts.append(f"ORDER BY {', '.join(order_parts)}")

        # LIMIT
        if self._limit is not None:
            parts.append(f"LIMIT {self._limit}")

        # OFFSET
        if self._offset is not None:
            parts.append(f"OFFSET {self._offset}")

        sql = " ".join(parts)
        return sql, tuple(self._params)

    def execute(self) -> list[tuple]:
        """Execute la requete et retourne les resultats."""
        sql, params = self.build()
        cursor = self._conn.execute(sql, params)
        return cursor.fetchall()

    def fetch_one(self) -> tuple | None:
        """Execute et retourne un seul resultat."""
        sql, params = self.build()
        cursor = self._conn.execute(sql, params)
        return cursor.fetchone()


# Exemple d'utilisation
if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        name TEXT,
        age INTEGER,
        city TEXT
    )''')
    conn.executemany(
        "INSERT INTO users (name, age, city) VALUES (?, ?, ?)",
        [("Alice", 25, "Paris"), ("Bob", 30, "Lyon"), ("Charlie", 35, "Paris")]
    )
    conn.commit()

    qb = QueryBuilder(conn)
    results = qb.select("name", "age") \
                .from_table("users") \
                .where("age > ?", 20) \
                .order_by("age", "DESC") \
                .limit(2) \
                .execute()

    print("Results:", results)
    sql, params = qb.build()
    print("SQL:", sql)
    print("Params:", params)
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Order) : Clauses SQL dans le mauvais ordre**

```python
# Mutant A (Order) : ORDER BY avant WHERE
def build(self) -> tuple[str, tuple]:
    parts = [f"SELECT {columns}", f"FROM {self._table}"]
    if self._order_by:
        parts.append(f"ORDER BY ...")  # Avant WHERE !
    if self._where_clauses:
        parts.append(f"WHERE ...")
    # ...

# Genere: SELECT * FROM users ORDER BY name WHERE age > 20
# Erreur de syntaxe SQL !
```

**Mutant B (Logic) : AND/OR mal gere**

```python
# Mutant B (Logic) : Premier WHERE avec AND
def where(self, condition: str, *params) -> 'QueryBuilder':
    self._where_clauses.append(("AND", condition))  # AND au lieu de WHERE !
    # ...

# Genere: SELECT * FROM users AND age > 20
# Manque le WHERE initial !
```

**Mutant C (Params) : Parametres non utilises**

```python
# Mutant C (Params) : Concatenation directe (INJECTION SQL !)
def where(self, condition: str, *params) -> 'QueryBuilder':
    # Remplace ? par la valeur directement
    for p in params:
        condition = condition.replace("?", str(p), 1)
    self._where_clauses.append(("WHERE", condition))
    # ...

# Vulnerable a l'injection SQL !
```

**Mutant D (Distinct) : DISTINCT mal place**

```python
# Mutant D (Distinct) : DISTINCT apres les colonnes
def build(self) -> tuple[str, tuple]:
    columns = ", ".join(self._columns) if self._columns else "*"
    if self._distinct:
        columns += " DISTINCT"  # Apres au lieu d'avant !
    # ...

# Genere: SELECT name, age DISTINCT FROM users
# Syntaxe invalide !
```

**Mutant E (Limit) : OFFSET sans LIMIT**

```python
# Mutant E (Limit) : OFFSET avant LIMIT
def build(self) -> tuple[str, tuple]:
    # ...
    if self._offset is not None:
        parts.append(f"OFFSET {self._offset}")
    if self._limit is not None:
        parts.append(f"LIMIT {self._limit}")
    # ...

# Genere: ... OFFSET 10 LIMIT 5
# SQLite accepte mais comportement inattendu
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| SELECT | Choisir les colonnes | Fondamental |
| FROM | Specifier la table | Fondamental |
| WHERE | Filtrer les lignes | Fondamental |
| AND/OR | Combiner les conditions | Important |
| ORDER BY | Trier les resultats | Important |
| LIMIT/OFFSET | Pagination | Important |
| DISTINCT | Eliminer les doublons | Utile |

---

### 5.2 Visualisation ASCII

**Anatomie d'une requete SELECT :**

```
SELECT [DISTINCT] columns    <-- Quelles colonnes ?
FROM table                   <-- Quelle table ?
WHERE condition              <-- Quelles lignes ?
  AND condition2             <-- Conditions additionnelles
  OR condition3
ORDER BY column [ASC|DESC]   <-- Dans quel ordre ?
LIMIT n                      <-- Combien de resultats ?
OFFSET m                     <-- A partir de quelle position ?
```

**Flux de donnees :**

```
TABLE (toutes les lignes)
         |
         v
    [WHERE clause]  --> Filtrage
         |
         v
    [DISTINCT]      --> Deduplication
         |
         v
    [ORDER BY]      --> Tri
         |
         v
    [LIMIT/OFFSET]  --> Pagination
         |
         v
    RESULTATS
```

---

### 5.3 Les pieges en detail

#### Piege 1 : Ordre des clauses SQL

```sql
-- FAUX : ORDER BY avant WHERE
SELECT * FROM users ORDER BY name WHERE age > 20;  -- ERREUR !

-- CORRECT : WHERE avant ORDER BY
SELECT * FROM users WHERE age > 20 ORDER BY name;
```

#### Piege 2 : DISTINCT avec ORDER BY

```sql
-- Attention : ORDER BY sur colonne non selectionnee
SELECT DISTINCT city FROM users ORDER BY name;  -- Peut echouer !

-- CORRECT : ORDER BY sur colonne selectionnee
SELECT DISTINCT city FROM users ORDER BY city;
```

#### Piege 3 : OFFSET sans LIMIT

```sql
-- Comportement indefini dans certaines DB
SELECT * FROM users OFFSET 10;  -- Pas de LIMIT !

-- CORRECT : LIMIT avec OFFSET
SELECT * FROM users LIMIT 10 OFFSET 10;
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Ordre des clauses | Erreur syntaxe | Respecter l'ordre SQL |
| 2 | Injection SQL | Securite | Utiliser des parametres |
| 3 | SELECT * en prod | Performance | Specifier les colonnes |
| 4 | LIMIT sans ORDER | Non-deterministe | Toujours combiner |
| 5 | OFFSET sans LIMIT | Comportement indefini | Utiliser les deux |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quel est l'ordre correct des clauses SQL ?

- A) SELECT, WHERE, FROM, ORDER BY
- B) SELECT, FROM, ORDER BY, WHERE
- C) SELECT, FROM, WHERE, ORDER BY
- D) FROM, SELECT, WHERE, ORDER BY

**Reponse : C** - L'ordre est toujours SELECT, FROM, WHERE, ORDER BY.

---

### Question 2 (3 points)
Comment eviter les injections SQL ?

- A) Echapper les quotes manuellement
- B) Utiliser des requetes parametrees
- C) Valider le type des donnees
- D) Toutes les reponses

**Reponse : B** - Les requetes parametrees sont la meilleure protection.

---

### Question 3 (4 points)
Que fait DISTINCT dans une requete ?

- A) Trie les resultats
- B) Limite les resultats
- C) Elimine les doublons
- D) Filtre les NULL

**Reponse : C** - DISTINCT elimine les lignes dupliquees.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.2 |
| **Nom** | sql_query_builder |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 80 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | SELECT, WHERE, ORDER BY, LIMIT |

---

*Document genere selon HACKBRAIN v5.5.2*
