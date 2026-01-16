# Exercice C.2.6 : sql_aggregator

**Module :**
C.2 - SQL Fundamentals

**Concept :**
f - Aggregation Functions (COUNT, SUM, AVG, MIN, MAX, GROUP BY, HAVING)

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
- Modules C.2.1-C.2.5
- Notion de groupement

**Domaines :**
DB, SQL, Analytics

**Duree estimee :**
35 min

**XP Base :**
80

**Complexite :**
T2 O(n) scan x S2 O(g) groups

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `aggregator.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | COUNT, SUM, AVG, MIN, MAX, GROUP BY, HAVING |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | pandas, numpy aggregations |

---

### 1.2 Consigne

#### Section Culture : "The Analyst"

**MATRIX - "You've been living in a dream world, Neo."**

Dans la Matrix, les chiffres cachent la verite. Morpheus peut analyser les patterns, compter les anomalies, calculer les moyennes. Tu vas devenir l'analyste de tes donnees - transformer des millions de lignes en quelques chiffres significatifs.

*"Unfortunately, no one can be told what the Matrix is. You have to see it for yourself."* - Et voir, c'est agreger.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `Aggregator` qui permet de construire des requetes d'aggregation :

1. **Fonctions** : COUNT, SUM, AVG, MIN, MAX
2. **Groupement** : GROUP BY
3. **Filtrage** : HAVING (filtrer les groupes)
4. **Combinaison** : Plusieurs aggregations dans une requete

**Entree (Python) :**

```python
class Aggregator:
    def __init__(self, connection: sqlite3.Connection):
        """Initialise avec une connexion DB."""
        pass

    def select(self, *columns: str) -> 'Aggregator':
        """Colonnes non-agregees a selectionner."""
        pass

    def count(self, column: str = "*", alias: str = None) -> 'Aggregator':
        """COUNT(column) AS alias."""
        pass

    def sum(self, column: str, alias: str = None) -> 'Aggregator':
        """SUM(column) AS alias."""
        pass

    def avg(self, column: str, alias: str = None) -> 'Aggregator':
        """AVG(column) AS alias."""
        pass

    def min(self, column: str, alias: str = None) -> 'Aggregator':
        """MIN(column) AS alias."""
        pass

    def max(self, column: str, alias: str = None) -> 'Aggregator':
        """MAX(column) AS alias."""
        pass

    def from_table(self, table: str) -> 'Aggregator':
        """Table source."""
        pass

    def where(self, condition: str, *params) -> 'Aggregator':
        """Clause WHERE (avant groupement)."""
        pass

    def group_by(self, *columns: str) -> 'Aggregator':
        """GROUP BY columns."""
        pass

    def having(self, condition: str, *params) -> 'Aggregator':
        """HAVING condition (apres groupement)."""
        pass

    def order_by(self, column: str, direction: str = "ASC") -> 'Aggregator':
        """ORDER BY (peut utiliser les alias)."""
        pass

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        pass

    def execute(self) -> list[dict]:
        """Execute et retourne les resultats."""
        pass
```

**Fonctions d'aggregation :**

| Fonction | Description | Exemple |
|----------|-------------|---------|
| COUNT(*) | Nombre de lignes | COUNT(*) -> 42 |
| COUNT(col) | Nombre de valeurs non-NULL | COUNT(email) -> 38 |
| SUM(col) | Somme des valeurs | SUM(amount) -> 1500.00 |
| AVG(col) | Moyenne | AVG(age) -> 28.5 |
| MIN(col) | Valeur minimum | MIN(price) -> 9.99 |
| MAX(col) | Valeur maximum | MAX(score) -> 100 |

---

### 1.3 Prototype

**Python :**
```python
import sqlite3
from typing import Any

class Aggregator:
    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._select_parts: list[str] = []
        self._from: str = ""
        self._where: list[str] = []
        self._group_by: list[str] = []
        self._having: list[str] = []
        self._order_by: list[str] = []
        self._params: list[Any] = []
        self._having_params: list[Any] = []

    def select(self, *columns: str) -> 'Aggregator': pass
    def count(self, column: str = "*", alias: str = None) -> 'Aggregator': pass
    def sum(self, column: str, alias: str = None) -> 'Aggregator': pass
    def avg(self, column: str, alias: str = None) -> 'Aggregator': pass
    def min(self, column: str, alias: str = None) -> 'Aggregator': pass
    def max(self, column: str, alias: str = None) -> 'Aggregator': pass
    def from_table(self, table: str) -> 'Aggregator': pass
    def where(self, condition: str, *params) -> 'Aggregator': pass
    def group_by(self, *columns: str) -> 'Aggregator': pass
    def having(self, condition: str, *params) -> 'Aggregator': pass
    def order_by(self, column: str, direction: str = "ASC") -> 'Aggregator': pass
    def build(self) -> tuple[str, tuple]: pass
    def execute(self) -> list[dict]: pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**COUNT(*) vs COUNT(column)**

`COUNT(*)` compte toutes les lignes, meme celles avec des NULL. `COUNT(column)` ne compte que les valeurs non-NULL dans cette colonne. Ca peut donner des resultats tres differents !

**AVG ignore les NULL**

`AVG(column)` ne prend en compte que les valeurs non-NULL. Si tu as [10, NULL, 20], la moyenne est 15, pas 10 !

**HAVING est le WHERE des groupes**

`WHERE` filtre les lignes AVANT le groupement. `HAVING` filtre les GROUPES apres l'aggregation. Tu peux utiliser des fonctions d'aggregation dans HAVING, pas dans WHERE.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Data Analyst** | KPIs, rapports, dashboards |
| **Business Intelligence** | Metriques business |
| **Finance** | Calculs de totaux, moyennes |
| **Marketing** | Analyse de campagnes |
| **Product Manager** | Metriques produit |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python aggregator.py

>>> import sqlite3
>>> from aggregator import Aggregator
>>>
>>> # Setup: donnees de ventes
>>> conn = sqlite3.connect(":memory:")
>>> conn.executescript('''
...     CREATE TABLE sales (
...         id INTEGER PRIMARY KEY,
...         product TEXT,
...         category TEXT,
...         amount REAL,
...         quantity INTEGER,
...         date TEXT
...     );
...     INSERT INTO sales VALUES
...         (1, 'Laptop', 'Electronics', 999.99, 2, '2024-01'),
...         (2, 'Mouse', 'Electronics', 29.99, 10, '2024-01'),
...         (3, 'Desk', 'Furniture', 299.99, 1, '2024-01'),
...         (4, 'Chair', 'Furniture', 199.99, 3, '2024-02'),
...         (5, 'Keyboard', 'Electronics', 79.99, 5, '2024-02'),
...         (6, 'Monitor', 'Electronics', 399.99, 2, '2024-02');
... ''')
>>>
>>> agg = Aggregator(conn)
>>>
>>> # Exemple 1: COUNT simple
>>> results = agg.count("*", "total_sales") \
...              .from_table("sales") \
...              .execute()
>>> print(results[0])
{'total_sales': 6}
>>>
>>> # Exemple 2: Multiple aggregations
>>> results = agg.count("*", "count") \
...              .sum("amount", "total") \
...              .avg("amount", "average") \
...              .min("amount", "min_sale") \
...              .max("amount", "max_sale") \
...              .from_table("sales") \
...              .execute()
>>> print(results[0])
{'count': 6, 'total': 2009.94, 'average': 334.99, 'min_sale': 29.99, 'max_sale': 999.99}
>>>
>>> # Exemple 3: GROUP BY
>>> results = agg.select("category") \
...              .count("*", "products") \
...              .sum("amount", "total") \
...              .from_table("sales") \
...              .group_by("category") \
...              .execute()
>>> for r in results:
...     print(dict(r))
{'category': 'Electronics', 'products': 4, 'total': 1509.96}
{'category': 'Furniture', 'products': 2, 'total': 499.98}
>>>
>>> # Exemple 4: GROUP BY + HAVING
>>> results = agg.select("category") \
...              .count("*", "products") \
...              .sum("amount", "total") \
...              .from_table("sales") \
...              .group_by("category") \
...              .having("COUNT(*) > ?", 2) \
...              .execute()
>>> print(results[0])
{'category': 'Electronics', 'products': 4, 'total': 1509.96}
>>>
>>> # Exemple 5: WHERE + GROUP BY + ORDER BY
>>> sql, params = agg.select("date") \
...                  .sum("amount", "daily_total") \
...                  .from_table("sales") \
...                  .where("category = ?", "Electronics") \
...                  .group_by("date") \
...                  .order_by("daily_total", "DESC") \
...                  .build()
>>> print(sql)
SELECT date, SUM(amount) AS daily_total FROM sales WHERE category = ? GROUP BY date ORDER BY daily_total DESC
>>> print(params)
('Electronics',)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | count_all | COUNT(*) | Nombre total | 10 | Aggregate |
| 2 | count_column | COUNT(col) | Sans NULL | 5 | Aggregate |
| 3 | sum_basic | SUM(col) | Total | 10 | Aggregate |
| 4 | avg_basic | AVG(col) | Moyenne | 10 | Aggregate |
| 5 | min_basic | MIN(col) | Minimum | 5 | Aggregate |
| 6 | max_basic | MAX(col) | Maximum | 5 | Aggregate |
| 7 | multiple_agg | COUNT + SUM + AVG | Tous corrects | 10 | Aggregate |
| 8 | group_by_single | GROUP BY col | Groupes corrects | 10 | GroupBy |
| 9 | group_by_multiple | GROUP BY a, b | Multi-groupes | 5 | GroupBy |
| 10 | having_basic | HAVING COUNT > n | Filtre groupes | 10 | Having |
| 11 | where_group_having | WHERE + GROUP + HAVING | Ordre correct | 10 | Integration |
| 12 | order_by_aggregate | ORDER BY SUM(col) | Tri sur aggregat | 5 | Sort |
| 13 | alias_in_order | ORDER BY alias | Utilise alias | 5 | Alias |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
import sqlite3
from aggregator import Aggregator


@pytest.fixture
def db_with_sales():
    """Cree une base avec donnees de ventes."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        CREATE TABLE sales (
            id INTEGER PRIMARY KEY,
            product TEXT,
            category TEXT,
            amount REAL,
            quantity INTEGER
        );
        INSERT INTO sales VALUES
            (1, 'Laptop', 'Electronics', 999.99, 2),
            (2, 'Mouse', 'Electronics', 29.99, 10),
            (3, 'Desk', 'Furniture', 299.99, 1),
            (4, 'Chair', 'Furniture', 199.99, 3),
            (5, 'Keyboard', 'Electronics', 79.99, 5),
            (6, NULL, 'Other', 50.00, 1);
    ''')
    return conn


def test_count_all(db_with_sales):
    """Test COUNT(*)."""
    agg = Aggregator(db_with_sales)
    results = agg.count("*", "total").from_table("sales").execute()
    assert results[0]["total"] == 6


def test_count_column_ignores_null(db_with_sales):
    """Test que COUNT(column) ignore les NULL."""
    agg = Aggregator(db_with_sales)
    results = agg.count("product", "count").from_table("sales").execute()
    assert results[0]["count"] == 5  # Une ligne a product = NULL


def test_sum_basic(db_with_sales):
    """Test SUM."""
    agg = Aggregator(db_with_sales)
    results = agg.sum("quantity", "total_qty").from_table("sales").execute()
    assert results[0]["total_qty"] == 22  # 2+10+1+3+5+1


def test_avg_basic(db_with_sales):
    """Test AVG."""
    agg = Aggregator(db_with_sales)
    results = agg.avg("amount", "avg_amount").from_table("sales").execute()
    avg = results[0]["avg_amount"]
    assert abs(avg - 276.66) < 1  # Approximation


def test_min_basic(db_with_sales):
    """Test MIN."""
    agg = Aggregator(db_with_sales)
    results = agg.min("amount", "min_val").from_table("sales").execute()
    assert results[0]["min_val"] == 29.99


def test_max_basic(db_with_sales):
    """Test MAX."""
    agg = Aggregator(db_with_sales)
    results = agg.max("amount", "max_val").from_table("sales").execute()
    assert results[0]["max_val"] == 999.99


def test_multiple_aggregations(db_with_sales):
    """Test plusieurs aggregations."""
    agg = Aggregator(db_with_sales)
    results = agg.count("*", "cnt") \
                 .sum("amount", "total") \
                 .avg("amount", "avg") \
                 .from_table("sales") \
                 .execute()

    r = results[0]
    assert r["cnt"] == 6
    assert r["total"] > 0
    assert r["avg"] > 0


def test_group_by_single(db_with_sales):
    """Test GROUP BY sur une colonne."""
    agg = Aggregator(db_with_sales)
    results = agg.select("category") \
                 .count("*", "cnt") \
                 .from_table("sales") \
                 .group_by("category") \
                 .execute()

    categories = {r["category"]: r["cnt"] for r in results}
    assert categories["Electronics"] == 3
    assert categories["Furniture"] == 2


def test_having_basic(db_with_sales):
    """Test HAVING."""
    agg = Aggregator(db_with_sales)
    results = agg.select("category") \
                 .count("*", "cnt") \
                 .from_table("sales") \
                 .group_by("category") \
                 .having("COUNT(*) > ?", 2) \
                 .execute()

    assert len(results) == 1
    assert results[0]["category"] == "Electronics"


def test_where_group_having(db_with_sales):
    """Test WHERE + GROUP BY + HAVING."""
    agg = Aggregator(db_with_sales)
    results = agg.select("category") \
                 .sum("amount", "total") \
                 .from_table("sales") \
                 .where("quantity > ?", 1) \
                 .group_by("category") \
                 .having("SUM(amount) > ?", 100) \
                 .execute()

    # Devrait filtrer par quantity, grouper, puis filtrer par total
    assert len(results) >= 1


def test_order_by_aggregate(db_with_sales):
    """Test ORDER BY sur un aggregat."""
    agg = Aggregator(db_with_sales)
    results = agg.select("category") \
                 .sum("amount", "total") \
                 .from_table("sales") \
                 .group_by("category") \
                 .order_by("total", "DESC") \
                 .execute()

    # Le premier devrait avoir le plus grand total
    assert results[0]["total"] >= results[-1]["total"]


def test_build_returns_correct_sql(db_with_sales):
    """Test que build() genere le bon SQL."""
    agg = Aggregator(db_with_sales)
    sql, params = agg.select("category") \
                     .count("*", "cnt") \
                     .from_table("sales") \
                     .where("amount > ?", 50) \
                     .group_by("category") \
                     .having("COUNT(*) > ?", 1) \
                     .build()

    assert "SELECT" in sql
    assert "COUNT(*)" in sql
    assert "GROUP BY" in sql
    assert "HAVING" in sql
    assert 50 in params
    assert 1 in params
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour Aggregator.
Module C.2.6 - SQL Aggregator
"""

import sqlite3
from typing import Any


class Aggregator:
    """Builder pour les requetes SQL d'aggregation."""

    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._reset()

    def _reset(self):
        """Reinitialise l'etat."""
        self._select_parts: list[str] = []
        self._from: str = ""
        self._where_clauses: list[str] = []
        self._where_params: list[Any] = []
        self._group_by: list[str] = []
        self._having_clauses: list[str] = []
        self._having_params: list[Any] = []
        self._order_by: list[tuple[str, str]] = []

    def _add_aggregate(self, func: str, column: str, alias: str = None) -> 'Aggregator':
        """Ajoute une fonction d'aggregation."""
        agg_str = f"{func}({column})"
        if alias:
            agg_str += f" AS {alias}"
        self._select_parts.append(agg_str)
        return self

    def select(self, *columns: str) -> 'Aggregator':
        """Colonnes non-agregees a selectionner."""
        self._reset()
        self._select_parts.extend(columns)
        return self

    def count(self, column: str = "*", alias: str = None) -> 'Aggregator':
        """COUNT(column)."""
        return self._add_aggregate("COUNT", column, alias)

    def sum(self, column: str, alias: str = None) -> 'Aggregator':
        """SUM(column)."""
        return self._add_aggregate("SUM", column, alias)

    def avg(self, column: str, alias: str = None) -> 'Aggregator':
        """AVG(column)."""
        return self._add_aggregate("AVG", column, alias)

    def min(self, column: str, alias: str = None) -> 'Aggregator':
        """MIN(column)."""
        return self._add_aggregate("MIN", column, alias)

    def max(self, column: str, alias: str = None) -> 'Aggregator':
        """MAX(column)."""
        return self._add_aggregate("MAX", column, alias)

    def from_table(self, table: str) -> 'Aggregator':
        """Table source."""
        self._from = table
        return self

    def where(self, condition: str, *params) -> 'Aggregator':
        """Clause WHERE."""
        self._where_clauses.append(condition)
        self._where_params.extend(params)
        return self

    def group_by(self, *columns: str) -> 'Aggregator':
        """GROUP BY."""
        self._group_by = list(columns)
        return self

    def having(self, condition: str, *params) -> 'Aggregator':
        """HAVING."""
        self._having_clauses.append(condition)
        self._having_params.extend(params)
        return self

    def order_by(self, column: str, direction: str = "ASC") -> 'Aggregator':
        """ORDER BY."""
        direction = direction.upper()
        if direction not in ("ASC", "DESC"):
            direction = "ASC"
        self._order_by.append((column, direction))
        return self

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        parts = []

        # SELECT
        columns = ", ".join(self._select_parts) if self._select_parts else "*"
        parts.append(f"SELECT {columns}")

        # FROM
        if self._from:
            parts.append(f"FROM {self._from}")

        # WHERE
        if self._where_clauses:
            where_sql = " AND ".join(self._where_clauses)
            parts.append(f"WHERE {where_sql}")

        # GROUP BY
        if self._group_by:
            parts.append(f"GROUP BY {', '.join(self._group_by)}")

        # HAVING
        if self._having_clauses:
            having_sql = " AND ".join(self._having_clauses)
            parts.append(f"HAVING {having_sql}")

        # ORDER BY
        if self._order_by:
            order_parts = [f"{col} {dir}" for col, dir in self._order_by]
            parts.append(f"ORDER BY {', '.join(order_parts)}")

        sql = " ".join(parts)
        all_params = tuple(self._where_params + self._having_params)
        return sql, all_params

    def execute(self) -> list[dict]:
        """Execute et retourne les resultats."""
        sql, params = self.build()
        cursor = self._conn.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]


# Exemple d'utilisation
if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    conn.executescript('''
        CREATE TABLE sales (
            id INTEGER PRIMARY KEY,
            product TEXT,
            category TEXT,
            amount REAL,
            quantity INTEGER
        );
        INSERT INTO sales VALUES
            (1, 'Laptop', 'Electronics', 999.99, 2),
            (2, 'Mouse', 'Electronics', 29.99, 10),
            (3, 'Desk', 'Furniture', 299.99, 1),
            (4, 'Chair', 'Furniture', 199.99, 3);
    ''')

    agg = Aggregator(conn)

    # Total par categorie
    print("=== Sales by Category ===")
    results = agg.select("category") \
                 .count("*", "products") \
                 .sum("amount", "total") \
                 .avg("amount", "average") \
                 .from_table("sales") \
                 .group_by("category") \
                 .order_by("total", "DESC") \
                 .execute()

    for r in results:
        print(r)

    conn.close()
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Order) : HAVING avant GROUP BY**

```python
# Mutant A (Order) : Mauvais ordre des clauses
def build(self) -> tuple[str, tuple]:
    parts = [f"SELECT ...", f"FROM ..."]
    if self._where_clauses:
        parts.append(f"WHERE ...")
    if self._having_clauses:
        parts.append(f"HAVING ...")  # Avant GROUP BY !
    if self._group_by:
        parts.append(f"GROUP BY ...")
    # ...

# Genere: ... WHERE ... HAVING ... GROUP BY ...
# Erreur SQL: HAVING doit venir apres GROUP BY
```

**Mutant B (Params) : Mauvais ordre des parametres**

```python
# Mutant B (Params) : HAVING params avant WHERE params
def build(self) -> tuple[str, tuple]:
    # ...
    all_params = tuple(self._having_params + self._where_params)  # Inverse !
    return sql, all_params

# Les parametres sont dans le mauvais ordre
# WHERE amount > 100 AND HAVING COUNT > 2 devient WHERE amount > 2 AND HAVING COUNT > 100
```

**Mutant C (Aggregate) : Pas de parentheses**

```python
# Mutant C (Aggregate) : Syntaxe incorrecte
def _add_aggregate(self, func: str, column: str, alias: str = None):
    agg_str = f"{func} {column}"  # Manque les parentheses !
    # ...

# Genere: COUNT * au lieu de COUNT(*)
# Erreur de syntaxe SQL
```

**Mutant D (GroupBy) : Select sans GROUP BY**

```python
# Mutant D (GroupBy) : Colonne non-agregee sans GROUP BY
def select(self, *columns: str) -> 'Aggregator':
    # Ne verifie pas que les colonnes sont dans GROUP BY
    self._select_parts.extend(columns)
    return self

# SELECT category, COUNT(*) FROM sales
# Sans GROUP BY category: comportement non-standard
```

**Mutant E (Reset) : Pas de reinitialisation**

```python
# Mutant E (Reset) : Accumulation des requetes
def select(self, *columns: str) -> 'Aggregator':
    # Pas de self._reset() !
    self._select_parts.extend(columns)
    return self

# La 2eme requete herite des aggregats de la 1ere
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| COUNT | Compter les lignes | Fondamental |
| SUM | Totaliser | Fondamental |
| AVG | Moyenner | Important |
| MIN/MAX | Extremes | Important |
| GROUP BY | Grouper | Fondamental |
| HAVING | Filtrer groupes | Important |

---

### 5.2 Visualisation ASCII

**Flux d'une requete d'aggregation :**

```
FROM sales                    -- Toutes les lignes
       |
       v
WHERE amount > 10             -- Filtre les lignes
       |
       v
GROUP BY category             -- Regroupe
       |
       v
  +--------+--------+
  | Elec.  | Furn.  |  <- Groupes
  +--------+--------+
       |
       v
HAVING COUNT(*) > 2           -- Filtre les groupes
       |
       v
SELECT category, SUM(amount)  -- Calcule les aggregats
       |
       v
ORDER BY SUM(amount) DESC     -- Trie
       |
       v
    Resultats
```

**WHERE vs HAVING :**

```
Donnees brutes:
+----+----------+--------+
| id | category | amount |
+----+----------+--------+
| 1  | A        | 100    |  WHERE amount > 50
| 2  | A        | 30     |  --> Exclu (30 <= 50)
| 3  | B        | 200    |
| 4  | B        | 60     |
+----+----------+--------+

Apres WHERE (amount > 50):
+----+----------+--------+
| 1  | A        | 100    |
| 3  | B        | 200    |
| 4  | B        | 60     |
+----+----------+--------+

Apres GROUP BY category:
+----------+-------+-------+
| category | COUNT | SUM   |
+----------+-------+-------+
| A        | 1     | 100   |  HAVING COUNT > 1
| B        | 2     | 260   |  --> A exclu
+----------+-------+-------+

Apres HAVING (COUNT > 1):
+----------+-------+-------+
| B        | 2     | 260   |
+----------+-------+-------+
```

---

### 5.3 Les pieges en detail

#### Piege 1 : Colonne non agregee sans GROUP BY

```sql
-- FAUX : category n'est pas agregee ni dans GROUP BY
SELECT category, COUNT(*) FROM sales;
-- Comportement non-standard (SQLite retourne une seule ligne)

-- CORRECT : Ajouter GROUP BY
SELECT category, COUNT(*) FROM sales GROUP BY category;
```

#### Piege 2 : Utiliser un alias dans WHERE

```sql
-- FAUX : L'alias n'existe pas encore dans WHERE
SELECT SUM(amount) AS total FROM sales WHERE total > 100;

-- CORRECT : Utiliser HAVING ou sous-requete
SELECT SUM(amount) AS total FROM sales HAVING total > 100;
```

#### Piege 3 : COUNT(*) vs COUNT(column)

```sql
-- Donnees: [10, NULL, 20, NULL]
SELECT COUNT(*) FROM data;      -- Retourne 4
SELECT COUNT(value) FROM data;  -- Retourne 2 (ignore NULL)
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Col non-agregee | Comportement indefini | GROUP BY |
| 2 | Alias dans WHERE | Erreur SQL | HAVING |
| 3 | COUNT(*) vs COUNT(col) | Resultat different | Choisir selon besoin |
| 4 | HAVING avant GROUP BY | Erreur syntaxe | Respecter l'ordre |
| 5 | AVG avec NULL | Ignore les NULL | COALESCE si besoin |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle clause filtre les GROUPES (pas les lignes individuelles) ?

- A) WHERE
- B) HAVING
- C) GROUP BY
- D) ORDER BY

**Reponse : B** - HAVING filtre apres le groupement.

---

### Question 2 (3 points)
Si une table a 100 lignes dont 20 ont NULL dans la colonne `email`, que retourne COUNT(email) ?

- A) 100
- B) 80
- C) 20
- D) NULL

**Reponse : B** - COUNT(column) ignore les NULL.

---

### Question 3 (4 points)
Quel est l'ordre correct des clauses SQL ?

- A) SELECT, FROM, GROUP BY, WHERE, HAVING
- B) SELECT, FROM, WHERE, GROUP BY, HAVING
- C) SELECT, FROM, WHERE, HAVING, GROUP BY
- D) SELECT, WHERE, FROM, GROUP BY, HAVING

**Reponse : B** - WHERE avant GROUP BY, HAVING apres.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.6 |
| **Nom** | sql_aggregator |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 80 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | COUNT, SUM, AVG, GROUP BY, HAVING |

---

*Document genere selon HACKBRAIN v5.5.2*
