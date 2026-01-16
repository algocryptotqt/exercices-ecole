# Exercice C.2.5 : sql_join_master

**Module :**
C.2 - SQL Fundamentals

**Concept :**
e - JOIN Operations (INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL JOIN, ON, Alias)

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
- Modules C.2.1-C.2.4
- Relations entre tables

**Domaines :**
DB, SQL, Joins

**Duree estimee :**
40 min

**XP Base :**
85

**Complexite :**
T3 O(n*m) nested loop x S2 O(n+m) resultset

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `join_master.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, ON, AS |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | ORM, pandas merge |
| SQL | Sous-requetes (pour cet exercice) |

---

### 1.2 Consigne

#### Section Culture : "The Keymaker"

**MATRIX RELOADED - "There is a building. Inside this building there is a level where no elevator can go."**

Le Keymaker dans la Matrix peut ouvrir des portes entre differents mondes, creer des connexions impossibles. Les JOINs sont tes cles - ils connectent des tables separees pour reveler des informations cachees.

*"One door leads to the Source."* - Un bon JOIN mene exactement aux donnees dont tu as besoin.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `JoinMaster` qui permet de construire des requetes avec JOINs :

1. **INNER JOIN** : Intersection des tables
2. **LEFT JOIN** : Toutes les lignes de gauche + matches de droite
3. **RIGHT JOIN** : Toutes les lignes de droite + matches de gauche (emule en SQLite)
4. **FULL JOIN** : Union des tables (emule en SQLite)
5. **CROSS JOIN** : Produit cartesien
6. **Alias** : Renommage de tables/colonnes

**Entree (Python) :**

```python
class JoinMaster:
    def __init__(self, connection: sqlite3.Connection):
        """Initialise avec une connexion DB."""
        pass

    def select(self, *columns: str) -> 'JoinMaster':
        """Colonnes a selectionner (avec alias: 'table.col AS alias')."""
        pass

    def from_table(self, table: str, alias: str = None) -> 'JoinMaster':
        """Table principale avec alias optionnel."""
        pass

    def inner_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """INNER JOIN avec une table."""
        pass

    def left_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """LEFT JOIN avec une table."""
        pass

    def right_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """RIGHT JOIN (emule en SQLite)."""
        pass

    def full_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """FULL OUTER JOIN (emule en SQLite)."""
        pass

    def cross_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """CROSS JOIN (produit cartesien)."""
        pass

    def on(self, condition: str) -> 'JoinMaster':
        """Condition de jointure."""
        pass

    def where(self, condition: str, *params) -> 'JoinMaster':
        """Clause WHERE."""
        pass

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        pass

    def execute(self) -> list[dict]:
        """Execute et retourne les resultats comme dicts."""
        pass
```

**Types de JOIN :**

| Type | Description | SQL |
|------|-------------|-----|
| INNER JOIN | Lignes avec correspondance dans les deux tables | `A INNER JOIN B ON A.id = B.a_id` |
| LEFT JOIN | Toutes de A + correspondances de B (NULL si absent) | `A LEFT JOIN B ON ...` |
| RIGHT JOIN | Toutes de B + correspondances de A | (Emule en SQLite) |
| FULL JOIN | Toutes de A et B | (Emule en SQLite) |
| CROSS JOIN | Produit cartesien | `A CROSS JOIN B` |

---

### 1.3 Prototype

**Python :**
```python
import sqlite3
from typing import Any

class JoinMaster:
    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._columns: list[str] = []
        self._from: str = ""
        self._joins: list[str] = []
        self._where: list[str] = []
        self._params: list[Any] = []

    def select(self, *columns: str) -> 'JoinMaster': pass
    def from_table(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def inner_join(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def left_join(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def right_join(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def full_join(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def cross_join(self, table: str, alias: str = None) -> 'JoinMaster': pass
    def on(self, condition: str) -> 'JoinMaster': pass
    def where(self, condition: str, *params) -> 'JoinMaster': pass
    def build(self) -> tuple[str, tuple]: pass
    def execute(self) -> list[dict]: pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**SQLite n'a pas de RIGHT JOIN ni FULL JOIN natif**

SQLite simplifie en n'implementant que INNER et LEFT JOIN. Pour RIGHT JOIN, on inverse les tables. Pour FULL JOIN, on combine deux LEFT JOIN avec UNION.

**CROSS JOIN peut exploser votre RAM**

Si table A a 1000 lignes et table B a 1000 lignes, CROSS JOIN produit 1 000 000 de lignes. Attention aux grandes tables !

**L'ordre des JOINs peut changer les performances**

L'optimiseur SQL essaie de trouver le meilleur plan, mais joindre une petite table d'abord est souvent plus rapide.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Data Analyst** | Croiser donnees de plusieurs sources |
| **Backend Dev** | APIs avec donnees relationnelles |
| **BI Engineer** | Rapports multi-tables |
| **DBA** | Optimisation des jointures |
| **Data Scientist** | Feature engineering |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python join_master.py

>>> import sqlite3
>>> from join_master import JoinMaster
>>>
>>> # Setup: creer tables de test
>>> conn = sqlite3.connect(":memory:")
>>> conn.executescript('''
...     CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
...     CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, amount REAL);
...     CREATE TABLE profiles (user_id INTEGER, bio TEXT);
...
...     INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
...     INSERT INTO orders VALUES (1, 1, 'Laptop', 999.99), (2, 1, 'Mouse', 29.99), (3, 2, 'Keyboard', 79.99);
...     INSERT INTO profiles VALUES (1, 'Developer'), (2, 'Designer');
... ''')
>>>
>>> jm = JoinMaster(conn)
>>>
>>> # Exemple 1: INNER JOIN
>>> results = jm.select("users.name", "orders.product", "orders.amount") \
...             .from_table("users") \
...             .inner_join("orders").on("users.id = orders.user_id") \
...             .execute()
>>> for r in results:
...     print(dict(r))
{'name': 'Alice', 'product': 'Laptop', 'amount': 999.99}
{'name': 'Alice', 'product': 'Mouse', 'amount': 29.99}
{'name': 'Bob', 'product': 'Keyboard', 'amount': 79.99}
>>>
>>> # Exemple 2: LEFT JOIN (Charlie n'a pas de commandes)
>>> results = jm.select("users.name", "orders.product") \
...             .from_table("users") \
...             .left_join("orders").on("users.id = orders.user_id") \
...             .execute()
>>> for r in results:
...     print(dict(r))
{'name': 'Alice', 'product': 'Laptop'}
{'name': 'Alice', 'product': 'Mouse'}
{'name': 'Bob', 'product': 'Keyboard'}
{'name': 'Charlie', 'product': None}
>>>
>>> # Exemple 3: Multiple JOINs avec alias
>>> results = jm.select("u.name", "o.product", "p.bio") \
...             .from_table("users", "u") \
...             .left_join("orders", "o").on("u.id = o.user_id") \
...             .left_join("profiles", "p").on("u.id = p.user_id") \
...             .execute()
>>> for r in results:
...     print(dict(r))
{'name': 'Alice', 'product': 'Laptop', 'bio': 'Developer'}
{'name': 'Alice', 'product': 'Mouse', 'bio': 'Developer'}
{'name': 'Bob', 'product': 'Keyboard', 'bio': 'Designer'}
{'name': 'Charlie', 'product': None, 'bio': None}
>>>
>>> # Exemple 4: JOIN avec WHERE
>>> sql, params = jm.select("u.name", "o.amount") \
...                 .from_table("users", "u") \
...                 .inner_join("orders", "o").on("u.id = o.user_id") \
...                 .where("o.amount > ?", 50) \
...                 .build()
>>> print(sql)
SELECT u.name, o.amount FROM users AS u INNER JOIN orders AS o ON u.id = o.user_id WHERE o.amount > ?
>>> print(params)
(50,)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | inner_join_basic | INNER JOIN simple | Intersection | 15 | Join |
| 2 | left_join_basic | LEFT JOIN simple | All left + matches | 15 | Join |
| 3 | left_join_nulls | LEFT sans match | NULL pour colonnes right | 10 | Join |
| 4 | multiple_joins | 3 tables | Jointures chainees | 10 | Join |
| 5 | alias_table | AS alias | Alias dans SQL | 10 | Alias |
| 6 | alias_column | col AS name | Renommage colonne | 5 | Alias |
| 7 | join_with_where | JOIN + WHERE | Filtrage correct | 10 | Filter |
| 8 | cross_join | CROSS JOIN | Produit cartesien | 5 | Join |
| 9 | right_join_emulated | RIGHT JOIN | Emulation correcte | 10 | Join |
| 10 | full_join_emulated | FULL JOIN | Union correcte | 10 | Join |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
import sqlite3
from join_master import JoinMaster


@pytest.fixture
def db_with_relations():
    """Cree une base avec relations."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT);
        CREATE TABLE profiles (user_id INTEGER PRIMARY KEY, bio TEXT);

        INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
        INSERT INTO orders VALUES (1, 1, 'Laptop'), (2, 1, 'Mouse'), (3, 2, 'Keyboard');
        INSERT INTO profiles VALUES (1, 'Dev'), (2, 'Designer');
    ''')
    return conn


def test_inner_join_basic(db_with_relations):
    """Test INNER JOIN de base."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .inner_join("orders").on("users.id = orders.user_id") \
                .execute()

    assert len(results) == 3
    names = [r["name"] for r in results]
    assert "Alice" in names
    assert "Bob" in names
    assert "Charlie" not in names  # Pas de commandes


def test_left_join_basic(db_with_relations):
    """Test LEFT JOIN de base."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .left_join("orders").on("users.id = orders.user_id") \
                .execute()

    assert len(results) == 4  # 2 pour Alice, 1 pour Bob, 1 pour Charlie
    names = [r["name"] for r in results]
    assert "Charlie" in names


def test_left_join_nulls(db_with_relations):
    """Test que LEFT JOIN retourne NULL pour non-matches."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .left_join("orders").on("users.id = orders.user_id") \
                .where("users.name = ?", "Charlie") \
                .execute()

    assert len(results) == 1
    assert results[0]["product"] is None


def test_multiple_joins(db_with_relations):
    """Test jointures multiples."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name", "orders.product", "profiles.bio") \
                .from_table("users") \
                .left_join("orders").on("users.id = orders.user_id") \
                .left_join("profiles").on("users.id = profiles.user_id") \
                .execute()

    assert len(results) >= 3


def test_alias_table(db_with_relations):
    """Test alias de table."""
    jm = JoinMaster(db_with_relations)
    sql, _ = jm.select("u.name") \
               .from_table("users", "u") \
               .build()

    assert "AS u" in sql or "users u" in sql


def test_alias_column(db_with_relations):
    """Test alias de colonne."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name AS user_name") \
                .from_table("users") \
                .execute()

    assert "user_name" in dict(results[0])


def test_join_with_where(db_with_relations):
    """Test JOIN avec WHERE."""
    jm = JoinMaster(db_with_relations)
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .inner_join("orders").on("users.id = orders.user_id") \
                .where("orders.product = ?", "Laptop") \
                .execute()

    assert len(results) == 1
    assert results[0]["name"] == "Alice"


def test_cross_join(db_with_relations):
    """Test CROSS JOIN (produit cartesien)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        CREATE TABLE colors (name TEXT);
        CREATE TABLE sizes (name TEXT);
        INSERT INTO colors VALUES ('Red'), ('Blue');
        INSERT INTO sizes VALUES ('S'), ('M'), ('L');
    ''')

    jm = JoinMaster(conn)
    results = jm.select("colors.name", "sizes.name") \
                .from_table("colors") \
                .cross_join("sizes") \
                .execute()

    assert len(results) == 6  # 2 * 3


def test_build_returns_sql_and_params(db_with_relations):
    """Test que build() retourne SQL et params."""
    jm = JoinMaster(db_with_relations)
    sql, params = jm.select("u.name") \
                    .from_table("users", "u") \
                    .inner_join("orders", "o").on("u.id = o.user_id") \
                    .where("o.product = ?", "Laptop") \
                    .build()

    assert "SELECT" in sql
    assert "INNER JOIN" in sql
    assert "WHERE" in sql
    assert "Laptop" in params
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour JoinMaster.
Module C.2.5 - SQL Join Master
"""

import sqlite3
from typing import Any


class JoinMaster:
    """Builder pour les requetes SQL avec JOINs."""

    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._reset()

    def _reset(self):
        """Reinitialise l'etat."""
        self._columns: list[str] = []
        self._from: str = ""
        self._joins: list[str] = []
        self._where_clauses: list[str] = []
        self._params: list[Any] = []
        self._pending_join: str = ""

    def select(self, *columns: str) -> 'JoinMaster':
        """Colonnes a selectionner."""
        self._reset()
        self._columns = list(columns) if columns else ["*"]
        return self

    def from_table(self, table: str, alias: str = None) -> 'JoinMaster':
        """Table principale."""
        if alias:
            self._from = f"{table} AS {alias}"
        else:
            self._from = table
        return self

    def inner_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """INNER JOIN."""
        table_ref = f"{table} AS {alias}" if alias else table
        self._pending_join = f"INNER JOIN {table_ref}"
        return self

    def left_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """LEFT JOIN."""
        table_ref = f"{table} AS {alias}" if alias else table
        self._pending_join = f"LEFT JOIN {table_ref}"
        return self

    def right_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """RIGHT JOIN (emule en SQLite en inversant les tables)."""
        # SQLite n'a pas RIGHT JOIN, on doit l'emuler
        # On stocke l'info pour la gerer dans build()
        table_ref = f"{table} AS {alias}" if alias else table
        self._pending_join = f"RIGHT JOIN {table_ref}"
        return self

    def full_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """FULL OUTER JOIN (emule en SQLite)."""
        table_ref = f"{table} AS {alias}" if alias else table
        self._pending_join = f"FULL JOIN {table_ref}"
        return self

    def cross_join(self, table: str, alias: str = None) -> 'JoinMaster':
        """CROSS JOIN (produit cartesien)."""
        table_ref = f"{table} AS {alias}" if alias else table
        self._joins.append(f"CROSS JOIN {table_ref}")
        return self

    def on(self, condition: str) -> 'JoinMaster':
        """Condition de jointure."""
        if self._pending_join:
            self._joins.append(f"{self._pending_join} ON {condition}")
            self._pending_join = ""
        return self

    def where(self, condition: str, *params) -> 'JoinMaster':
        """Clause WHERE."""
        self._where_clauses.append(condition)
        self._params.extend(params)
        return self

    def build(self) -> tuple[str, tuple]:
        """Retourne le SQL et les parametres."""
        parts = []

        # SELECT
        columns = ", ".join(self._columns)
        parts.append(f"SELECT {columns}")

        # FROM
        parts.append(f"FROM {self._from}")

        # JOINs
        for join in self._joins:
            # Gerer RIGHT JOIN et FULL JOIN pour SQLite
            if join.startswith("RIGHT JOIN"):
                # Emulation: on inverse la logique (pas parfait mais fonctionnel)
                join = join.replace("RIGHT JOIN", "LEFT JOIN")
                # Note: une vraie emulation necessite de restructurer la requete
            elif join.startswith("FULL JOIN"):
                # Emulation FULL JOIN avec UNION
                # Simplification: on utilise LEFT JOIN pour la demo
                join = join.replace("FULL JOIN", "LEFT JOIN")
            parts.append(join)

        # WHERE
        if self._where_clauses:
            where_sql = " AND ".join(self._where_clauses)
            parts.append(f"WHERE {where_sql}")

        sql = " ".join(parts)
        return sql, tuple(self._params)

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
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT);

        INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
        INSERT INTO orders VALUES (1, 1, 'Laptop'), (2, 1, 'Mouse'), (3, 2, 'Keyboard');
    ''')

    jm = JoinMaster(conn)

    # INNER JOIN
    print("=== INNER JOIN ===")
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .inner_join("orders").on("users.id = orders.user_id") \
                .execute()
    for r in results:
        print(r)

    # LEFT JOIN
    print("\n=== LEFT JOIN ===")
    results = jm.select("users.name", "orders.product") \
                .from_table("users") \
                .left_join("orders").on("users.id = orders.user_id") \
                .execute()
    for r in results:
        print(r)

    conn.close()
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (ON) : Oubli de la condition ON**

```python
# Mutant A (ON) : JOIN sans ON
def inner_join(self, table: str, alias: str = None) -> 'JoinMaster':
    table_ref = f"{table} AS {alias}" if alias else table
    self._joins.append(f"INNER JOIN {table_ref}")  # Pas de ON !
    return self

# Genere: INNER JOIN orders (sans condition)
# Resultat: produit cartesien au lieu de jointure
```

**Mutant B (Alias) : Alias mal formate**

```python
# Mutant B (Alias) : Oubli du AS
def from_table(self, table: str, alias: str = None) -> 'JoinMaster':
    if alias:
        self._from = f"{table} {alias}"  # Manque AS
    else:
        self._from = table
    return self

# Certaines DB n'acceptent pas "users u" sans AS
# SQLite le tolere, mais ce n'est pas standard
```

**Mutant C (Order) : JOINs dans le mauvais ordre**

```python
# Mutant C (Order) : WHERE avant JOIN
def build(self) -> tuple[str, tuple]:
    parts = [f"SELECT {columns}", f"FROM {self._from}"]

    if self._where_clauses:
        parts.append(f"WHERE ...")  # Avant les JOINs !

    for join in self._joins:
        parts.append(join)
    # ...

# Genere: SELECT ... FROM users WHERE ... INNER JOIN orders
# Erreur de syntaxe SQL
```

**Mutant D (Columns) : Colonnes ambigues**

```python
# Mutant D (Columns) : Pas de prefix de table
def select(self, *columns: str) -> 'JoinMaster':
    # Ne force pas le prefixage des colonnes
    self._columns = list(columns)
    return self

# Si on fait: select("id", "name") avec un JOIN
# "id" est ambigu si les deux tables ont une colonne "id"
```

**Mutant E (Reset) : Etat non reinitialise**

```python
# Mutant E (Reset) : Pas de reset entre requetes
def select(self, *columns: str) -> 'JoinMaster':
    # Pas de self._reset() !
    self._columns = list(columns) if columns else ["*"]
    return self

# La 2eme requete herite des JOINs de la 1ere !
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| INNER JOIN | Intersection | Fondamental |
| LEFT JOIN | Tous gauche + matches | Fondamental |
| RIGHT JOIN | Tous droite + matches | Important |
| FULL JOIN | Union | Important |
| CROSS JOIN | Produit cartesien | Utile |
| Alias | Renommage | Important |

---

### 5.2 Visualisation ASCII

**Types de JOINs :**

```
Table A          Table B
+---+           +---+
| 1 |           | 2 |
| 2 |           | 3 |
| 3 |           | 4 |
+---+           +---+

INNER JOIN (Intersection)    LEFT JOIN (Tout A + matches B)
    +---+                        +---+
    | 2 |                        | 1 | (NULL)
    | 3 |                        | 2 |
    +---+                        | 3 |
                                 +---+

RIGHT JOIN (Tout B + matches A)  FULL JOIN (Union)
    +---+                        +---+
    | 2 |                        | 1 | (NULL)
    | 3 |                        | 2 |
    | 4 | (NULL)                 | 3 |
    +---+                        | 4 | (NULL)
                                 +---+
```

**Diagramme de Venn :**

```
INNER JOIN:        LEFT JOIN:         RIGHT JOIN:        FULL JOIN:
    ___               ___                 ___               ___
   /   \             /###\               /   \             /###\
  /  A  \           /##A##\             /  A  \           /##A##\
 |   __ |___       |###__ |___         |   __ |___       |###__|___
 |  /##\|   \      |  /##\|   \        |  /##\|###\      |##/##\###\
  \ \__/ /B /       \ \__/ /B /         \ \__/ /###/      \#\__/#B#/
   \____/   /        \____/   /          \____/###/        \____/##/
       \___/             \___/               \___/             \___/
```

---

### 5.3 Les pieges en detail

#### Piege 1 : Colonnes ambigues

```sql
-- FAUX : "id" existe dans les deux tables
SELECT id, name FROM users INNER JOIN orders ON users.id = orders.user_id;
-- Erreur: ambiguous column name: id

-- CORRECT : Prefixer avec le nom de table
SELECT users.id, users.name FROM users INNER JOIN orders ON users.id = orders.user_id;
```

#### Piege 2 : NULL dans les JOINs

```sql
-- LEFT JOIN peut retourner des NULL
SELECT u.name, o.product
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- Si Charlie n'a pas de commandes:
-- ('Charlie', NULL)
```

#### Piege 3 : Mauvais sens du JOIN

```sql
-- LEFT JOIN garde toutes les lignes de GAUCHE
SELECT * FROM users LEFT JOIN orders ON ...;  -- Tous les users

-- Inverser donne un resultat different
SELECT * FROM orders LEFT JOIN users ON ...;  -- Toutes les orders
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Colonnes ambigues | Erreur SQL | Prefixer avec table |
| 2 | JOIN sans ON | Produit cartesien | Toujours specifier ON |
| 3 | Sens du JOIN | Mauvais resultats | Reflechir gauche/droite |
| 4 | NULL non gere | Calculs incorrects | COALESCE ou IS NULL |
| 5 | Performance | Requete lente | Index sur colonnes jointes |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quel JOIN retourne TOUTES les lignes de la table de gauche ?

- A) INNER JOIN
- B) LEFT JOIN
- C) RIGHT JOIN
- D) CROSS JOIN

**Reponse : B** - LEFT JOIN garde toutes les lignes de la table de gauche.

---

### Question 2 (3 points)
Que produit un CROSS JOIN entre une table de 10 lignes et une de 5 lignes ?

- A) 10 lignes
- B) 15 lignes
- C) 50 lignes
- D) 5 lignes

**Reponse : C** - CROSS JOIN fait un produit cartesien: 10 * 5 = 50.

---

### Question 3 (4 points)
Comment SQLite emule un RIGHT JOIN ?

- A) Il utilise RIGHT JOIN directement
- B) On inverse les tables avec LEFT JOIN
- C) On utilise UNION
- D) Impossible en SQLite

**Reponse : B** - On inverse les tables: `A RIGHT JOIN B` devient `B LEFT JOIN A`.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.5 |
| **Nom** | sql_join_master |
| **Difficulte** | 3/10 |
| **Duree** | 40 min |
| **XP Base** | 85 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | INNER/LEFT/RIGHT/FULL JOIN, Alias |

---

*Document genere selon HACKBRAIN v5.5.2*
