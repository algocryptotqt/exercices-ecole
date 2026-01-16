# Exercice C.2.4 : sql_crud_manager

**Module :**
C.2 - SQL Fundamentals

**Concept :**
d - CRUD Operations (INSERT, VALUES, UPDATE, SET, DELETE, TRUNCATE, ALTER TABLE)

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
- Modules C.2.1-C.2.3
- Comprehension des transactions

**Domaines :**
DB, SQL, CRUD

**Duree estimee :**
35 min

**XP Base :**
80

**Complexite :**
T1 O(1) single row x T2 O(n) bulk x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `crud_manager.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | INSERT, UPDATE, DELETE, TRUNCATE, ALTER TABLE |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | ORM, DROP TABLE (sauf dans tests) |

---

### 1.2 Consigne

#### Section Culture : "The Merovingian"

**MATRIX RELOADED - "Choice is an illusion created between those with power and those without."**

Le Merovingien controle le traffic d'informations dans la Matrix. Il peut creer, modifier et supprimer ce qu'il veut. Tu vas devenir le Merovingien de ta base de donnees - maitrisant les operations CRUD (Create, Read, Update, Delete).

*"I have survived your predecessors, and I will survive you!"* - Comme tes donnees persistent entre les sessions.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `CRUDManager` qui encapsule les operations de modification de donnees :

1. **Create** : INSERT INTO ... VALUES
2. **Update** : UPDATE ... SET ... WHERE
3. **Delete** : DELETE FROM ... WHERE
4. **Truncate** : Vider une table
5. **Alter** : Modifier la structure d'une table

**Entree (Python) :**

```python
class CRUDManager:
    def __init__(self, connection: sqlite3.Connection):
        """Initialise le manager avec une connexion DB."""
        pass

    # INSERT
    def insert(self, table: str, data: dict) -> int:
        """Insere une ligne et retourne l'ID genere."""
        pass

    def insert_many(self, table: str, columns: list[str], rows: list[tuple]) -> int:
        """Insere plusieurs lignes, retourne le nombre insere."""
        pass

    # UPDATE
    def update(self, table: str, data: dict, where: str, *params) -> int:
        """Met a jour des lignes, retourne le nombre modifie."""
        pass

    # DELETE
    def delete(self, table: str, where: str, *params) -> int:
        """Supprime des lignes, retourne le nombre supprime."""
        pass

    def truncate(self, table: str) -> None:
        """Vide completement une table."""
        pass

    # ALTER TABLE
    def add_column(self, table: str, column: str, col_type: str,
                   default: any = None) -> None:
        """Ajoute une colonne a une table existante."""
        pass

    def rename_table(self, old_name: str, new_name: str) -> None:
        """Renomme une table."""
        pass

    # Transaction helpers
    def begin_transaction(self) -> None:
        """Demarre une transaction."""
        pass

    def commit(self) -> None:
        """Valide la transaction."""
        pass

    def rollback(self) -> None:
        """Annule la transaction."""
        pass
```

**Sortie :**
- Operations executees avec succes
- Nombre de lignes affectees retourne
- Support des transactions

**Operations CRUD :**

| Operation | SQL | Description |
|-----------|-----|-------------|
| INSERT | `INSERT INTO t (cols) VALUES (vals)` | Cree une nouvelle ligne |
| UPDATE | `UPDATE t SET col=val WHERE cond` | Modifie des lignes existantes |
| DELETE | `DELETE FROM t WHERE cond` | Supprime des lignes |
| TRUNCATE | `DELETE FROM t` | Vide la table (pas de WHERE) |

---

### 1.3 Prototype

**Python :**
```python
import sqlite3
from typing import Any

class CRUDManager:
    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row

    def insert(self, table: str, data: dict) -> int: pass
    def insert_many(self, table: str, columns: list[str], rows: list[tuple]) -> int: pass
    def update(self, table: str, data: dict, where: str, *params) -> int: pass
    def delete(self, table: str, where: str, *params) -> int: pass
    def truncate(self, table: str) -> None: pass
    def add_column(self, table: str, column: str, col_type: str, default: Any = None) -> None: pass
    def rename_table(self, old_name: str, new_name: str) -> None: pass
    def begin_transaction(self) -> None: pass
    def commit(self) -> None: pass
    def rollback(self) -> None: pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**DELETE vs TRUNCATE**

`DELETE FROM table` est loggue et peut etre rollback. `TRUNCATE TABLE` (dans d'autres DB) est plus rapide mais ne peut pas etre annule. En SQLite, il n'y a pas de vrai TRUNCATE - on utilise `DELETE FROM`.

**INSERT OR REPLACE**

SQLite a une syntaxe speciale : `INSERT OR REPLACE INTO` qui fait un UPSERT (Update or Insert). Tres utile pour les caches !

**ROWID est magique**

En SQLite, chaque table a un ROWID implicite. `INTEGER PRIMARY KEY` devient un alias pour ROWID, ce qui le rend auto-increment.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Backend Developer** | APIs REST CRUD |
| **DevOps** | Migrations de donnees |
| **Data Engineer** | ETL et transformations |
| **DBA** | Maintenance et nettoyage |
| **Mobile Developer** | Sync local/remote |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python crud_manager.py

>>> import sqlite3
>>> from crud_manager import CRUDManager
>>>
>>> conn = sqlite3.connect(":memory:")
>>> conn.execute('''CREATE TABLE users (
...     id INTEGER PRIMARY KEY,
...     name TEXT NOT NULL,
...     email TEXT UNIQUE,
...     age INTEGER DEFAULT 0
... )''')
>>> conn.commit()
>>>
>>> crud = CRUDManager(conn)
>>>
>>> # INSERT simple
>>> user_id = crud.insert("users", {"name": "Alice", "email": "alice@test.com", "age": 25})
>>> print(f"User created with ID: {user_id}")
User created with ID: 1
>>>
>>> # INSERT multiple
>>> rows = [
...     ("Bob", "bob@test.com", 30),
...     ("Charlie", "charlie@test.com", 35),
...     ("Diana", "diana@test.com", 28)
... ]
>>> count = crud.insert_many("users", ["name", "email", "age"], rows)
>>> print(f"Inserted {count} users")
Inserted 3 users
>>>
>>> # UPDATE
>>> updated = crud.update("users", {"age": 26}, "name = ?", "Alice")
>>> print(f"Updated {updated} row(s)")
Updated 1 row(s)
>>>
>>> # DELETE
>>> deleted = crud.delete("users", "age > ?", 32)
>>> print(f"Deleted {deleted} row(s)")
Deleted 1 row(s)
>>>
>>> # Transaction example
>>> crud.begin_transaction()
>>> try:
...     crud.insert("users", {"name": "Eve", "email": "eve@test.com"})
...     crud.insert("users", {"name": "Frank", "email": "frank@test.com"})
...     crud.commit()
...     print("Transaction committed")
... except Exception as e:
...     crud.rollback()
...     print(f"Transaction rolled back: {e}")
Transaction committed
>>>
>>> # ALTER TABLE - Add column
>>> crud.add_column("users", "active", "INTEGER", default=1)
>>>
>>> # Verify
>>> cursor = conn.execute("SELECT * FROM users")
>>> for row in cursor:
...     print(dict(row))
{'id': 1, 'name': 'Alice', 'email': 'alice@test.com', 'age': 26, 'active': 1}
{'id': 2, 'name': 'Bob', 'email': 'bob@test.com', 'age': 30, 'active': 1}
{'id': 4, 'name': 'Diana', 'email': 'diana@test.com', 'age': 28, 'active': 1}
{'id': 5, 'name': 'Eve', 'email': 'eve@test.com', 'age': 0, 'active': 1}
{'id': 6, 'name': 'Frank', 'email': 'frank@test.com', 'age': 0, 'active': 1}
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | insert_single | insert(t, {data}) | Returns ID | 10 | Create |
| 2 | insert_returns_id | insert(...) | last_insert_rowid | 5 | Create |
| 3 | insert_many | insert_many(t, cols, rows) | Count = len(rows) | 10 | Create |
| 4 | update_single | update(t, data, where) | Returns 1 | 10 | Update |
| 5 | update_multiple | update sans where precis | Returns N | 5 | Update |
| 6 | update_returns_count | update(...) | rowcount | 5 | Update |
| 7 | delete_single | delete(t, where) | Returns 1 | 10 | Delete |
| 8 | delete_multiple | delete large | Returns N | 5 | Delete |
| 9 | truncate | truncate(t) | Table vide | 10 | Delete |
| 10 | add_column | add_column(t, c, type) | Colonne existe | 10 | Alter |
| 11 | add_column_default | add_column(..., default) | Default applique | 5 | Alter |
| 12 | rename_table | rename_table(old, new) | Nouveau nom | 5 | Alter |
| 13 | transaction_commit | begin + commit | Donnees persistees | 5 | Transaction |
| 14 | transaction_rollback | begin + rollback | Donnees annulees | 5 | Transaction |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
import sqlite3
from crud_manager import CRUDManager


@pytest.fixture
def db_with_table():
    """Cree une base avec une table users."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        age INTEGER DEFAULT 0
    )''')
    conn.commit()
    return conn


def test_insert_single(db_with_table):
    """Test insertion simple."""
    crud = CRUDManager(db_with_table)
    user_id = crud.insert("users", {"name": "Alice", "email": "alice@test.com"})
    assert user_id == 1

    cursor = db_with_table.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    assert row["name"] == "Alice"


def test_insert_returns_correct_id(db_with_table):
    """Test que insert retourne le bon ID."""
    crud = CRUDManager(db_with_table)
    id1 = crud.insert("users", {"name": "User1"})
    id2 = crud.insert("users", {"name": "User2"})
    assert id2 == id1 + 1


def test_insert_many(db_with_table):
    """Test insertion multiple."""
    crud = CRUDManager(db_with_table)
    rows = [("Bob", "bob@test.com", 30), ("Charlie", "charlie@test.com", 35)]
    count = crud.insert_many("users", ["name", "email", "age"], rows)
    assert count == 2


def test_update_single(db_with_table):
    """Test mise a jour simple."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice", "age": 25})

    updated = crud.update("users", {"age": 26}, "name = ?", "Alice")
    assert updated == 1


def test_update_multiple(db_with_table):
    """Test mise a jour multiple."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice", "age": 20})
    crud.insert("users", {"name": "Bob", "age": 20})

    updated = crud.update("users", {"age": 21}, "age = ?", 20)
    assert updated == 2


def test_delete_single(db_with_table):
    """Test suppression simple."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice"})

    deleted = crud.delete("users", "name = ?", "Alice")
    assert deleted == 1


def test_delete_multiple(db_with_table):
    """Test suppression multiple."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice", "age": 20})
    crud.insert("users", {"name": "Bob", "age": 20})
    crud.insert("users", {"name": "Charlie", "age": 30})

    deleted = crud.delete("users", "age = ?", 20)
    assert deleted == 2


def test_truncate(db_with_table):
    """Test truncate."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice"})
    crud.insert("users", {"name": "Bob"})

    crud.truncate("users")

    cursor = db_with_table.execute("SELECT COUNT(*) FROM users")
    assert cursor.fetchone()[0] == 0


def test_add_column(db_with_table):
    """Test ajout de colonne."""
    crud = CRUDManager(db_with_table)
    crud.add_column("users", "active", "INTEGER")

    # Verify column exists
    cursor = db_with_table.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    assert "active" in columns


def test_add_column_with_default(db_with_table):
    """Test ajout de colonne avec default."""
    crud = CRUDManager(db_with_table)
    crud.insert("users", {"name": "Alice"})
    crud.add_column("users", "status", "TEXT", default="active")

    cursor = db_with_table.execute("SELECT status FROM users")
    row = cursor.fetchone()
    assert row[0] == "active"


def test_rename_table(db_with_table):
    """Test renommage de table."""
    crud = CRUDManager(db_with_table)
    crud.rename_table("users", "members")

    cursor = db_with_table.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='members'"
    )
    assert cursor.fetchone() is not None


def test_transaction_commit(db_with_table):
    """Test commit de transaction."""
    crud = CRUDManager(db_with_table)
    crud.begin_transaction()
    crud.insert("users", {"name": "Alice"})
    crud.commit()

    cursor = db_with_table.execute("SELECT COUNT(*) FROM users")
    assert cursor.fetchone()[0] == 1


def test_transaction_rollback(db_with_table):
    """Test rollback de transaction."""
    crud = CRUDManager(db_with_table)

    # Insert initial data and commit
    crud.insert("users", {"name": "Initial"})
    crud.commit()

    # Start new transaction
    crud.begin_transaction()
    crud.insert("users", {"name": "Should be rolled back"})
    crud.rollback()

    cursor = db_with_table.execute("SELECT COUNT(*) FROM users")
    assert cursor.fetchone()[0] == 1  # Only Initial
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour CRUDManager.
Module C.2.4 - SQL CRUD Manager
"""

import sqlite3
from typing import Any


class CRUDManager:
    """Manager pour les operations CRUD SQL."""

    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row

    # ============ CREATE ============

    def insert(self, table: str, data: dict) -> int:
        """Insere une ligne et retourne l'ID genere."""
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" * len(data))
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"

        cursor = self._conn.execute(sql, tuple(data.values()))
        self._conn.commit()
        return cursor.lastrowid

    def insert_many(self, table: str, columns: list[str], rows: list[tuple]) -> int:
        """Insere plusieurs lignes, retourne le nombre insere."""
        cols_str = ", ".join(columns)
        placeholders = ", ".join("?" * len(columns))
        sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders})"

        cursor = self._conn.executemany(sql, rows)
        self._conn.commit()
        return cursor.rowcount

    # ============ UPDATE ============

    def update(self, table: str, data: dict, where: str, *params) -> int:
        """Met a jour des lignes, retourne le nombre modifie."""
        set_clause = ", ".join(f"{k} = ?" for k in data.keys())
        sql = f"UPDATE {table} SET {set_clause} WHERE {where}"

        all_params = list(data.values()) + list(params)
        cursor = self._conn.execute(sql, all_params)
        self._conn.commit()
        return cursor.rowcount

    # ============ DELETE ============

    def delete(self, table: str, where: str, *params) -> int:
        """Supprime des lignes, retourne le nombre supprime."""
        sql = f"DELETE FROM {table} WHERE {where}"
        cursor = self._conn.execute(sql, params)
        self._conn.commit()
        return cursor.rowcount

    def truncate(self, table: str) -> None:
        """Vide completement une table."""
        self._conn.execute(f"DELETE FROM {table}")
        self._conn.commit()

    # ============ ALTER TABLE ============

    def add_column(self, table: str, column: str, col_type: str,
                   default: Any = None) -> None:
        """Ajoute une colonne a une table existante."""
        sql = f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
        if default is not None:
            if isinstance(default, str):
                sql += f" DEFAULT '{default}'"
            else:
                sql += f" DEFAULT {default}"

        self._conn.execute(sql)
        self._conn.commit()

    def rename_table(self, old_name: str, new_name: str) -> None:
        """Renomme une table."""
        sql = f"ALTER TABLE {old_name} RENAME TO {new_name}"
        self._conn.execute(sql)
        self._conn.commit()

    # ============ TRANSACTIONS ============

    def begin_transaction(self) -> None:
        """Demarre une transaction."""
        self._conn.execute("BEGIN TRANSACTION")

    def commit(self) -> None:
        """Valide la transaction."""
        self._conn.commit()

    def rollback(self) -> None:
        """Annule la transaction."""
        self._conn.rollback()


# Exemple d'utilisation
if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        age INTEGER DEFAULT 0
    )''')

    crud = CRUDManager(conn)

    # Insert
    user_id = crud.insert("users", {"name": "Alice", "email": "alice@test.com", "age": 25})
    print(f"Inserted user with ID: {user_id}")

    # Update
    updated = crud.update("users", {"age": 26}, "id = ?", user_id)
    print(f"Updated {updated} rows")

    # Add column
    crud.add_column("users", "active", "INTEGER", default=1)

    # Query to verify
    cursor = conn.execute("SELECT * FROM users")
    for row in cursor:
        print(dict(row))

    conn.close()
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Insert) : Pas de commit apres insert**

```python
# Mutant A (Insert) : Transaction non validee
def insert(self, table: str, data: dict) -> int:
    # ... execute SQL ...
    cursor = self._conn.execute(sql, tuple(data.values()))
    # OUBLI: self._conn.commit()
    return cursor.lastrowid

# Les donnees ne sont pas persistees si la connexion est fermee
```

**Mutant B (Update) : Paramettres dans le mauvais ordre**

```python
# Mutant B (Update) : WHERE params avant SET params
def update(self, table: str, data: dict, where: str, *params) -> int:
    set_clause = ", ".join(f"{k} = ?" for k in data.keys())
    sql = f"UPDATE {table} SET {set_clause} WHERE {where}"

    # FAUX : params (WHERE) avant data.values() (SET)
    all_params = list(params) + list(data.values())
    cursor = self._conn.execute(sql, all_params)
    # ...

# Les valeurs sont inversees, UPDATE incorrect
```

**Mutant C (Delete) : DELETE sans WHERE**

```python
# Mutant C (Delete) : Pas de protection
def delete(self, table: str, where: str = None, *params) -> int:
    if where:
        sql = f"DELETE FROM {table} WHERE {where}"
    else:
        sql = f"DELETE FROM {table}"  # DANGER: truncate accidentel !
    # ...

# Un appel sans WHERE supprime tout
```

**Mutant D (Alter) : Quotes manquantes pour default string**

```python
# Mutant D (Alter) : Pas de quotes
def add_column(self, table: str, column: str, col_type: str, default: Any = None):
    sql = f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
    if default is not None:
        sql += f" DEFAULT {default}"  # Pas de quotes pour strings !
    # ...

# Genere: DEFAULT active au lieu de DEFAULT 'active'
# Erreur SQL si default est une string
```

**Mutant E (Transaction) : Commit apres rollback**

```python
# Mutant E (Transaction) : Logic inversee
def rollback(self) -> None:
    self._conn.commit()  # FAUX ! Devrait etre rollback

def commit(self) -> None:
    self._conn.rollback()  # FAUX ! Devrait etre commit

# Comportement completement inverse
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| INSERT | Creer des donnees | Fondamental |
| UPDATE | Modifier des donnees | Fondamental |
| DELETE | Supprimer des donnees | Fondamental |
| TRUNCATE | Vider une table | Important |
| ALTER TABLE | Modifier la structure | Important |
| Transactions | Atomicite des operations | Fondamental |

---

### 5.2 Visualisation ASCII

**Cycle CRUD :**

```
     CREATE (INSERT)
           |
           v
    +-------------+
    |   DONNEES   |<----+
    +-------------+     |
      |         |       |
      v         v       |
   READ     UPDATE -----+
  (SELECT)    |
              |
              v
          DELETE
```

**Transaction :**

```
BEGIN
   |
   +---> INSERT
   |
   +---> UPDATE
   |
   +---> DELETE
   |
   +---> Success? --YES--> COMMIT  --> Permanent
   |
   +---> Error?   --YES--> ROLLBACK --> Undo all
```

---

### 5.3 Les pieges en detail

#### Piege 1 : UPDATE/DELETE sans WHERE

```sql
-- DANGER : Met a jour TOUTES les lignes !
UPDATE users SET status = 'deleted';

-- DANGER : Supprime TOUT !
DELETE FROM users;

-- CORRECT : Toujours avoir une condition
UPDATE users SET status = 'deleted' WHERE id = 42;
DELETE FROM users WHERE id = 42;
```

#### Piege 2 : Oublier le commit

```python
# FAUX : Pas de commit = pas de persistence
conn.execute("INSERT INTO users (name) VALUES ('Alice')")
conn.close()  # Les donnees sont perdues !

# CORRECT : Toujours commit
conn.execute("INSERT INTO users (name) VALUES ('Alice')")
conn.commit()
conn.close()
```

#### Piege 3 : Ordre des parametres

```python
# ATTENTION a l'ordre des ? dans UPDATE
# UPDATE table SET col1 = ?, col2 = ? WHERE id = ?
# Les parametres doivent etre dans l'ordre : col1, col2, id
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | UPDATE sans WHERE | Toutes lignes modifiees | Toujours ajouter WHERE |
| 2 | DELETE sans WHERE | Table videe | Toujours ajouter WHERE |
| 3 | Pas de commit | Donnees perdues | Commit apres chaque op |
| 4 | Ordre parametres | Valeurs inversees | Verifier l'ordre |
| 5 | Rollback oublie | Transaction zombie | Try/except avec rollback |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle commande retourne l'ID de la derniere insertion en SQLite ?

- A) SELECT MAX(id)
- B) LAST_INSERT_ROWID()
- C) cursor.lastrowid
- D) SELECT SCOPE_IDENTITY()

**Reponse : C** - En Python avec sqlite3, c'est cursor.lastrowid.

---

### Question 2 (3 points)
Que fait TRUNCATE dans la plupart des SGBD ?

- A) Supprime la table
- B) Vide la table sans log
- C) Renomme la table
- D) Modifie la structure

**Reponse : B** - TRUNCATE vide la table rapidement sans journaliser chaque ligne.

---

### Question 3 (4 points)
Quand utiliser ROLLBACK ?

- A) Pour valider une transaction
- B) Pour annuler une transaction en cas d'erreur
- C) Pour demarrer une transaction
- D) Pour fermer une connexion

**Reponse : B** - ROLLBACK annule toutes les modifications depuis BEGIN.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.4 |
| **Nom** | sql_crud_manager |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 80 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | INSERT, UPDATE, DELETE, Transactions |

---

*Document genere selon HACKBRAIN v5.5.2*
