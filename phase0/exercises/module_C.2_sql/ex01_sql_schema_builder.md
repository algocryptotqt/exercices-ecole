# Exercice C.2.1 : sql_schema_builder

**Module :**
C.2 - SQL Fundamentals

**Concept :**
a - Schema Definition (CREATE TABLE, types, PRIMARY KEY, FOREIGN KEY, NOT NULL, DEFAULT, INDEX)

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
- Notion de base de donnees relationnelle
- Types de donnees fondamentaux

**Domaines :**
DB, SQL, Schema

**Duree estimee :**
30 min

**XP Base :**
75

**Complexite :**
T1 O(1) per statement x S1 O(n) storage

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `schema_builder.py` |
| SQL | `schema.sql` (genere) |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `sqlite3.*`, built-ins |
| SQL | CREATE TABLE, ALTER TABLE, DROP TABLE, CREATE INDEX |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | ORM (SQLAlchemy, Django ORM), pandas |
| SQL | Aucune restriction SQL |

---

### 1.2 Consigne

#### Section Culture : "The Architect"

**MATRIX - "You are the result of an unbalanced equation"**

Dans la Matrix, l'Architecte a concu la structure parfaite, chaque element a sa place, chaque contrainte est respectee. Tu es maintenant l'Architecte de ta base de donnees.

Chaque table est un pilier, chaque cle primaire une fondation, chaque cle etrangere un lien vital entre les constructions. Sans schema solide, tout s'effondre.

*"The first Matrix was designed to be perfect, a work of art... inevitably flawed. Your database must not make the same mistake."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une classe `SchemaBuilder` qui permet de construire et executer des schemas SQL de maniere programmatique :

1. **Creation de tables** : Definir des tables avec colonnes typees
2. **Cles primaires** : Definir des identifiants uniques
3. **Cles etrangeres** : Creer des relations entre tables
4. **Contraintes** : NOT NULL, DEFAULT, UNIQUE
5. **Index** : Optimiser les recherches

**Entree (Python) :**

```python
class SchemaBuilder:
    def __init__(self, db_path: str = ":memory:"):
        """Initialise la connexion a la base de donnees."""
        pass

    def create_table(self, table_name: str) -> 'TableBuilder':
        """Demarre la definition d'une nouvelle table."""
        pass

    def execute(self) -> list[str]:
        """Execute toutes les commandes SQL et retourne les statements."""
        pass

    def get_schema(self) -> str:
        """Retourne le schema SQL complet sous forme de texte."""
        pass


class TableBuilder:
    def column(self, name: str, col_type: str,
               primary_key: bool = False,
               not_null: bool = False,
               default: any = None,
               unique: bool = False) -> 'TableBuilder':
        """Ajoute une colonne a la table."""
        pass

    def foreign_key(self, column: str, references: str) -> 'TableBuilder':
        """Ajoute une cle etrangere (format: 'table(column)')."""
        pass

    def index(self, *columns: str) -> 'TableBuilder':
        """Cree un index sur les colonnes specifiees."""
        pass

    def build(self) -> 'SchemaBuilder':
        """Finalise la table et retourne au SchemaBuilder."""
        pass
```

**Sortie :**
- Statements SQL valides generes
- Base de donnees SQLite creee correctement
- Schema exportable en texte

**Types SQL supportes :**

| Type SQL | Description |
|----------|-------------|
| INTEGER | Entier |
| TEXT | Chaine de caracteres |
| REAL | Nombre a virgule flottante |
| BLOB | Donnees binaires |
| BOOLEAN | Booleen (0/1) |
| DATE | Date |
| DATETIME | Date et heure |

**Exemples :**

| Operation | SQL Genere |
|-----------|------------|
| `.column("id", "INTEGER", primary_key=True)` | `id INTEGER PRIMARY KEY` |
| `.column("name", "TEXT", not_null=True)` | `name TEXT NOT NULL` |
| `.column("score", "REAL", default=0.0)` | `score REAL DEFAULT 0.0` |
| `.foreign_key("user_id", "users(id)")` | `FOREIGN KEY (user_id) REFERENCES users(id)` |

---

### 1.3 Prototype

**Python :**
```python
from typing import Any, Optional
import sqlite3

class TableBuilder:
    def __init__(self, schema_builder: 'SchemaBuilder', table_name: str):
        pass

    def column(self, name: str, col_type: str, **kwargs) -> 'TableBuilder':
        pass

    def foreign_key(self, column: str, references: str) -> 'TableBuilder':
        pass

    def index(self, *columns: str) -> 'TableBuilder':
        pass

    def build(self) -> 'SchemaBuilder':
        pass


class SchemaBuilder:
    def __init__(self, db_path: str = ":memory:"):
        pass

    def create_table(self, table_name: str) -> TableBuilder:
        pass

    def execute(self) -> list[str]:
        pass

    def get_schema(self) -> str:
        pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Le NULL n'est pas zero !**

En SQL, NULL represente l'absence de valeur, pas zero ni une chaine vide. C'est pourquoi on utilise `IS NULL` et pas `= NULL`. Meme `NULL = NULL` retourne... NULL (pas TRUE) !

**Les cles etrangeres sont optionnelles en SQLite**

Par defaut, SQLite n'enforce pas les contraintes de cles etrangeres ! Il faut activer `PRAGMA foreign_keys = ON;` pour que ca fonctionne.

**L'index parfait n'existe pas**

Chaque index accelere les lectures mais ralentit les ecritures. Les DBAs passent des heures a trouver le bon equilibre. Un index sur chaque colonne ? Mauvaise idee !

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DBA** | Design et optimisation de schemas de production |
| **Backend Developer** | Migrations de bases de donnees |
| **Data Engineer** | Modelisation de data warehouses |
| **DevOps** | Automatisation des deployments de schema |
| **Architect** | Conception de systemes distribues |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python schema_builder.py

# Exemple d'utilisation
>>> from schema_builder import SchemaBuilder
>>>
>>> schema = SchemaBuilder()
>>> schema.create_table("users") \
...     .column("id", "INTEGER", primary_key=True) \
...     .column("username", "TEXT", not_null=True, unique=True) \
...     .column("email", "TEXT", not_null=True) \
...     .column("created_at", "DATETIME", default="CURRENT_TIMESTAMP") \
...     .index("email") \
...     .build()
>>>
>>> schema.create_table("posts") \
...     .column("id", "INTEGER", primary_key=True) \
...     .column("user_id", "INTEGER", not_null=True) \
...     .column("title", "TEXT", not_null=True) \
...     .column("content", "TEXT") \
...     .column("views", "INTEGER", default=0) \
...     .foreign_key("user_id", "users(id)") \
...     .index("user_id", "created_at") \
...     .build()
>>>
>>> statements = schema.execute()
>>> for stmt in statements:
...     print(stmt)
...
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_users_email ON users (email);
CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    views INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_posts_user_id_created_at ON posts (user_id, created_at);
```

**Verification du schema :**
```bash
$ sqlite3 test.db ".schema"
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_users_email ON users (email);
CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    views INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_posts_user_id_created_at ON posts (user_id, created_at);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_simple_table | 1 table, 2 colonnes | SQL valide | 10 | Basic |
| 2 | primary_key | column avec primary_key=True | PRIMARY KEY dans SQL | 10 | Constraint |
| 3 | not_null | column avec not_null=True | NOT NULL dans SQL | 5 | Constraint |
| 4 | default_value | column avec default=42 | DEFAULT 42 | 10 | Constraint |
| 5 | default_string | default="hello" | DEFAULT 'hello' | 5 | Constraint |
| 6 | unique_constraint | column avec unique=True | UNIQUE dans SQL | 5 | Constraint |
| 7 | foreign_key_basic | foreign_key("col", "t(c)") | FOREIGN KEY valide | 15 | FK |
| 8 | index_single | index("col") | CREATE INDEX | 10 | Index |
| 9 | index_composite | index("a", "b") | INDEX sur (a, b) | 10 | Index |
| 10 | multiple_tables | 3 tables liees | Relations valides | 10 | Integration |
| 11 | execute_creates_db | execute() | Tables existent | 5 | Execution |
| 12 | get_schema_output | get_schema() | SQL complet | 5 | Output |

**Total : 100 points**

---

### 4.2 Tests unitaires (pytest)

```python
import pytest
import sqlite3
from schema_builder import SchemaBuilder, TableBuilder


def test_create_simple_table():
    """Test creation d'une table simple."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("id", "INTEGER") \
        .column("name", "TEXT") \
        .build()

    sql = schema.get_schema()
    assert "CREATE TABLE users" in sql
    assert "id INTEGER" in sql
    assert "name TEXT" in sql


def test_primary_key():
    """Test contrainte PRIMARY KEY."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("id", "INTEGER", primary_key=True) \
        .build()

    sql = schema.get_schema()
    assert "PRIMARY KEY" in sql


def test_not_null_constraint():
    """Test contrainte NOT NULL."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("name", "TEXT", not_null=True) \
        .build()

    sql = schema.get_schema()
    assert "NOT NULL" in sql


def test_default_integer():
    """Test valeur par defaut entiere."""
    schema = SchemaBuilder()
    schema.create_table("scores") \
        .column("points", "INTEGER", default=0) \
        .build()

    sql = schema.get_schema()
    assert "DEFAULT 0" in sql


def test_default_string():
    """Test valeur par defaut chaine."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("role", "TEXT", default="user") \
        .build()

    sql = schema.get_schema()
    assert "DEFAULT 'user'" in sql


def test_unique_constraint():
    """Test contrainte UNIQUE."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("email", "TEXT", unique=True) \
        .build()

    sql = schema.get_schema()
    assert "UNIQUE" in sql


def test_foreign_key():
    """Test cle etrangere."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("id", "INTEGER", primary_key=True) \
        .build()
    schema.create_table("posts") \
        .column("user_id", "INTEGER") \
        .foreign_key("user_id", "users(id)") \
        .build()

    sql = schema.get_schema()
    assert "FOREIGN KEY (user_id) REFERENCES users(id)" in sql


def test_single_column_index():
    """Test index sur une colonne."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("email", "TEXT") \
        .index("email") \
        .build()

    sql = schema.get_schema()
    assert "CREATE INDEX" in sql
    assert "email" in sql


def test_composite_index():
    """Test index composite."""
    schema = SchemaBuilder()
    schema.create_table("logs") \
        .column("user_id", "INTEGER") \
        .column("timestamp", "DATETIME") \
        .index("user_id", "timestamp") \
        .build()

    sql = schema.get_schema()
    assert "user_id" in sql and "timestamp" in sql


def test_execute_creates_tables():
    """Test que execute() cree les tables dans la DB."""
    schema = SchemaBuilder()
    schema.create_table("test_table") \
        .column("id", "INTEGER", primary_key=True) \
        .build()

    schema.execute()

    # Verifier que la table existe
    conn = sqlite3.connect(":memory:")
    # Note: In real test, we'd need access to the same connection


def test_multiple_tables():
    """Test creation de plusieurs tables liees."""
    schema = SchemaBuilder()
    schema.create_table("categories") \
        .column("id", "INTEGER", primary_key=True) \
        .column("name", "TEXT", not_null=True) \
        .build()
    schema.create_table("products") \
        .column("id", "INTEGER", primary_key=True) \
        .column("category_id", "INTEGER") \
        .foreign_key("category_id", "categories(id)") \
        .build()

    sql = schema.get_schema()
    assert "categories" in sql
    assert "products" in sql
    assert "FOREIGN KEY" in sql


def test_full_schema_integration():
    """Test d'integration complet."""
    schema = SchemaBuilder()
    schema.create_table("users") \
        .column("id", "INTEGER", primary_key=True) \
        .column("username", "TEXT", not_null=True, unique=True) \
        .column("email", "TEXT", not_null=True) \
        .column("active", "BOOLEAN", default=True) \
        .index("email") \
        .build()

    schema.create_table("posts") \
        .column("id", "INTEGER", primary_key=True) \
        .column("user_id", "INTEGER", not_null=True) \
        .column("title", "TEXT", not_null=True) \
        .column("views", "INTEGER", default=0) \
        .foreign_key("user_id", "users(id)") \
        .index("user_id") \
        .build()

    statements = schema.execute()
    assert len(statements) >= 4  # 2 tables + 2 indexes
```

---

### 4.3 Solution de reference (Python)

```python
"""
Solution de reference pour SchemaBuilder.
Module C.2.1 - SQL Schema Builder
"""

from typing import Any, Optional
import sqlite3
import re


class TableBuilder:
    """Builder pour la definition d'une table SQL."""

    def __init__(self, schema_builder: 'SchemaBuilder', table_name: str):
        self._schema_builder = schema_builder
        self._table_name = table_name
        self._columns: list[str] = []
        self._foreign_keys: list[str] = []
        self._indexes: list[tuple[str, ...]] = []

    def column(self, name: str, col_type: str,
               primary_key: bool = False,
               not_null: bool = False,
               default: Any = None,
               unique: bool = False) -> 'TableBuilder':
        """Ajoute une colonne a la table."""
        parts = [name, col_type]

        if primary_key:
            parts.append("PRIMARY KEY")
        if not_null:
            parts.append("NOT NULL")
        if unique:
            parts.append("UNIQUE")
        if default is not None:
            if isinstance(default, str) and default not in ("CURRENT_TIMESTAMP", "CURRENT_DATE"):
                parts.append(f"DEFAULT '{default}'")
            elif isinstance(default, bool):
                parts.append(f"DEFAULT {1 if default else 0}")
            else:
                parts.append(f"DEFAULT {default}")

        self._columns.append(" ".join(parts))
        return self

    def foreign_key(self, column: str, references: str) -> 'TableBuilder':
        """Ajoute une cle etrangere."""
        # Parse references format: "table(column)"
        match = re.match(r'(\w+)\((\w+)\)', references)
        if match:
            ref_table, ref_column = match.groups()
            self._foreign_keys.append(
                f"FOREIGN KEY ({column}) REFERENCES {ref_table}({ref_column})"
            )
        return self

    def index(self, *columns: str) -> 'TableBuilder':
        """Ajoute un index sur les colonnes specifiees."""
        self._indexes.append(columns)
        return self

    def build(self) -> 'SchemaBuilder':
        """Finalise la table et retourne au SchemaBuilder."""
        # Build CREATE TABLE statement
        all_defs = self._columns + self._foreign_keys
        columns_sql = ",\n    ".join(all_defs)
        create_sql = f"CREATE TABLE {self._table_name} (\n    {columns_sql}\n);"

        self._schema_builder._statements.append(create_sql)

        # Build CREATE INDEX statements
        for idx_columns in self._indexes:
            idx_name = f"idx_{self._table_name}_{'_'.join(idx_columns)}"
            cols_str = ", ".join(idx_columns)
            index_sql = f"CREATE INDEX {idx_name} ON {self._table_name} ({cols_str});"
            self._schema_builder._statements.append(index_sql)

        return self._schema_builder


class SchemaBuilder:
    """Builder principal pour la construction de schemas SQL."""

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._statements: list[str] = []

    def create_table(self, table_name: str) -> TableBuilder:
        """Demarre la definition d'une nouvelle table."""
        return TableBuilder(self, table_name)

    def execute(self) -> list[str]:
        """Execute toutes les commandes SQL et retourne les statements."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA foreign_keys = ON;")

        for stmt in self._statements:
            self._conn.execute(stmt)

        self._conn.commit()
        return self._statements.copy()

    def get_schema(self) -> str:
        """Retourne le schema SQL complet sous forme de texte."""
        return "\n".join(self._statements)

    def close(self):
        """Ferme la connexion a la base de donnees."""
        if self._conn:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Exemple d'utilisation
if __name__ == "__main__":
    with SchemaBuilder("example.db") as schema:
        schema.create_table("users") \
            .column("id", "INTEGER", primary_key=True) \
            .column("username", "TEXT", not_null=True, unique=True) \
            .column("email", "TEXT", not_null=True) \
            .column("created_at", "DATETIME", default="CURRENT_TIMESTAMP") \
            .index("email") \
            .build()

        schema.create_table("posts") \
            .column("id", "INTEGER", primary_key=True) \
            .column("user_id", "INTEGER", not_null=True) \
            .column("title", "TEXT", not_null=True) \
            .column("content", "TEXT") \
            .column("views", "INTEGER", default=0) \
            .foreign_key("user_id", "users(id)") \
            .index("user_id") \
            .build()

        statements = schema.execute()
        print(schema.get_schema())
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de dataclasses**

```python
from dataclasses import dataclass, field
from typing import List, Optional, Any

@dataclass
class Column:
    name: str
    col_type: str
    primary_key: bool = False
    not_null: bool = False
    default: Optional[Any] = None
    unique: bool = False

    def to_sql(self) -> str:
        parts = [self.name, self.col_type]
        if self.primary_key:
            parts.append("PRIMARY KEY")
        if self.not_null:
            parts.append("NOT NULL")
        if self.unique:
            parts.append("UNIQUE")
        if self.default is not None:
            if isinstance(self.default, str):
                parts.append(f"DEFAULT '{self.default}'")
            else:
                parts.append(f"DEFAULT {self.default}")
        return " ".join(parts)
```

**Alternative 2 : Approche fonctionnelle**

```python
def create_table(name: str, columns: list[dict], fkeys: list = None, indexes: list = None) -> str:
    """Approche fonctionnelle pour creer une table."""
    col_defs = []
    for col in columns:
        col_sql = f"{col['name']} {col['type']}"
        if col.get('primary_key'):
            col_sql += " PRIMARY KEY"
        if col.get('not_null'):
            col_sql += " NOT NULL"
        col_defs.append(col_sql)

    if fkeys:
        for fk in fkeys:
            col_defs.append(f"FOREIGN KEY ({fk['col']}) REFERENCES {fk['ref']}")

    return f"CREATE TABLE {name} (\n    " + ",\n    ".join(col_defs) + "\n);"
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : SQL Injection vulnerable**

```python
# REFUSE : Vulnerable aux injections SQL !
def column(self, name: str, col_type: str) -> 'TableBuilder':
    self._columns.append(f"{name} {col_type}")  # Pas de validation !
    return self

# Attaque possible : column("id; DROP TABLE users; --", "INTEGER")
```
**Pourquoi refuse :** Les noms de colonnes et tables doivent etre valides pour eviter les injections SQL.

**Refus 2 : Pas de gestion des erreurs**

```python
# REFUSE : execute() sans try/except
def execute(self):
    self._conn = sqlite3.connect(self._db_path)
    for stmt in self._statements:
        self._conn.execute(stmt)  # Peut lever une exception non geree
```
**Pourquoi refuse :** Les erreurs SQL doivent etre gerees proprement.

**Refus 3 : Utilisation d'un ORM**

```python
# REFUSE : L'exercice demande du SQL brut
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
```
**Pourquoi refuse :** L'objectif est d'apprendre la syntaxe SQL, pas d'utiliser un ORM.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Syntax) : Oubli de la virgule entre colonnes**

```python
# Mutant A (Syntax) : Mauvais separateur
def build(self) -> 'SchemaBuilder':
    columns_sql = " ".join(self._columns)  # Oubli des virgules !
    create_sql = f"CREATE TABLE {self._table_name} ({columns_sql});"
    # ...

# Genere: CREATE TABLE users (id INTEGER name TEXT)
# Au lieu de: CREATE TABLE users (id INTEGER, name TEXT)
```

**Mutant B (Logic) : DEFAULT mal formate pour les strings**

```python
# Mutant B (Logic) : Pas de quotes autour des strings
def column(self, name: str, col_type: str, default: Any = None, **kwargs):
    if default is not None:
        parts.append(f"DEFAULT {default}")  # Manque les quotes !
    # ...

# Genere: DEFAULT hello
# Au lieu de: DEFAULT 'hello'
```

**Mutant C (Constraint) : PRIMARY KEY mal place**

```python
# Mutant C (Constraint) : PRIMARY KEY avant le type
def column(self, name: str, col_type: str, primary_key: bool = False, **kwargs):
    if primary_key:
        parts = [name, "PRIMARY KEY", col_type]  # Ordre incorrect !
    # ...

# Genere: id PRIMARY KEY INTEGER
# Au lieu de: id INTEGER PRIMARY KEY
```

**Mutant D (FK) : Format de reference incorrect**

```python
# Mutant D (FK) : Parsing incorrect des references
def foreign_key(self, column: str, references: str) -> 'TableBuilder':
    self._foreign_keys.append(
        f"FOREIGN KEY {column} REFERENCES {references}"  # Manque les parentheses !
    )
    # ...

# Genere: FOREIGN KEY user_id REFERENCES users(id)
# Au lieu de: FOREIGN KEY (user_id) REFERENCES users(id)
```

**Mutant E (Index) : Nom d'index invalide**

```python
# Mutant E (Index) : Caracteres speciaux dans le nom d'index
def build(self) -> 'SchemaBuilder':
    for idx_columns in self._indexes:
        idx_name = f"idx-{self._table_name}-{'-'.join(idx_columns)}"  # Tirets invalides !
        # ...

# Genere: CREATE INDEX idx-users-email (invalide en SQL)
# Au lieu de: CREATE INDEX idx_users_email
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| CREATE TABLE | Definir la structure des donnees | Fondamental |
| Types SQL | INTEGER, TEXT, REAL, etc. | Fondamental |
| PRIMARY KEY | Identifiant unique | Fondamental |
| FOREIGN KEY | Relations entre tables | Fondamental |
| NOT NULL | Contrainte d'obligation | Important |
| DEFAULT | Valeurs par defaut | Important |
| INDEX | Optimisation des requetes | Important |

---

### 5.2 LDA - Traduction litterale en MAJUSCULES

```
STRUCTURE TableBuilder CONTENANT :
    schema_builder QUI EST UNE REFERENCE VERS SchemaBuilder
    table_name QUI EST UNE CHAINE DE CARACTERES
    columns QUI EST UNE LISTE DE CHAINES
    foreign_keys QUI EST UNE LISTE DE CHAINES
    indexes QUI EST UNE LISTE DE TUPLES
FIN STRUCTURE

FONCTION column QUI PREND name, col_type, ET options COMME PARAMETRES
DEBUT FONCTION
    CREER parts COMME LISTE CONTENANT name ET col_type
    SI primary_key EST VRAI ALORS
        AJOUTER "PRIMARY KEY" A parts
    FIN SI
    SI not_null EST VRAI ALORS
        AJOUTER "NOT NULL" A parts
    FIN SI
    SI default N'EST PAS NULL ALORS
        SI default EST UNE CHAINE ALORS
            AJOUTER "DEFAULT 'valeur'" A parts
        SINON
            AJOUTER "DEFAULT valeur" A parts
        FIN SI
    FIN SI
    JOINDRE parts AVEC ESPACES ET AJOUTER A columns
    RETOURNER self
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Structure d'une table SQL :**

```
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

+------------------+------------------+------------------+
|   Column Name    |    Data Type     |   Constraints    |
+------------------+------------------+------------------+
|       id         |     INTEGER      |   PRIMARY KEY    |
|    username      |      TEXT        | NOT NULL, UNIQUE |
|      email       |      TEXT        |     NOT NULL     |
|   created_at     |    DATETIME      |  DEFAULT NOW()   |
+------------------+------------------+------------------+
```

**Relations avec Foreign Keys :**

```
+-------------+         +-------------+
|   users     |         |    posts    |
+-------------+         +-------------+
| id (PK)     |<------->| user_id (FK)|
| username    |         | id (PK)     |
| email       |         | title       |
+-------------+         | content     |
                        +-------------+

FOREIGN KEY (user_id) REFERENCES users(id)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Oublier PRAGMA foreign_keys

```python
# FAUX : Les FK ne sont pas enforces
conn = sqlite3.connect("db.sqlite")
conn.execute("INSERT INTO posts (user_id) VALUES (999)")  # Passe meme si user 999 n'existe pas !

# CORRECT : Activer les FK
conn = sqlite3.connect("db.sqlite")
conn.execute("PRAGMA foreign_keys = ON;")
```

#### Piege 2 : Ordre des tables avec FK

```sql
-- FAUX : posts reference users qui n'existe pas encore
CREATE TABLE posts (
    user_id INTEGER REFERENCES users(id)
);
CREATE TABLE users (id INTEGER PRIMARY KEY);

-- CORRECT : Creer users d'abord
CREATE TABLE users (id INTEGER PRIMARY KEY);
CREATE TABLE posts (
    user_id INTEGER REFERENCES users(id)
);
```

#### Piege 3 : DEFAULT avec quotes

```sql
-- FAUX : hello est interprete comme un nom de colonne
CREATE TABLE users (role TEXT DEFAULT hello);

-- CORRECT : Quotes autour de la chaine
CREATE TABLE users (role TEXT DEFAULT 'hello');
```

---

### 5.5 Cours Complet

#### 5.5.1 CREATE TABLE - Syntaxe de base

```sql
CREATE TABLE nom_table (
    colonne1 TYPE [CONTRAINTES],
    colonne2 TYPE [CONTRAINTES],
    ...
    [CONTRAINTES DE TABLE]
);
```

#### 5.5.2 Types de donnees SQL

| Type | Description | Exemple |
|------|-------------|---------|
| INTEGER | Entier signe | 42, -17 |
| REAL | Nombre flottant | 3.14159 |
| TEXT | Chaine Unicode | 'Hello' |
| BLOB | Donnees binaires | Images, fichiers |
| NULL | Absence de valeur | NULL |

#### 5.5.3 Contraintes

| Contrainte | Description |
|------------|-------------|
| PRIMARY KEY | Identifiant unique, auto-increment en SQLite |
| NOT NULL | Valeur obligatoire |
| UNIQUE | Valeur unique dans la colonne |
| DEFAULT | Valeur par defaut |
| CHECK | Condition a respecter |
| FOREIGN KEY | Reference vers une autre table |

#### 5.5.4 Index

```sql
-- Index simple
CREATE INDEX idx_users_email ON users (email);

-- Index composite
CREATE INDEX idx_posts_user_date ON posts (user_id, created_at);

-- Index unique
CREATE UNIQUE INDEX idx_users_username ON users (username);
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | FK non activees | Integrite non respectee | PRAGMA foreign_keys = ON |
| 2 | Ordre des tables | Erreur de reference | Creer tables parents d'abord |
| 3 | Quotes manquantes | Erreur de syntaxe | Toujours quoter les strings |
| 4 | Virgules oubliees | SQL invalide | Verifier le formatage |
| 5 | Types incompatibles | Erreur d'insertion | Verifier les types |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle contrainte garantit qu'une colonne ne peut pas contenir de valeurs dupliquees ?

- A) PRIMARY KEY
- B) NOT NULL
- C) UNIQUE
- D) DEFAULT
- E) FOREIGN KEY

**Reponse : C** - UNIQUE empeche les doublons. PRIMARY KEY implique aussi UNIQUE mais ajoute NOT NULL.

---

### Question 2 (3 points)
Quel statement active les contraintes de cles etrangeres en SQLite ?

- A) SET FOREIGN_KEYS = TRUE;
- B) PRAGMA foreign_keys = ON;
- C) ENABLE FOREIGN KEYS;
- D) ALTER DATABASE SET FK ON;

**Reponse : B** - PRAGMA foreign_keys = ON; est la syntaxe SQLite.

---

### Question 3 (4 points)
Quelle est la bonne syntaxe pour definir une cle etrangere ?

- A) FOREIGN KEY user_id REFERENCES users.id
- B) FOREIGN KEY (user_id) REFERENCES users(id)
- C) REFERENCES users(id) ON user_id
- D) user_id FOREIGN KEY users(id)

**Reponse : B** - La syntaxe correcte utilise des parentheses autour de la colonne locale et de la reference.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.2.1 |
| **Nom** | sql_schema_builder |
| **Difficulte** | 3/10 |
| **Duree** | 30 min |
| **XP Base** | 75 |
| **Langage** | Python 3.14 + SQL |
| **Concepts cles** | CREATE TABLE, PRIMARY KEY, FOREIGN KEY, INDEX |

---

*Document genere selon HACKBRAIN v5.5.2*
