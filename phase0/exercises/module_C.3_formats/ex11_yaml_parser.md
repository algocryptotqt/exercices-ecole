# Exercice C.3.0-d : yaml_parser

**Module :**
C.3.0 — Data Formats: YAML Processing

**Concept :**
d — Key-value, indentation, lists, nesting, multiline, comments

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Indentation et structure de blocs
- Recursivite
- Dictionnaires et listes

**Domaines :**
Struct, FS, Encodage

**Duree estimee :**
40 min

**XP Base :**
60

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
`yaml_parser.py`

**Fonctions autorisees :**
- Toutes les fonctions Python natives
- Methodes de string
- Module `re` si necessaire

**Fonctions interdites :**
- Module `yaml` ou `PyYAML` (tu dois implementer toi-meme!)
- Module `ruamel.yaml`
- `eval`, `exec`

---

### 1.2 Consigne

#### Section Culture : "Kubernetes Config Hell"

**"YAML: Yet Another Markup Language... or YAML Ain't Markup Language?"**

Tu es DevOps. Il est 3h du matin. Le cluster Kubernetes est down. Tu ouvres le fichier de config. 500 lignes de YAML. Une indentation de travers. Tout est casse.

YAML est le format de configuration prefere de Kubernetes, Docker Compose, Ansible, GitHub Actions... Ironiquement, un format cense etre "human-readable" cause plus de bugs que n'importe quel autre a cause de son indentation significative.

*"Spaces, not tabs. Always spaces. Two spaces. Not four. TWO."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un parser YAML simplifie :

1. **`parse_yaml(content: str) -> any`** : Parse YAML en objet Python
2. **`yaml_to_dict(content: str) -> dict`** : Parse un document YAML en dictionnaire
3. **`parse_value(value: str) -> any`** : Convertit une valeur YAML en type Python
4. **`get_indent_level(line: str) -> int`** : Calcule le niveau d'indentation
5. **`stringify_yaml(obj: any, indent: int = 0) -> str`** : Convertit objet Python en YAML

**Entree :**
```python
def parse_yaml(content: str) -> any:
    """
    Parse YAML string into Python object.

    Supports:
    - Key-value pairs: key: value
    - Nested objects (via indentation)
    - Lists: - item
    - Inline lists: [a, b, c]
    - Inline objects: {a: 1, b: 2}
    - Strings: "quoted" or unquoted
    - Numbers: 42, 3.14
    - Booleans: true, false, yes, no, on, off
    - Null: null, ~
    - Comments: # ignored
    - Multiline strings: | or >
    """
    pass
```

**Sortie :**
- Dictionnaire, liste, ou valeur scalaire Python
- Les types sont correctement convertis

**Contraintes :**
- L'indentation definit la structure (generalement 2 espaces)
- Les commentaires (`#`) sont ignores
- Les strings multilignes (`|` literal, `>` folded) sont supportees
- Les booleens YAML incluent: `true`, `false`, `yes`, `no`, `on`, `off`

**Exemples :**

| YAML | Python |
|------|--------|
| `name: Alice` | `{'name': 'Alice'}` |
| `age: 30` | `{'age': 30}` |
| `active: true` | `{'active': True}` |
| `items:\n  - a\n  - b` | `{'items': ['a', 'b']}` |
| `# comment` | (ignore) |

---

### 1.3 Prototype

```python
def parse_yaml(content: str) -> any:
    pass

def yaml_to_dict(content: str) -> dict:
    pass

def parse_value(value: str) -> any:
    pass

def get_indent_level(line: str) -> int:
    pass

def stringify_yaml(obj: any, indent: int = 0) -> str:
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**YAML est un superset de JSON !**

Tout JSON valide est du YAML valide. Mais pas l'inverse. YAML ajoute les commentaires, l'indentation, les ancres/aliases...

**L'indentation significative vient de Python !**

Le createur de YAML, Clark Evans, s'est inspire de Python. Ironie : parser du YAML en Python sans le module `yaml` est un cauchemar.

**Le "Norway Problem"**

En YAML, `NO` est interprete comme `false` (boolean). Donc le code pays de la Norvege `NO` devient... `False`. Des dizaines de bugs en production a cause de ca.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps** | Kubernetes manifests, Docker Compose, Ansible playbooks |
| **Backend Developer** | Config files, CI/CD pipelines |
| **Cloud Engineer** | CloudFormation, Terraform HCL (similar) |
| **Data Engineer** | dbt configs, Airflow DAGs |
| **SRE** | Prometheus alerting rules, Grafana dashboards |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
yaml_parser.py  test_yaml.py

$ python test_yaml.py
Test key-value: OK
Test nested: OK
Test lists: OK
Test types: OK
Test multiline: OK
Test comments: OK
Test stringify: OK
All tests passed!
```

---

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

**"Advanced YAML Features"**

**Ta mission bonus :**

1. **`yaml_anchors(content: str) -> dict`** : Support des ancres (`&`) et aliases (`*`)
2. **`yaml_merge(content: str) -> dict`** : Support du merge key (`<<:`)
3. **`validate_yaml(content: str) -> tuple[bool, str]`** : Validation avec messages d'erreur

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | key_value | `name: Alice` | `{'name': 'Alice'}` | 5 | Basic |
| 2 | number | `age: 30` | `{'age': 30}` | 5 | Types |
| 3 | float | `pi: 3.14` | `{'pi': 3.14}` | 5 | Types |
| 4 | bool_true | `active: true` | `{'active': True}` | 5 | Types |
| 5 | bool_yes | `enabled: yes` | `{'enabled': True}` | 5 | Types |
| 6 | null | `value: null` | `{'value': None}` | 5 | Types |
| 7 | nested | `a:\n  b: 1` | `{'a': {'b': 1}}` | 10 | Nested |
| 8 | list | `- a\n- b` | `['a', 'b']` | 8 | Lists |
| 9 | list_in_dict | `items:\n  - x\n  - y` | `{'items': ['x', 'y']}` | 10 | Complex |
| 10 | inline_list | `tags: [a, b, c]` | `{'tags': ['a', 'b', 'c']}` | 8 | Inline |
| 11 | inline_dict | `point: {x: 1, y: 2}` | `{'point': {'x': 1, 'y': 2}}` | 8 | Inline |
| 12 | comment | `# comment\na: 1` | `{'a': 1}` | 5 | Comments |
| 13 | multiline_literal | `text: \|\n  line1\n  line2` | `{'text': 'line1\nline2'}` | 8 | Multiline |
| 14 | multiline_folded | `text: >\n  line1\n  line2` | `{'text': 'line1 line2'}` | 8 | Multiline |
| 15 | stringify | `{'a': 1}` | `a: 1\n` | 5 | Output |

**Total : 100 points**

---

### 4.2 test_yaml.py

```python
import sys
sys.path.insert(0, '.')
from yaml_parser import (
    parse_yaml, yaml_to_dict, parse_value,
    get_indent_level, stringify_yaml
)

def test_key_value():
    result = parse_yaml("name: Alice")
    assert result == {'name': 'Alice'}
    print("Test key-value: OK")

def test_nested():
    yaml_content = """
person:
  name: Alice
  age: 30
"""
    result = parse_yaml(yaml_content)
    assert result['person']['name'] == 'Alice'
    assert result['person']['age'] == 30
    print("Test nested: OK")

def test_lists():
    yaml_content = """
items:
  - apple
  - banana
  - cherry
"""
    result = parse_yaml(yaml_content)
    assert result['items'] == ['apple', 'banana', 'cherry']

    # Inline list
    result2 = parse_yaml("tags: [a, b, c]")
    assert result2['tags'] == ['a', 'b', 'c']
    print("Test lists: OK")

def test_types():
    yaml_content = """
int_val: 42
float_val: 3.14
bool_true: true
bool_yes: yes
bool_false: false
null_val: null
null_tilde: ~
string_val: hello
quoted: "hello world"
"""
    result = parse_yaml(yaml_content)
    assert result['int_val'] == 42
    assert result['float_val'] == 3.14
    assert result['bool_true'] == True
    assert result['bool_yes'] == True
    assert result['bool_false'] == False
    assert result['null_val'] == None
    assert result['null_tilde'] == None
    assert result['string_val'] == 'hello'
    print("Test types: OK")

def test_multiline():
    literal = """text: |
  line1
  line2
"""
    result = parse_yaml(literal)
    assert 'line1' in result['text'] and 'line2' in result['text']

    folded = """text: >
  line1
  line2
"""
    result2 = parse_yaml(folded)
    assert 'line1' in result2['text']
    print("Test multiline: OK")

def test_comments():
    yaml_content = """
# This is a comment
name: Alice  # inline comment
"""
    result = parse_yaml(yaml_content)
    assert result['name'] == 'Alice'
    print("Test comments: OK")

def test_stringify():
    obj = {'name': 'Alice', 'age': 30}
    result = stringify_yaml(obj)
    assert 'name: Alice' in result
    assert 'age: 30' in result
    print("Test stringify: OK")

if __name__ == "__main__":
    test_key_value()
    test_nested()
    test_lists()
    test_types()
    test_multiline()
    test_comments()
    test_stringify()
    print("\nAll tests passed!")
```

---

### 4.3 Solution de reference

```python
import re

def get_indent_level(line: str) -> int:
    """Count leading spaces."""
    return len(line) - len(line.lstrip(' '))


def parse_value(value: str) -> any:
    """Convert YAML value to Python type."""
    value = value.strip()

    # Remove inline comment
    if '#' in value and not value.startswith('"') and not value.startswith("'"):
        value = value.split('#')[0].strip()

    if not value or value == '~':
        return None

    # Quoted string
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]

    # Boolean
    if value.lower() in ('true', 'yes', 'on'):
        return True
    if value.lower() in ('false', 'no', 'off'):
        return False

    # Null
    if value.lower() == 'null':
        return None

    # Integer
    try:
        return int(value)
    except ValueError:
        pass

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # Inline list
    if value.startswith('[') and value.endswith(']'):
        items = value[1:-1].split(',')
        return [parse_value(item.strip()) for item in items if item.strip()]

    # Inline dict
    if value.startswith('{') and value.endswith('}'):
        result = {}
        pairs = value[1:-1].split(',')
        for pair in pairs:
            if ':' in pair:
                k, v = pair.split(':', 1)
                result[k.strip()] = parse_value(v.strip())
        return result

    # Plain string
    return value


def parse_yaml(content: str) -> any:
    """Parse YAML content."""
    lines = content.split('\n')
    lines = [l for l in lines if l.strip() and not l.strip().startswith('#')]

    if not lines:
        return {}

    # Check if it's a list at root level
    first_line = lines[0].lstrip()
    if first_line.startswith('- '):
        return parse_list(lines, 0)[0]

    return parse_dict(lines, 0)[0]


def parse_dict(lines: list[str], base_indent: int) -> tuple[dict, int]:
    """Parse dictionary from lines."""
    result = {}
    i = 0

    while i < len(lines):
        line = lines[i]

        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('#'):
            i += 1
            continue

        indent = get_indent_level(line)

        # Less indented = end of this dict
        if indent < base_indent:
            break

        # More indented = skip (handled by nested call)
        if indent > base_indent:
            i += 1
            continue

        line_content = line.strip()

        # Key-value pair
        if ':' in line_content:
            colon_pos = line_content.find(':')
            key = line_content[:colon_pos].strip()
            value_part = line_content[colon_pos + 1:].strip()

            # Check for multiline indicator
            if value_part == '|':
                # Literal block scalar
                multiline_value, consumed = parse_multiline_literal(lines[i+1:], indent)
                result[key] = multiline_value
                i += consumed + 1
                continue
            elif value_part == '>':
                # Folded block scalar
                multiline_value, consumed = parse_multiline_folded(lines[i+1:], indent)
                result[key] = multiline_value
                i += consumed + 1
                continue
            elif value_part:
                # Inline value
                result[key] = parse_value(value_part)
            else:
                # Check next line for nested content
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    next_indent = get_indent_level(next_line)

                    if next_indent > indent:
                        if next_line.strip().startswith('- '):
                            # Nested list
                            nested, consumed = parse_list(lines[i+1:], next_indent)
                            result[key] = nested
                            i += consumed
                        else:
                            # Nested dict
                            nested, consumed = parse_dict(lines[i+1:], next_indent)
                            result[key] = nested
                            i += consumed
                    else:
                        result[key] = None
                else:
                    result[key] = None

        i += 1

    return result, i


def parse_list(lines: list[str], base_indent: int) -> tuple[list, int]:
    """Parse list from lines."""
    result = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if not line.strip():
            i += 1
            continue

        indent = get_indent_level(line)

        if indent < base_indent:
            break

        if indent > base_indent:
            i += 1
            continue

        line_content = line.strip()

        if line_content.startswith('- '):
            value = line_content[2:].strip()

            if ':' in value and not value.startswith('"'):
                # Inline dict in list item
                # Check if it's a nested structure
                if i + 1 < len(lines):
                    next_indent = get_indent_level(lines[i + 1]) if i + 1 < len(lines) else 0
                    if next_indent > indent:
                        # Has nested content - parse as dict
                        nested_lines = [line[2:].strip()] + lines[i+1:]
                        nested, consumed = parse_dict(nested_lines, 0)
                        result.append(nested)
                        i += consumed
                        continue

                # Simple key: value
                k, v = value.split(':', 1)
                result.append({k.strip(): parse_value(v.strip())})
            else:
                result.append(parse_value(value))

        i += 1

    return result, i


def parse_multiline_literal(lines: list[str], base_indent: int) -> tuple[str, int]:
    """Parse literal block scalar (|)."""
    result_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        indent = get_indent_level(line)

        if line.strip() and indent <= base_indent:
            break

        if indent > base_indent:
            result_lines.append(line[base_indent + 2:])

        i += 1

    return '\n'.join(result_lines), i


def parse_multiline_folded(lines: list[str], base_indent: int) -> tuple[str, int]:
    """Parse folded block scalar (>)."""
    result_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        indent = get_indent_level(line)

        if line.strip() and indent <= base_indent:
            break

        if indent > base_indent:
            result_lines.append(line.strip())

        i += 1

    return ' '.join(result_lines), i


def yaml_to_dict(content: str) -> dict:
    """Parse YAML to dictionary."""
    result = parse_yaml(content)
    if isinstance(result, dict):
        return result
    return {'root': result}


def stringify_yaml(obj: any, indent: int = 0) -> str:
    """Convert Python object to YAML."""
    prefix = '  ' * indent

    if obj is None:
        return 'null'
    elif isinstance(obj, bool):
        return 'true' if obj else 'false'
    elif isinstance(obj, (int, float)):
        return str(obj)
    elif isinstance(obj, str):
        if '\n' in obj or ':' in obj or '#' in obj:
            return f'"{obj}"'
        return obj
    elif isinstance(obj, list):
        if not obj:
            return '[]'
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(f'{prefix}- ')
                nested = stringify_yaml(item, indent + 1)
                lines[-1] += nested.lstrip()
            else:
                lines.append(f'{prefix}- {stringify_yaml(item)}')
        return '\n'.join(lines)
    elif isinstance(obj, dict):
        if not obj:
            return '{}'
        lines = []
        for key, value in obj.items():
            if isinstance(value, (dict, list)) and value:
                lines.append(f'{prefix}{key}:')
                lines.append(stringify_yaml(value, indent + 1))
            else:
                lines.append(f'{prefix}{key}: {stringify_yaml(value)}')
        return '\n'.join(lines)
    else:
        return str(obj)
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Indentation mal calculee**

```python
# Mutant A : Compte les tabs comme 1 espace
def get_indent_level(line: str) -> int:
    count = 0
    for char in line:
        if char == ' ' or char == '\t':  # Tab compte comme 1 !
            count += 1
        else:
            break
    return count
# Pourquoi faux : Un tab peut representer 4 ou 8 espaces
```

**Mutant B (Safety) : Norway problem**

```python
# Mutant B : Ne gere pas le cas sensible
def parse_value(value: str) -> any:
    if value == 'NO':  # Code pays Norvege
        return False  # Oups !
    # Devrait verifier: value.lower() in ('no', 'false', ...)
```

**Mutant C (Logic) : Commentaires inline ignores**

```python
# Mutant C : Ne supprime pas les commentaires inline
def parse_value(value: str) -> any:
    # "Alice  # comment" retourne "Alice  # comment"
    return value
```

**Mutant D (Resource) : Recursion infinie sur dict vide**

```python
# Mutant D : Boucle infinie
def parse_dict(lines, base_indent):
    while i < len(lines):
        if not lines[i].strip():
            continue  # Oublie i += 1 !
```

**Mutant E (Return) : Multiline mal gere**

```python
# Mutant E : | et > identiques
def parse_multiline_literal(lines, base_indent):
    return ' '.join(...)  # Devrait etre '\n'.join pour |
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Indentation significative | Structure par espaces | 5/5 |
| Types implicites | Conversion automatique | 4/5 |
| Structures imbriquees | Recursion naturelle | 4/5 |
| Block scalars | Multiline strings | 3/5 |

---

### 5.3 Visualisation ASCII

**Structure YAML et indentation :**

```
server:           <- indent 0, dict
  host: localhost <- indent 2, key-value
  port: 8080      <- indent 2, key-value
  ssl:            <- indent 2, nested dict
    enabled: true <- indent 4
    cert: /path   <- indent 4
  routes:         <- indent 2, list
    - /api        <- indent 4, list item
    - /health     <- indent 4, list item
```

**Conversion types :**

```
YAML Value     ->  Python Type
-----------        -----------
42             ->  int
3.14           ->  float
true/yes/on    ->  True
false/no/off   ->  False
null/~         ->  None
"quoted"       ->  str
unquoted       ->  str
[a, b]         ->  list
{x: 1}         ->  dict
```

---

### 5.8 Mnemotechniques (MEME obligatoire)

#### MEME : "YAML Indentation Hell"

```
DevOps at 3am:
  problem: indentation
  spaces: 2
  tabs: NEVER
  sanity: null
  coffee:
    - cup 1
    - cup 2
    - cup 3
    - please help

# The real error was on line 47
# But YAML says line 312
# Classic YAML
```

**Les 3 commandements du YAML :**
1. Tu utiliseras des espaces, JAMAIS des tabs
2. Tu compteras tes espaces (2, pas 4)
3. Tu n'oublieras point que `NO` est un boolean

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.3.0-d |
| **Nom** | yaml_parser |
| **Difficulte** | 4/10 |
| **Duree** | 40 min |
| **XP Base** | 60 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Indentation, types, recursion |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "C.3.0-d-yaml_parser",
    "metadata": {
      "exercise_id": "C.3.0-d",
      "exercise_name": "yaml_parser",
      "module": "C.3.0",
      "concept": "d",
      "concept_name": "YAML Processing",
      "type": "code",
      "tier": 1,
      "phase": 0,
      "difficulty": 4,
      "language": "python",
      "language_version": "3.14"
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2 — L'excellence pedagogique ne se negocie pas*
