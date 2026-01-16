# Exercice C.3.0-b : json_toolkit

**Module :**
C.3.0 — Data Formats: JSON Manipulation

**Concept :**
b — JSON types, objects, arrays, nesting, validation, pretty print

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Dictionnaires et listes Python
- Recursivite basique
- Manipulation de strings

**Domaines :**
Struct, Encodage, FS

**Duree estimee :**
35 min

**XP Base :**
55

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
`json_toolkit.py`

**Fonctions autorisees :**
- Toutes les fonctions Python natives (sans imports)
- `str`, `int`, `float`, `bool`, `list`, `dict`
- Methodes de string

**Fonctions interdites :**
- Module `json` (tu dois implementer toi-meme!)
- Module `ast`
- `eval`, `exec`

---

### 1.2 Consigne

#### Section Culture : "The API Response Saga"

**"It's a UNIX system! I know this!" — mais c'est du JSON**

Tu te souviens de cette scene de Jurassic Park ou la gamine hacke le systeme de securite du parc? Aujourd'hui, les vrais dinosaures sont les APIs qui retournent du JSON mal forme. Et toi, tu vas etre le hacker qui sait VRAIMENT parser ce format.

JSON (JavaScript Object Notation) est PARTOUT : APIs REST, fichiers de config, NoSQL databases... C'est le langage universel du web moderne. Mais derriere sa simplicite apparente se cachent des pieges : types primitifs, echappement, Unicode...

*"Life finds a way... to break your JSON parser."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un parser et serializer JSON complet :

1. **`parse_json(content: str) -> any`** : Parse une chaine JSON en objet Python
2. **`stringify_json(obj: any, indent: int = 0) -> str`** : Convertit un objet Python en JSON
3. **`validate_json(content: str) -> tuple[bool, str]`** : Valide la syntaxe JSON
4. **`get_nested(obj: any, path: str) -> any`** : Acces aux valeurs imbriquees par chemin
5. **`merge_json(obj1: dict, obj2: dict) -> dict`** : Fusion profonde de deux objets

**Entree :**
```python
def parse_json(content: str) -> any:
    """
    Parse JSON string into Python object.

    Supports:
    - Objects: {"key": value}
    - Arrays: [item1, item2]
    - Strings: "text" (with escape sequences)
    - Numbers: 42, 3.14, -5, 1e10
    - Booleans: true, false
    - Null: null
    """
    pass

def stringify_json(obj: any, indent: int = 0) -> str:
    """
    Convert Python object to JSON string.

    Args:
        obj: Python object (dict, list, str, int, float, bool, None)
        indent: Indentation spaces for pretty print (0 = compact)
    """
    pass

def validate_json(content: str) -> tuple[bool, str]:
    """
    Validate JSON syntax.

    Returns:
        (True, "") if valid
        (False, "Error message") if invalid
    """
    pass

def get_nested(obj: any, path: str) -> any:
    """
    Get nested value by dot-notation path.

    Example: get_nested({"a": {"b": 1}}, "a.b") -> 1
    """
    pass

def merge_json(obj1: dict, obj2: dict) -> dict:
    """
    Deep merge two JSON objects.
    obj2 values override obj1 values.
    """
    pass
```

**Sortie :**
- `parse_json` retourne l'objet Python correspondant
- `stringify_json` retourne une chaine JSON valide
- `validate_json` retourne un tuple (valid, error_message)
- `get_nested` retourne la valeur ou None si chemin invalide
- `merge_json` retourne un nouveau dictionnaire fusionne

**Contraintes :**
- Gerer tous les types JSON : object, array, string, number, boolean, null
- Gerer les sequences d'echappement dans les strings : `\"`, `\\`, `\/`, `\n`, `\t`, `\r`, `\b`, `\f`, `\uXXXX`
- Les nombres peuvent etre entiers, decimaux, ou en notation scientifique
- Gerer les espaces blancs (ignorer entre tokens)
- Detecter les erreurs de syntaxe avec messages clairs

**Exemples :**

| Input | Fonction | Output |
|-------|----------|--------|
| `'{"name": "Alice", "age": 30}'` | `parse_json` | `{'name': 'Alice', 'age': 30}` |
| `'[1, 2, 3]'` | `parse_json` | `[1, 2, 3]` |
| `'"Hello\\nWorld"'` | `parse_json` | `'Hello\nWorld'` |
| `{'a': 1}` | `stringify_json` | `'{"a": 1}'` |
| `{'a': 1}, indent=2` | `stringify_json` | `'{\n  "a": 1\n}'` |
| `'{"a": }'` | `validate_json` | `(False, "Unexpected token at position 6")` |

---

### 1.3 Prototype

```python
def parse_json(content: str) -> any:
    pass

def stringify_json(obj: any, indent: int = 0) -> str:
    pass

def validate_json(content: str) -> tuple[bool, str]:
    pass

def get_nested(obj: any, path: str) -> any:
    pass

def merge_json(obj1: dict, obj2: dict) -> dict:
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**JSON est ne d'une frustration avec XML !**

Douglas Crockford a cree JSON en 2001 parce qu'il en avait marre de la verbosity de XML. Sa devise : "The less we have to agree upon, the easier it is to agree."

**JSON a gagne la guerre des formats**

Dans les annees 2000, XML etait roi. Aujourd'hui, JSON represente 90%+ des APIs REST. Meme Microsoft et Oracle ont capitule.

**Les trailing commas sont illegales en JSON !**

`{"a": 1,}` est INVALIDE en JSON standard (mais valide en JSON5 et JavaScript). Des milliers de bugs sont nes de cette decision.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Backend Developer** | APIs REST, serialization de donnees |
| **Frontend Developer** | Fetch API, state management |
| **DevOps** | Fichiers de config (package.json, tsconfig.json) |
| **Data Engineer** | NoSQL (MongoDB, CouchDB), Elasticsearch |
| **Mobile Developer** | Communication client-serveur |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
json_toolkit.py  test_json.py

$ python test_json.py
Test parse_json object: OK
Test parse_json array: OK
Test parse_json primitives: OK
Test parse_json escaped: OK
Test stringify_json compact: OK
Test stringify_json pretty: OK
Test validate_json valid: OK
Test validate_json invalid: OK
Test get_nested: OK
Test merge_json: OK
All tests passed!
```

---

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

**Time Complexity attendue :**
O(n)

**Space Complexity attendue :**
O(n)

**Domaines Bonus :**
`Struct`, `Algo`

#### 3.1.1 Consigne Bonus

**"JSON Schema Validator"**

Comme le Dr Malcolm qui avertit des dangers du parc, tu vas creer un systeme de validation qui empeche les donnees chaotiques d'entrer.

**Ta mission bonus :**

1. **`json_diff(obj1: any, obj2: any) -> dict`** : Compare deux objets JSON et retourne les differences
2. **`json_query(obj: any, query: str) -> list`** : Mini JSONPath (supporte `$`, `.key`, `[n]`, `[*]`)
3. **`flatten_json(obj: dict, sep: str = '.') -> dict`** : Aplatit un objet imbrique

**Contraintes :**
```
Diff doit retourner:
- "added": cles presentes dans obj2 mais pas obj1
- "removed": cles presentes dans obj1 mais pas obj2
- "changed": cles avec valeurs differentes
```

**Exemples :**

| Input | Fonction | Output |
|-------|----------|--------|
| `{"a":1}`, `{"a":2,"b":3}` | `json_diff` | `{"changed":{"a":[1,2]},"added":{"b":3}}` |
| `{"a":{"b":[1,2,3]}}`, `"$.a.b[0]"` | `json_query` | `[1]` |
| `{"a":{"b":1},"c":2}` | `flatten_json` | `{"a.b":1,"c":2}` |

#### 3.1.2 Prototype Bonus

```python
def json_diff(obj1: any, obj2: any) -> dict:
    pass

def json_query(obj: any, query: str) -> list:
    pass

def flatten_json(obj: dict, sep: str = '.') -> dict:
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | parse_empty_object | `'{}'` | `{}` | 5 | Basic |
| 2 | parse_simple_object | `'{"a":1}'` | `{'a':1}` | 5 | Basic |
| 3 | parse_nested_object | `'{"a":{"b":1}}'` | `{'a':{'b':1}}` | 8 | Nested |
| 4 | parse_array | `'[1,2,3]'` | `[1,2,3]` | 5 | Array |
| 5 | parse_mixed | `'{"a":[1,2]}'` | `{'a':[1,2]}` | 8 | Mixed |
| 6 | parse_string_escape | `'"a\\nb"'` | `'a\nb'` | 8 | Escape |
| 7 | parse_unicode | `'"\\u0041"'` | `'A'` | 8 | Unicode |
| 8 | parse_numbers | `'[42,3.14,-5,1e10]'` | `[42,3.14,-5,1e10]` | 8 | Numbers |
| 9 | parse_booleans | `'[true,false,null]'` | `[True,False,None]` | 5 | Primitives |
| 10 | stringify_compact | `{'a':1}` | `'{"a": 1}'` | 8 | Stringify |
| 11 | stringify_pretty | `{'a':1}, indent=2` | formatted | 8 | Pretty |
| 12 | validate_valid | `'{"a":1}'` | `(True, "")` | 5 | Validate |
| 13 | validate_invalid | `'{"a":}'` | `(False, ...)` | 8 | Validate |
| 14 | get_nested | `{"a":{"b":1}}, "a.b"` | `1` | 6 | Access |
| 15 | merge_json | `{"a":1}, {"b":2}` | `{"a":1,"b":2}` | 5 | Merge |

**Total : 100 points**

---

### 4.2 test_json.py

```python
import sys
sys.path.insert(0, '.')
from json_toolkit import (
    parse_json, stringify_json, validate_json,
    get_nested, merge_json
)

def test_parse_json_object():
    result = parse_json('{"name": "Alice", "age": 30}')
    assert result == {'name': 'Alice', 'age': 30}
    print("Test parse_json object: OK")

def test_parse_json_array():
    result = parse_json('[1, 2, 3, "hello", true, null]')
    assert result == [1, 2, 3, "hello", True, None]
    print("Test parse_json array: OK")

def test_parse_json_primitives():
    assert parse_json('42') == 42
    assert parse_json('3.14') == 3.14
    assert parse_json('-5') == -5
    assert parse_json('true') == True
    assert parse_json('false') == False
    assert parse_json('null') == None
    assert parse_json('"hello"') == "hello"
    print("Test parse_json primitives: OK")

def test_parse_json_escaped():
    assert parse_json('"hello\\nworld"') == "hello\nworld"
    assert parse_json('"tab\\there"') == "tab\there"
    assert parse_json('"quote\\"here"') == 'quote"here'
    assert parse_json('"\\u0041"') == 'A'
    print("Test parse_json escaped: OK")

def test_stringify_json_compact():
    result = stringify_json({'a': 1, 'b': 'hello'})
    # Order may vary, so check both possibilities
    assert result in ['{"a": 1, "b": "hello"}', '{"b": "hello", "a": 1}']
    print("Test stringify_json compact: OK")

def test_stringify_json_pretty():
    result = stringify_json({'a': 1}, indent=2)
    assert '{\n' in result and '"a": 1' in result
    print("Test stringify_json pretty: OK")

def test_validate_json_valid():
    valid, msg = validate_json('{"a": 1, "b": [1, 2, 3]}')
    assert valid == True and msg == ""
    print("Test validate_json valid: OK")

def test_validate_json_invalid():
    valid, msg = validate_json('{"a": }')
    assert valid == False and len(msg) > 0
    print("Test validate_json invalid: OK")

def test_get_nested():
    obj = {"a": {"b": {"c": 42}}, "d": [1, 2, 3]}
    assert get_nested(obj, "a.b.c") == 42
    assert get_nested(obj, "a.b") == {"c": 42}
    assert get_nested(obj, "x.y") == None
    print("Test get_nested: OK")

def test_merge_json():
    obj1 = {"a": 1, "b": {"x": 1}}
    obj2 = {"b": {"y": 2}, "c": 3}
    result = merge_json(obj1, obj2)
    assert result == {"a": 1, "b": {"x": 1, "y": 2}, "c": 3}
    print("Test merge_json: OK")

if __name__ == "__main__":
    test_parse_json_object()
    test_parse_json_array()
    test_parse_json_primitives()
    test_parse_json_escaped()
    test_stringify_json_compact()
    test_stringify_json_pretty()
    test_validate_json_valid()
    test_validate_json_invalid()
    test_get_nested()
    test_merge_json()
    print("\nAll tests passed!")
```

---

### 4.3 Solution de reference

```python
class JSONParser:
    def __init__(self, content: str):
        self.content = content
        self.pos = 0

    def parse(self):
        self.skip_whitespace()
        value = self.parse_value()
        self.skip_whitespace()
        if self.pos < len(self.content):
            raise ValueError(f"Unexpected token at position {self.pos}")
        return value

    def skip_whitespace(self):
        while self.pos < len(self.content) and self.content[self.pos] in ' \t\n\r':
            self.pos += 1

    def parse_value(self):
        self.skip_whitespace()
        if self.pos >= len(self.content):
            raise ValueError("Unexpected end of input")

        char = self.content[self.pos]

        if char == '"':
            return self.parse_string()
        elif char == '{':
            return self.parse_object()
        elif char == '[':
            return self.parse_array()
        elif char == 't':
            return self.parse_literal('true', True)
        elif char == 'f':
            return self.parse_literal('false', False)
        elif char == 'n':
            return self.parse_literal('null', None)
        elif char == '-' or char.isdigit():
            return self.parse_number()
        else:
            raise ValueError(f"Unexpected character '{char}' at position {self.pos}")

    def parse_string(self):
        self.pos += 1  # Skip opening quote
        result = []

        while self.pos < len(self.content):
            char = self.content[self.pos]

            if char == '"':
                self.pos += 1
                return ''.join(result)
            elif char == '\\':
                self.pos += 1
                if self.pos >= len(self.content):
                    raise ValueError("Unexpected end of string")
                escape = self.content[self.pos]
                if escape == 'n':
                    result.append('\n')
                elif escape == 't':
                    result.append('\t')
                elif escape == 'r':
                    result.append('\r')
                elif escape == 'b':
                    result.append('\b')
                elif escape == 'f':
                    result.append('\f')
                elif escape == '"':
                    result.append('"')
                elif escape == '\\':
                    result.append('\\')
                elif escape == '/':
                    result.append('/')
                elif escape == 'u':
                    hex_str = self.content[self.pos+1:self.pos+5]
                    result.append(chr(int(hex_str, 16)))
                    self.pos += 4
                else:
                    raise ValueError(f"Invalid escape sequence \\{escape}")
            else:
                result.append(char)
            self.pos += 1

        raise ValueError("Unterminated string")

    def parse_object(self):
        self.pos += 1  # Skip {
        result = {}

        self.skip_whitespace()
        if self.pos < len(self.content) and self.content[self.pos] == '}':
            self.pos += 1
            return result

        while True:
            self.skip_whitespace()
            if self.content[self.pos] != '"':
                raise ValueError(f"Expected string key at position {self.pos}")
            key = self.parse_string()

            self.skip_whitespace()
            if self.content[self.pos] != ':':
                raise ValueError(f"Expected ':' at position {self.pos}")
            self.pos += 1

            value = self.parse_value()
            result[key] = value

            self.skip_whitespace()
            if self.content[self.pos] == '}':
                self.pos += 1
                return result
            elif self.content[self.pos] == ',':
                self.pos += 1
            else:
                raise ValueError(f"Expected ',' or '}}' at position {self.pos}")

    def parse_array(self):
        self.pos += 1  # Skip [
        result = []

        self.skip_whitespace()
        if self.pos < len(self.content) and self.content[self.pos] == ']':
            self.pos += 1
            return result

        while True:
            value = self.parse_value()
            result.append(value)

            self.skip_whitespace()
            if self.content[self.pos] == ']':
                self.pos += 1
                return result
            elif self.content[self.pos] == ',':
                self.pos += 1
            else:
                raise ValueError(f"Expected ',' or ']' at position {self.pos}")

    def parse_number(self):
        start = self.pos
        if self.content[self.pos] == '-':
            self.pos += 1

        while self.pos < len(self.content) and self.content[self.pos].isdigit():
            self.pos += 1

        if self.pos < len(self.content) and self.content[self.pos] == '.':
            self.pos += 1
            while self.pos < len(self.content) and self.content[self.pos].isdigit():
                self.pos += 1

        if self.pos < len(self.content) and self.content[self.pos] in 'eE':
            self.pos += 1
            if self.pos < len(self.content) and self.content[self.pos] in '+-':
                self.pos += 1
            while self.pos < len(self.content) and self.content[self.pos].isdigit():
                self.pos += 1

        num_str = self.content[start:self.pos]
        if '.' in num_str or 'e' in num_str or 'E' in num_str:
            return float(num_str)
        return int(num_str)

    def parse_literal(self, literal: str, value):
        if self.content[self.pos:self.pos+len(literal)] == literal:
            self.pos += len(literal)
            return value
        raise ValueError(f"Expected '{literal}' at position {self.pos}")


def parse_json(content: str) -> any:
    parser = JSONParser(content.strip())
    return parser.parse()


def stringify_json(obj: any, indent: int = 0) -> str:
    def to_json(value, level=0):
        if value is None:
            return "null"
        elif value is True:
            return "true"
        elif value is False:
            return "false"
        elif isinstance(value, str):
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            escaped = escaped.replace('\n', '\\n').replace('\t', '\\t')
            escaped = escaped.replace('\r', '\\r')
            return f'"{escaped}"'
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, list):
            if not value:
                return "[]"
            if indent == 0:
                items = ", ".join(to_json(v, level) for v in value)
                return f"[{items}]"
            else:
                items = []
                for v in value:
                    items.append(" " * ((level + 1) * indent) + to_json(v, level + 1))
                return "[\n" + ",\n".join(items) + "\n" + " " * (level * indent) + "]"
        elif isinstance(value, dict):
            if not value:
                return "{}"
            if indent == 0:
                pairs = ", ".join(f'"{k}": {to_json(v, level)}' for k, v in value.items())
                return "{" + pairs + "}"
            else:
                pairs = []
                for k, v in value.items():
                    pairs.append(" " * ((level + 1) * indent) + f'"{k}": {to_json(v, level + 1)}')
                return "{\n" + ",\n".join(pairs) + "\n" + " " * (level * indent) + "}"
        else:
            raise ValueError(f"Cannot serialize type {type(value)}")

    return to_json(obj)


def validate_json(content: str) -> tuple[bool, str]:
    try:
        parse_json(content)
        return (True, "")
    except ValueError as e:
        return (False, str(e))
    except Exception as e:
        return (False, f"Parse error: {str(e)}")


def get_nested(obj: any, path: str) -> any:
    if not path:
        return obj

    keys = path.split('.')
    current = obj

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                index = int(key)
                current = current[index]
            except (ValueError, IndexError):
                return None
        else:
            return None

    return current


def merge_json(obj1: dict, obj2: dict) -> dict:
    result = dict(obj1)

    for key, value in obj2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_json(result[key], value)
        else:
            result[key] = value

    return result
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Parser recursif simple sans classe**

```python
def parse_json(content: str) -> any:
    pos = [0]  # Use list for mutability in nested functions

    def parse_value():
        skip_ws()
        # ... similar logic without class
        pass

    return parse_value()
```

**Alternative 2 : Stringify avec f-strings et match**

```python
def stringify_json(obj: any, indent: int = 0) -> str:
    match obj:
        case None:
            return "null"
        case True:
            return "true"
        case False:
            return "false"
        case str():
            return f'"{escape_string(obj)}"'
        # ... etc
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Utilisation du module json**

```python
# REFUSE : Module json interdit !
import json

def parse_json(content: str) -> any:
    return json.loads(content)
```
**Pourquoi refuse :** L'exercice demande d'implementer le parsing manuellement.

**Refus 2 : Utilisation de eval**

```python
# REFUSE : eval est interdit et dangereux !
def parse_json(content: str) -> any:
    # Replace JSON booleans/null with Python equivalents
    content = content.replace('true', 'True').replace('false', 'False').replace('null', 'None')
    return eval(content)  # DANGER !
```
**Pourquoi refuse :** Faille de securite majeure, permet l'execution de code arbitraire.

**Refus 3 : Ne gere pas les escape sequences**

```python
# REFUSE : Ignore les escapes !
def parse_string(self):
    end = self.content.find('"', self.pos + 1)
    return self.content[self.pos+1:end]  # \n reste literal !
```
**Pourquoi refuse :** `"a\nb"` doit donner `a` + newline + `b`, pas la chaine literale.

---

### 4.6 Solution bonus de reference

```python
def json_diff(obj1: any, obj2: any) -> dict:
    result = {"added": {}, "removed": {}, "changed": {}}

    if isinstance(obj1, dict) and isinstance(obj2, dict):
        all_keys = set(obj1.keys()) | set(obj2.keys())
        for key in all_keys:
            if key not in obj1:
                result["added"][key] = obj2[key]
            elif key not in obj2:
                result["removed"][key] = obj1[key]
            elif obj1[key] != obj2[key]:
                if isinstance(obj1[key], dict) and isinstance(obj2[key], dict):
                    nested = json_diff(obj1[key], obj2[key])
                    if any(nested.values()):
                        result["changed"][key] = nested
                else:
                    result["changed"][key] = [obj1[key], obj2[key]]

    return {k: v for k, v in result.items() if v}


def json_query(obj: any, query: str) -> list:
    if query == "$":
        return [obj]

    parts = query.replace("$.", "").replace("$", "").split(".")
    current = [obj]

    for part in parts:
        if not part:
            continue

        new_current = []
        for item in current:
            if "[" in part:
                key = part[:part.index("[")]
                index_str = part[part.index("[")+1:part.index("]")]

                if key:
                    if isinstance(item, dict) and key in item:
                        item = item[key]
                    else:
                        continue

                if index_str == "*":
                    if isinstance(item, list):
                        new_current.extend(item)
                else:
                    idx = int(index_str)
                    if isinstance(item, list) and 0 <= idx < len(item):
                        new_current.append(item[idx])
            else:
                if isinstance(item, dict) and part in item:
                    new_current.append(item[part])

        current = new_current

    return current


def flatten_json(obj: dict, sep: str = '.', parent_key: str = '') -> dict:
    items = {}

    for key, value in obj.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key

        if isinstance(value, dict):
            items.update(flatten_json(value, sep, new_key))
        else:
            items[new_key] = value

    return items
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Off-by-one dans le parsing de string**

```python
# Mutant A (Boundary) : Oublie le dernier caractere
def parse_string(self):
    self.pos += 1
    result = []
    while self.pos < len(self.content) - 1:  # -1 de trop !
        char = self.content[self.pos]
        if char == '"':
            break
        result.append(char)
        self.pos += 1
    return ''.join(result)

# Pourquoi c'est faux : "abc" retourne "ab" au lieu de "abc"
```

**Mutant B (Safety) : Pas de validation des escape sequences**

```python
# Mutant B (Safety) : Accepte n'importe quoi apres backslash
def parse_string(self):
    # ...
    if char == '\\':
        self.pos += 1
        result.append(self.content[self.pos])  # Ajoute sans valider !
    # ...

# Pourquoi c'est faux : \q devrait lever une erreur, pas ajouter 'q'
```

**Mutant C (Resource) : Recursion infinie sur objets vides**

```python
# Mutant C (Resource) : Boucle infinie
def parse_object(self):
    self.pos += 1
    result = {}
    while True:
        self.skip_whitespace()
        # Oublie de verifier '}' vide !
        key = self.parse_string()  # Erreur si objet vide
        # ...

# Pourquoi c'est faux : {} cause une erreur au lieu de retourner {}
```

**Mutant D (Logic) : Confusion true/True**

```python
# Mutant D (Logic) : Mauvaise conversion
def parse_value(self):
    if char == 't':
        return self.parse_literal('true', 'True')  # String au lieu de bool !
    # ...

# Pourquoi c'est faux : true doit devenir True (bool), pas "True" (str)
```

**Mutant E (Return) : Stringify ne gere pas None**

```python
# Mutant E (Return) : Oublie null
def stringify_json(obj: any, indent: int = 0) -> str:
    if obj is None:
        return "None"  # Devrait etre "null" !
    # ...

# Pourquoi c'est faux : JSON utilise null, pas None
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Parsing recursif | Descente recursive pour structures imbriquees | 5/5 |
| Types JSON | 6 types primitifs et composes | 5/5 |
| Echappement | Sequences speciales dans les strings | 4/5 |
| Validation | Detecter les erreurs de syntaxe | 4/5 |
| Serialisation | Conversion bidirectionnelle | 4/5 |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION parse_json QUI RETOURNE UN OBJET PYTHON ET PREND content COMME CHAINE
DEBUT FONCTION
    DECLARER parser COMME NOUVEAU JSONParser AVEC content
    RETOURNER parser.parse()
FIN FONCTION

METHODE parse_value DE LA CLASSE JSONParser
DEBUT METHODE
    APPELER skip_whitespace
    DECLARER char COMME LE CARACTERE A LA POSITION pos

    SI char EST EGAL A GUILLEMET ALORS
        RETOURNER parse_string()
    SINON SI char EST EGAL A ACCOLADE OUVRANTE ALORS
        RETOURNER parse_object()
    SINON SI char EST EGAL A CROCHET OUVRANT ALORS
        RETOURNER parse_array()
    SINON SI char COMMENCE PAR 't' ALORS
        RETOURNER parse_literal("true", True)
    SINON SI char COMMENCE PAR 'f' ALORS
        RETOURNER parse_literal("false", False)
    SINON SI char COMMENCE PAR 'n' ALORS
        RETOURNER parse_literal("null", None)
    SINON SI char EST CHIFFRE OU MOINS ALORS
        RETOURNER parse_number()
    SINON
        LEVER UNE ERREUR "Caractere inattendu"
    FIN SI
FIN METHODE
```

---

### 5.2.2.1 Logic Flow (Structured English)

```
ALGORITHM: JSON Recursive Descent Parser
---

1. PARSE_VALUE():
   |-- SKIP whitespace
   |-- CHECK first character:
   |     |-- '"' -> PARSE_STRING()
   |     |-- '{' -> PARSE_OBJECT()
   |     |-- '[' -> PARSE_ARRAY()
   |     |-- 't' -> PARSE_LITERAL("true", True)
   |     |-- 'f' -> PARSE_LITERAL("false", False)
   |     |-- 'n' -> PARSE_LITERAL("null", None)
   |     |-- digit/'-' -> PARSE_NUMBER()
   |     |-- else -> ERROR

2. PARSE_OBJECT():
   |-- CONSUME '{'
   |-- IF next is '}' -> RETURN {}
   |-- LOOP:
   |     |-- key = PARSE_STRING()
   |     |-- EXPECT ':'
   |     |-- value = PARSE_VALUE()
   |     |-- ADD key:value to result
   |     |-- IF next is '}' -> BREAK
   |     |-- EXPECT ','

3. PARSE_ARRAY():
   |-- CONSUME '['
   |-- IF next is ']' -> RETURN []
   |-- LOOP:
   |     |-- value = PARSE_VALUE()
   |     |-- ADD value to result
   |     |-- IF next is ']' -> BREAK
   |     |-- EXPECT ','
```

---

### 5.2.3.1 Diagramme Mermaid

```mermaid
flowchart TD
    A[parse_value] --> B{First char?}
    B -->|"| C[parse_string]
    B -->|{| D[parse_object]
    B -->|[| E[parse_array]
    B -->|t| F[true]
    B -->|f| G[false]
    B -->|n| H[null]
    B -->|digit/-| I[parse_number]
    B -->|other| J[ERROR]

    D --> K[Loop: key-value pairs]
    K --> C
    K --> A
    K -->|}| L[Return object]

    E --> M[Loop: values]
    M --> A
    M -->|]| N[Return array]
```

---

### 5.3 Visualisation ASCII

**Structure JSON et son arbre de parsing :**

```
JSON:  {"user": {"name": "Alice", "age": 30}, "active": true}

Arbre de parsing:

                        OBJECT
                       /      \
                  "user"      "active"
                    |            |
                 OBJECT        true
                /      \
           "name"     "age"
              |          |
           "Alice"      30
```

**Sequence d'echappement :**

```
Input:  "Hello\nWorld\t\"JSON\""
         |    ||    ||  ||  ||
         v    vv    vv  vv  vv
Output: Hello
        World   "JSON"

Mapping:
  \n -> newline
  \t -> tab
  \" -> literal quote
  \\ -> literal backslash
  \uXXXX -> Unicode character
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Confusion entre les types boolean

```python
# FAUX : Python True != JSON true
if value == "true":
    return "true"  # Devrait etre: return True

# En JSON: true, false, null
# En Python: True, False, None
```

#### Piege 2 : Nombres avec exposant

```python
# FAUX : Oublie la notation scientifique
def parse_number(self):
    while self.content[self.pos].isdigit():
        self.pos += 1
    # 1e10 n'est pas parse correctement !
```

#### Piege 3 : Unicode escapes

```python
# FAUX : \uXXXX mal gere
if escape == 'u':
    # Doit lire 4 caracteres hex et convertir
    hex_str = self.content[self.pos+1:self.pos+5]
    return chr(int(hex_str, 16))
```

---

### 5.5 Cours Complet

#### 5.5.1 Les 6 types JSON

| Type | JSON | Python | Exemple |
|------|------|--------|---------|
| Object | `{...}` | `dict` | `{"key": "value"}` |
| Array | `[...]` | `list` | `[1, 2, 3]` |
| String | `"..."` | `str` | `"hello"` |
| Number | `42`, `3.14` | `int`, `float` | `42`, `3.14` |
| Boolean | `true`, `false` | `True`, `False` | `true` |
| Null | `null` | `None` | `null` |

#### 5.5.2 Grammaire JSON (BNF simplifiee)

```
value     := object | array | string | number | "true" | "false" | "null"
object    := "{" [ pair ("," pair)* ] "}"
pair      := string ":" value
array     := "[" [ value ("," value)* ] "]"
string    := '"' character* '"'
character := unescaped | escaped
escaped   := '\' ('"' | '\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u' HEX4)
number    := integer [ fraction ] [ exponent ]
```

#### 5.5.3 Parsing par descente recursive

Le parsing JSON est un exemple parfait de descente recursive :
- Chaque type a sa propre fonction de parsing
- Les types composes (object, array) appellent recursivement `parse_value`
- La pile d'appels reflete la structure imbriquee du JSON

---

### 5.8 Mnemotechniques (MEME obligatoire)

#### MEME : "Life finds a way... to break your parser"

```
Dr. Malcolm: "You're parsing JSON without tests? That's chaos."
Dr. Grant: "It worked in development!"
Dr. Malcolm: "Yeah, but production... finds a way to break it."

Regles du Dr. Malcolm pour JSON:
1. Nature always wins -> Edge cases always exist
2. Chaos theory -> Malformed input will arrive
3. "Life finds a way" -> Users will find bugs
```

**Les 6 commandements du JSON :**
- Tu ne confondras point `true` et `"true"`
- Tu echapperas tes guillemets
- Tu n'utiliseras point de trailing commas
- Tu valideras avant de parser
- Tu geras les strings Unicode
- Tu testeras les edge cases

---

### 5.9 Applications pratiques

| Application | Utilisation |
|-------------|-------------|
| **REST APIs** | Request/Response bodies |
| **Config files** | package.json, tsconfig.json |
| **NoSQL DBs** | MongoDB, CouchDB |
| **LocalStorage** | Browser state |
| **Logging** | Structured logs |

---

## SECTION 6 : PIEGES RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | true vs True | Mauvais type | Mapper correctement |
| 2 | Escape sequences | Strings corrompues | Parser \n, \t, etc. |
| 3 | Unicode \uXXXX | Caracteres manquants | Decoder hex |
| 4 | Trailing comma | Erreur inattendue | Rejeter proprement |
| 5 | Nombres scientifiques | Parse incomplet | Gerer e/E |

---

## SECTION 7 : QCM

### Question 1 (2 points)
Quel est le resultat de `parse_json('true')` ?

- A) `"true"`
- B) `True`
- C) `1`
- D) Erreur

**Reponse : B** — `true` JSON devient `True` Python (boolean).

### Question 2 (3 points)
Que represente `\u0041` en JSON ?

- A) Le caractere 'A'
- B) Le nombre 41
- C) Une erreur
- D) La chaine "u0041"

**Reponse : A** — `\u0041` est le code Unicode de 'A' (65 en decimal).

### Question 3 (3 points)
Lequel est du JSON invalide ?

- A) `{"a": 1,}`
- B) `{"a": 1}`
- C) `[1, 2, 3]`
- D) `"hello"`

**Reponse : A** — La trailing comma est illegale en JSON.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.3.0-b |
| **Nom** | json_toolkit |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 55 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Parsing recursif, types, echappement |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "C.3.0-b-json_toolkit",
    "generated_at": "2026-01-16 12:00:00",

    "metadata": {
      "exercise_id": "C.3.0-b",
      "exercise_name": "json_toolkit",
      "module": "C.3.0",
      "module_name": "Data Formats",
      "concept": "b",
      "concept_name": "JSON Manipulation",
      "type": "code",
      "tier": 1,
      "phase": 0,
      "difficulty": 3,
      "language": "python",
      "language_version": "3.14",
      "duration_minutes": 35,
      "xp_base": 55
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2 — L'excellence pedagogique ne se negocie pas*
