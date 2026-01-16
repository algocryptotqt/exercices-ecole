# Exercice 0.3.1-a : hello_repl

**Module :**
0.3.1 — Introduction a Python et le REPL

**Concept :**
a-h — Interpreteur Python, REPL, Hello World, Scripts, Commentaires, Docstrings, help(), exit()

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
cours_code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
Aucun

**Domaines :**
Encodage, FS

**Duree estimee :**
30 min

**XP Base :**
100

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `hello.py`

**Fonctions autorisees :**
- `print()`
- `help()`

**Fonctions interdites :**
- Aucune restriction pour cet exercice d'introduction

### 1.2 Consigne

**The Matrix: First Contact avec Python**

Tu te reveilles. L'ecran vert clignote devant toi. Une voix resonne dans ta tete: "Free your mind". Mais avant de pouvoir courber des cuilleres avec ton esprit, tu dois d'abord apprendre a communiquer avec la Machine.

Le REPL (Read-Eval-Print Loop) est ton premier point de contact avec Python. C'est l'Oracle de la programmation: tu poses une question, il te repond immediatement. Aujourd'hui, tu vas ecrire ton premier message a la Matrix.

**Ta mission :**

Creer un fichier `hello.py` qui demontre ta maitrise des fondamentaux Python:

**Taches :**
1. Ajouter un commentaire en-tete expliquant le script (avec #)
2. Ajouter une docstring de module (triple guillemets)
3. Implementer `greet(name: str) -> str` qui retourne "Hello, {name}!"
4. Implementer `show_help()` qui affiche l'aide de greet via help()
5. Dans le bloc `if __name__ == "__main__"`:
   - Afficher "Hello, World!"
   - Appeler et afficher greet("Python 3.14")
   - Appeler show_help()

**Entree :**
- `name` : chaine de caracteres representant un nom

**Sortie :**
- `greet()` retourne une chaine formatee "Hello, {name}!"
- `show_help()` ne retourne rien (affiche l'aide)

**Contraintes :**
- Le fichier DOIT avoir une docstring de module
- La fonction greet DOIT avoir une docstring
- Le bloc `if __name__ == "__main__"` est obligatoire
- Utiliser uniquement les fonctions autorisees

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `greet("Neo")` | `"Hello, Neo!"` | Formatage simple avec le nom |
| `greet("Python 3.14")` | `"Hello, Python 3.14!"` | Fonctionne avec n'importe quelle chaine |
| `greet("")` | `"Hello, !"` | Cas chaine vide (accepte) |

### 1.3 Prototype

```python
def greet(name: str) -> str:
    """
    Retourne un message de salutation personnalise.

    Args:
        name: Le nom de la personne a saluer.

    Returns:
        Une chaine formatee "Hello, {name}!"
    """
    ...

def show_help() -> None:
    """
    Affiche l'aide de la fonction greet.
    """
    ...
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Pourquoi Python s'appelle Python ?

Contrairement a ce que beaucoup pensent, Python ne tire pas son nom du serpent mais de la troupe comique britannique **Monty Python**. Guido van Rossum, le createur de Python, etait fan de leur emission "Monty Python's Flying Circus" et cherchait un nom court, unique et un peu mysterieux.

### 2.2 Le REPL : Ton laboratoire instantane

Le REPL existe depuis les premiers langages (Lisp, 1958). C'est l'un des outils les plus puissants pour apprendre: tu peux tester n'importe quelle idee en quelques secondes sans creer de fichier.

```
>>> 2 + 2
4
>>> "Python" * 3
'PythonPythonPython'
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : DevOps Engineer / SRE**

Les DevOps utilisent le REPL Python quotidiennement pour:
- Debugger des scripts d'automatisation en direct
- Tester des appels API rapidement
- Manipuler des donnees JSON/YAML
- Prototyper des solutions avant de les scripter

**Metier : Data Scientist**

Les Data Scientists vivent dans Jupyter Notebooks (un REPL evolue):
- Exploration de donnees interactive
- Visualisation immediate des resultats
- Documentation integree avec le code

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3.14 hello.py
Hello, World!
Hello, Python 3.14!
Help on function greet in module __main__:

greet(name: str) -> str
    Retourne un message de salutation personnalise.

    Args:
        name: Le nom de la personne a saluer.

    Returns:
        Une chaine formatee "Hello, {name}!"
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★☆☆☆☆☆☆☆ (3/10)

**Recompense :**
XP x2

**Time Complexity attendue :**
O(1)

**Space Complexity attendue :**
O(1)

#### 3.1.1 Consigne Bonus

**The Matrix Reloaded**

L'Architecte te lance un defi supplementaire. Ta fonction doit maintenant gerer plusieurs langues.

**Ta mission :**

Implementer `greet_multilingual(name: str, lang: str = "en") -> str`

**Langues supportees :**
- "en" -> "Hello, {name}!"
- "fr" -> "Bonjour, {name}!"
- "es" -> "Hola, {name}!"
- "de" -> "Hallo, {name}!"
- autre -> "Hello, {name}!" (defaut)

**Exemples Bonus :**

| Appel | Retour |
|-------|--------|
| `greet_multilingual("Neo", "fr")` | `"Bonjour, Neo!"` |
| `greet_multilingual("Trinity", "es")` | `"Hola, Trinity!"` |
| `greet_multilingual("Morpheus")` | `"Hello, Morpheus!"` |

#### 3.1.2 Prototype Bonus

```python
def greet_multilingual(name: str, lang: str = "en") -> str:
    ...
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Input | Expected Output | Points |
|---------|-------|-----------------|--------|
| T01 | `greet("World")` | `"Hello, World!"` | 10 |
| T02 | `greet("Python 3.14")` | `"Hello, Python 3.14!"` | 10 |
| T03 | `greet("")` | `"Hello, !"` | 10 |
| T04 | `greet("Neo")` | `"Hello, Neo!"` | 10 |
| T05 | Module docstring exists | `True` | 15 |
| T06 | Function docstring exists | `True` | 15 |
| T07 | Script runs without error | `True` | 15 |
| T08 | Output contains "Hello, World!" | `True` | 15 |

### 4.2 main.py de test

```python
#!/usr/bin/env python3.14
"""Tests automatises pour ex00_hello_repl"""

import importlib.util
import sys

def test_greet():
    # Import du module etudiant
    spec = importlib.util.spec_from_file_location("hello", "hello.py")
    hello = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hello)

    # Tests de la fonction greet
    assert hello.greet("World") == "Hello, World!", "T01 FAILED"
    assert hello.greet("Python 3.14") == "Hello, Python 3.14!", "T02 FAILED"
    assert hello.greet("") == "Hello, !", "T03 FAILED"
    assert hello.greet("Neo") == "Hello, Neo!", "T04 FAILED"

    # Test docstrings
    assert hello.__doc__ is not None, "T05 FAILED: Module docstring missing"
    assert hello.greet.__doc__ is not None, "T06 FAILED: Function docstring missing"

    print("All tests passed!")

if __name__ == "__main__":
    test_greet()
```

### 4.3 Solution de reference

```python
#!/usr/bin/env python3.14
# hello.py - Premier contact avec Python
# Exercice ex00_hello_repl

"""
Module d'introduction a Python 3.14.

Ce module demontre les concepts fondamentaux:
- Commentaires et docstrings
- Definition de fonctions
- Utilisation de help()
- Le pattern if __name__ == "__main__"
"""

def greet(name: str) -> str:
    """
    Retourne un message de salutation personnalise.

    Args:
        name: Le nom de la personne a saluer.

    Returns:
        Une chaine formatee "Hello, {name}!"
    """
    return f"Hello, {name}!"

def show_help() -> None:
    """
    Affiche l'aide de la fonction greet.
    """
    help(greet)

if __name__ == "__main__":
    print("Hello, World!")
    print(greet("Python 3.14"))
    show_help()
```

### 4.4 Solutions alternatives acceptees

```python
# Alternative 1: Concatenation classique
def greet(name: str) -> str:
    """Salue une personne."""
    return "Hello, " + name + "!"

# Alternative 2: format()
def greet(name: str) -> str:
    """Salue une personne."""
    return "Hello, {}!".format(name)

# Alternative 3: % formatting (ancien style)
def greet(name: str) -> str:
    """Salue une personne."""
    return "Hello, %s!" % name
```

### 4.5 Solutions refusees (avec explications)

```python
# REFUSE 1: Pas de docstring
def greet(name: str) -> str:
    return f"Hello, {name}!"
# Raison: Docstring obligatoire pour cet exercice

# REFUSE 2: Print au lieu de return
def greet(name: str) -> str:
    """Salue."""
    print(f"Hello, {name}!")
# Raison: Doit RETOURNER, pas afficher

# REFUSE 3: Mauvais format
def greet(name: str) -> str:
    """Salue."""
    return f"hello {name}"
# Raison: Format exact requis "Hello, {name}!"
```

### 4.6 Solution bonus de reference

```python
def greet_multilingual(name: str, lang: str = "en") -> str:
    """
    Retourne un message de salutation dans la langue specifiee.

    Args:
        name: Le nom de la personne a saluer.
        lang: Code de langue (en, fr, es, de). Defaut: en

    Returns:
        Une chaine de salutation dans la langue demandee.
    """
    greetings = {
        "en": "Hello",
        "fr": "Bonjour",
        "es": "Hola",
        "de": "Hallo"
    }
    greeting = greetings.get(lang, "Hello")
    return f"{greeting}, {name}!"
```

### 4.7 Solutions alternatives bonus

```python
# Alternative avec match (Python 3.10+)
def greet_multilingual(name: str, lang: str = "en") -> str:
    """Salutation multilingue avec match."""
    match lang:
        case "en": greeting = "Hello"
        case "fr": greeting = "Bonjour"
        case "es": greeting = "Hola"
        case "de": greeting = "Hallo"
        case _: greeting = "Hello"
    return f"{greeting}, {name}!"
```

### 4.8 Solutions refusees bonus

```python
# REFUSE: Pas de valeur par defaut pour lang
def greet_multilingual(name: str, lang: str) -> str:
    ...
# Raison: lang doit avoir "en" comme defaut
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.3.1-a",
  "name": "hello_repl",
  "version": "1.0.0",
  "language": "python",
  "language_version": "3.14",
  "files": {
    "submission": ["hello.py"],
    "test": ["test_hello.py"]
  },
  "functions": [
    {
      "name": "greet",
      "params": [{"name": "name", "type": "str"}],
      "return_type": "str",
      "required": true
    },
    {
      "name": "show_help",
      "params": [],
      "return_type": "None",
      "required": true
    }
  ],
  "tests": {
    "unit": [
      {"input": ["World"], "expected": "Hello, World!"},
      {"input": ["Python 3.14"], "expected": "Hello, Python 3.14!"},
      {"input": [""], "expected": "Hello, !"},
      {"input": ["Neo"], "expected": "Hello, Neo!"}
    ],
    "meta": [
      {"check": "module_docstring", "expected": true},
      {"check": "function_docstring", "target": "greet", "expected": true}
    ]
  },
  "scoring": {
    "total": 100,
    "tests": 60,
    "style": 20,
    "docstrings": 20
  },
  "bonus": {
    "available": true,
    "function": "greet_multilingual",
    "multiplier": 2
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```python
# MUTANT 1 (Boundary): Oubli de l'espace apres la virgule
def greet(name: str) -> str:
    """Salue."""
    return f"Hello,{name}!"  # Manque l'espace!
# Detection: assert greet("Neo") == "Hello, Neo!" echoue

# MUTANT 2 (Safety): Pas de gestion du None
def greet(name: str) -> str:
    """Salue."""
    return f"Hello, {name.upper()}!"  # Crash si name est None
# Detection: Test avec None

# MUTANT 3 (Logic): Minuscule au lieu de majuscule
def greet(name: str) -> str:
    """Salue."""
    return f"hello, {name}!"  # 'h' minuscule
# Detection: Comparaison exacte echoue

# MUTANT 4 (Return): Print au lieu de return
def greet(name: str) -> str:
    """Salue."""
    print(f"Hello, {name}!")  # Retourne None implicitement
# Detection: assert greet("Neo") == "Hello, Neo!" echoue (None != str)

# MUTANT 5 (Format): Oubli du point d'exclamation
def greet(name: str) -> str:
    """Salue."""
    return f"Hello, {name}"  # Pas de '!' a la fin
# Detection: Comparaison exacte echoue
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Cet exercice introduit les **8 concepts fondamentaux** pour demarrer avec Python:

1. **L'interpreteur Python** - Le programme qui execute ton code
2. **Le REPL** - L'environnement interactif Read-Eval-Print Loop
3. **Hello World** - La tradition universelle du premier programme
4. **Execution de scripts** - Comment lancer un fichier .py
5. **Commentaires** - Documentation inline avec #
6. **Docstrings** - Documentation formelle avec triple guillemets
7. **help()** - Acceder a la documentation integree
8. **exit()** - Quitter proprement le REPL

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION greet(nom):
    DEBUT
        RETOURNER "Hello, " + nom + "!"
    FIN

FONCTION show_help():
    DEBUT
        AFFICHER l'aide de la fonction greet
    FIN

SI ce fichier est execute directement:
    AFFICHER "Hello, World!"
    AFFICHER greet("Python 3.14")
    APPELER show_help()
```

### 5.3 Visualisation ASCII

```
+------------------+     +------------------+
|   hello.py       |     |   Python REPL    |
|                  |     |                  |
| # Commentaire    |     | >>> 2 + 2        |
| """Docstring""" |     | 4                |
|                  |     | >>> exit()       |
| def greet(name): |---->|                  |
|     return ...   |     +------------------+
|                  |
| if __name__...   |     +------------------+
|     print(...)   |---->|   Terminal       |
+------------------+     |                  |
                         | Hello, World!    |
                         | Hello, Python!   |
                         +------------------+
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier les guillemets autour des strings
```python
# FAUX
print(Hello World)  # NameError: name 'Hello' is not defined

# CORRECT
print("Hello World")
```

#### Piege 2: Confondre print() et return
```python
# print() affiche a l'ecran mais ne retourne rien
def bad_greet(name):
    print(f"Hello, {name}!")  # Retourne None!

# return renvoie une valeur
def good_greet(name):
    return f"Hello, {name}!"  # Retourne la string
```

#### Piege 3: Oublier l'indentation
```python
# FAUX
def greet(name):
return f"Hello, {name}!"  # IndentationError!

# CORRECT
def greet(name):
    return f"Hello, {name}!"
```

#### Piege 4: Confondre docstring et commentaire
```python
# Commentaire (ignore par help())
# Cette fonction salue

# Docstring (accessible via help())
"""Cette fonction salue."""
```

### 5.5 Cours Complet

#### 5.5.1 L'Interpreteur Python

Python est un langage **interprete**: le code est execute ligne par ligne par un programme appele l'**interpreteur**. Contrairement aux langages compiles (C, Rust), tu n'as pas besoin de transformer ton code en executable avant de le lancer.

```bash
# Verifier la version installee
$ python3 --version
Python 3.14.0

# Lancer l'interpreteur (REPL)
$ python3
>>>
```

#### 5.5.2 Le REPL (Read-Eval-Print Loop)

Le REPL est ton **laboratoire instantane**:

1. **Read** - Python lit ton entree
2. **Eval** - Python evalue/execute le code
3. **Print** - Python affiche le resultat
4. **Loop** - Python attend la prochaine commande

```python
>>> 2 + 2        # Read & Eval
4                # Print
>>>              # Loop (attend)
```

#### 5.5.3 Hello World - La Tradition

Depuis les annees 1970, le premier programme qu'on ecrit dans un nouveau langage affiche "Hello, World!". C'est une tradition initiee par Brian Kernighan dans le livre "The C Programming Language".

```python
print("Hello, World!")
```

#### 5.5.4 Scripts Python

Un script Python est un fichier texte avec l'extension `.py`:

```bash
# Creer le fichier
$ echo 'print("Hello!")' > hello.py

# L'executer
$ python3 hello.py
Hello!
```

#### 5.5.5 Commentaires (#)

Les commentaires sont ignores par Python. Ils servent a documenter le code pour les humains:

```python
# Ceci est un commentaire sur une ligne

x = 42  # Commentaire en fin de ligne

# On peut aussi
# ecrire sur
# plusieurs lignes
```

#### 5.5.6 Docstrings (Triple Guillemets)

Les docstrings sont des chaines speciales utilisees pour documenter modules, classes et fonctions:

```python
"""
Ceci est une docstring de module.
Elle decrit ce que fait le module entier.
"""

def ma_fonction():
    """
    Ceci est une docstring de fonction.
    Elle decrit ce que fait la fonction.

    Args:
        Aucun argument.

    Returns:
        Aucune valeur de retour.
    """
    pass
```

#### 5.5.7 help() - Documentation Integree

La fonction `help()` affiche la documentation d'un objet:

```python
>>> help(print)
Help on built-in function print...

>>> help(str.upper)
Help on method_descriptor...
```

#### 5.5.8 Le Pattern if __name__ == "__main__"

Ce pattern permet de distinguer si un fichier est execute directement ou importe:

```python
# Ce code s'execute TOUJOURS
print("Je suis charge")

# Ce code s'execute SEULEMENT si le fichier est lance directement
if __name__ == "__main__":
    print("Je suis le script principal")
```

### 5.6 Normes avec explications pedagogiques

| Norme | Explication | Exemple |
|-------|-------------|---------|
| PEP 8 | Guide de style Python officiel | 4 espaces pour l'indentation |
| PEP 257 | Convention pour docstrings | Triple guillemets, premiere ligne = resume |
| snake_case | Nommage des fonctions/variables | `ma_fonction`, `mon_variable` |
| MAJUSCULES | Nommage des constantes | `PI = 3.14159` |

### 5.7 Simulation avec trace d'execution

```python
# Execution de hello.py

# Ligne 1-8: Docstring de module (stockee dans __doc__)
# Ligne 10-20: Definition de greet() (pas encore executee)
# Ligne 22-26: Definition de show_help() (pas encore executee)
# Ligne 28: Condition __name__ == "__main__" -> True
# Ligne 29: print("Hello, World!") -> Affiche "Hello, World!"
# Ligne 30: greet("Python 3.14") -> Retourne "Hello, Python 3.14!"
#           print(...) -> Affiche "Hello, Python 3.14!"
# Ligne 31: show_help() -> Affiche l'aide de greet
```

### 5.8 Mnemotechniques

**REPL = "Repete Encore Pour L'eternite"**
- Read = Lit ce que tu tapes
- Eval = Evalue/execute le code
- Print = Affiche le resultat
- Loop = Recommence

**"Help() est ton ami dans la Matrix"**
- Quand tu es perdu, demande help()
- `help(fonction)` -> documentation
- `help(module)` -> tout le contenu

### 5.9 Applications pratiques

1. **Prototypage rapide**: Tester une idee en 10 secondes dans le REPL
2. **Debugging**: Explorer des objets avec `help()` et `type()`
3. **Calculs**: Utiliser Python comme calculatrice avancee
4. **Scripting**: Automatiser des taches repetitives

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de guillemets | `NameError` | Entourer les strings de `"` ou `'` |
| Mauvaise indentation | `IndentationError` | 4 espaces apres `:` |
| print vs return | Fonction retourne `None` | Utiliser `return` pour renvoyer |
| Oubli de docstring | `help()` vide | Ajouter `"""docstring"""` |
| `__name__` mal ecrit | Code pas execute | Exactement `if __name__ == "__main__":` |

---

## SECTION 7 : QCM

### Question 1
Qu'est-ce que le REPL?

A) Un type de variable Python
B) Read-Eval-Print Loop, l'environnement interactif
C) Un module standard Python
D) Une erreur de syntaxe
E) Un editeur de code
F) Un type de fichier
G) Une fonction built-in
H) Un framework web
I) Un gestionnaire de packages
J) Un debugger

**Reponse correcte: B**

### Question 2
Quelle syntaxe cree une docstring?

A) `# Ceci est une docstring`
B) `// Ceci est une docstring`
C) `"""Ceci est une docstring"""`
D) `/* Ceci est une docstring */`
E) `-- Ceci est une docstring`
F) `' Ceci est une docstring`
G) `<! Ceci est une docstring >`
H) `{{ Ceci est une docstring }}`
I) `[[ Ceci est une docstring ]]`
J) `%% Ceci est une docstring %%`

**Reponse correcte: C**

### Question 3
Que retourne une fonction qui ne contient que `print()`?

A) La chaine affichee
B) `True`
C) `0`
D) `None`
E) Une erreur
F) Un tuple vide
G) Une liste vide
H) `False`
I) `-1`
J) L'objet `print`

**Reponse correcte: D**

### Question 4
Quand le bloc `if __name__ == "__main__":` s'execute-t-il?

A) Toujours
B) Jamais
C) Quand le fichier est importe
D) Quand le fichier est execute directement
E) Quand une erreur survient
F) Quand le REPL demarre
G) Quand help() est appele
H) Quand exit() est appele
I) Quand print() est appele
J) Au hasard

**Reponse correcte: D**

### Question 5
Comment afficher l'aide de la fonction `len`?

A) `doc(len)`
B) `info(len)`
C) `help(len)`
D) `man(len)`
E) `len.help()`
F) `len.__help__()`
G) `?len`
H) `len?`
I) `describe(len)`
J) `explain(len)`

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Syntaxe |
|---------|-------------|---------|
| REPL | Environnement interactif | `python3` |
| Script | Fichier executable | `python3 fichier.py` |
| Commentaire | Documentation ignoree | `# commentaire` |
| Docstring | Documentation formelle | `"""doc"""` |
| help() | Affiche documentation | `help(objet)` |
| print() | Affiche a l'ecran | `print("texte")` |
| return | Renvoie une valeur | `return valeur` |
| __name__ | Nom du module courant | `if __name__ == "__main__":` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.3.1-a",
    "name": "hello_repl",
    "module": "0.3.1",
    "phase": 0,
    "difficulty": 2,
    "xp": 100,
    "time_minutes": 30
  },
  "metadata": {
    "concepts": ["interpreter", "repl", "hello_world", "scripts", "comments", "docstrings", "help", "exit"],
    "prerequisites": [],
    "language": "python",
    "language_version": "3.14"
  },
  "files": {
    "template": "hello.py",
    "solution": "hello_solution.py",
    "test": "test_hello.py"
  },
  "grading": {
    "automated": true,
    "tests_weight": 60,
    "style_weight": 20,
    "docstring_weight": 20
  },
  "bonus": {
    "available": true,
    "name": "greet_multilingual",
    "multiplier": 2,
    "difficulty": 3
  }
}
```
