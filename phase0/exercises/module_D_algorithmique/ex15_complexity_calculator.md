# Exercice D.15 : complexity_calculator

**Module :**
D — Algorithmique

**Concept :**
15 — Calcul de complexite (boucles, recursion, espace)

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Big O notation (ex14)
- Boucles et recursion
- Notion de memoire

**Domaines :**
Algo, Theory

**Duree estimee :**
40 min

**XP Base :**
75

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `complexity_calculator.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | Toutes les fonctions built-in standard |

---

### 1.2 Consigne

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions qui calculent la complexite temporelle et spatiale d'algorithmes decrits par leur structure.

1. `analyze_loops(loop_structure: str) -> str` : Analyse des boucles imbriquees
2. `analyze_recursion(recurrence: str) -> str` : Analyse des relations de recurrence
3. `space_complexity(description: str) -> str` : Analyse de la complexite spatiale
4. `time_space_tradeoff(approach1: dict, approach2: dict) -> str` : Comparaison de compromis

**Entree :**

```python
def analyze_loops(loop_structure: str) -> str:
    """
    Analyse la complexite d'une structure de boucles.

    Args:
        loop_structure: Description de la structure (ex: "for i in n: for j in n")

    Returns:
        La complexite temporelle
    """
    pass

def analyze_recursion(recurrence: str) -> str:
    """
    Analyse une relation de recurrence.

    Args:
        recurrence: Relation (ex: "T(n) = 2T(n/2) + n")

    Returns:
        La complexite
    """
    pass

def space_complexity(description: str) -> str:
    """
    Determine la complexite spatiale.

    Args:
        description: Description de l'utilisation memoire

    Returns:
        La complexite spatiale
    """
    pass
```

**Exemples :**

| Structure | Complexite Temps | Explication |
|-----------|------------------|-------------|
| "for i in n" | O(n) | Une boucle simple |
| "for i in n: for j in n" | O(n^2) | Deux boucles imbriquees |
| "for i in n: for j in i" | O(n^2) | Somme 1+2+...+n = n(n+1)/2 |
| "while n > 1: n = n/2" | O(log n) | Division par 2 |
| "T(n) = T(n-1) + 1" | O(n) | Recursion lineaire |
| "T(n) = 2T(n/2) + n" | O(n log n) | Merge sort pattern |
| "T(n) = 2T(n-1)" | O(2^n) | Arbre binaire complet |

---

### 1.3 Prototype

```python
def analyze_loops(loop_structure: str) -> str:
    pass

def analyze_recursion(recurrence: str) -> str:
    pass

def space_complexity(description: str) -> str:
    pass

def time_space_tradeoff(approach1: dict, approach2: dict) -> str:
    """
    Compare deux approches et retourne laquelle est meilleure selon le contexte.

    Args:
        approach1: {"name": str, "time": str, "space": str}
        approach2: {"name": str, "time": str, "space": str}

    Returns:
        Analyse comparative
    """
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Le Theoreme Maitre (Master Theorem)**

Pour les recurrences de la forme T(n) = aT(n/b) + f(n):
- Si f(n) = O(n^c) avec c < log_b(a): T(n) = O(n^(log_b(a)))
- Si f(n) = O(n^c) avec c = log_b(a): T(n) = O(n^c * log n)
- Si f(n) = O(n^c) avec c > log_b(a): T(n) = O(f(n))

**Trade-offs celebres**

| Probleme | Temps rapide | Espace faible |
|----------|-------------|---------------|
| Fibonacci | O(n) avec memo, O(n) espace | O(n) sans memo, O(1) espace |
| Tri | O(n log n) merge sort, O(n) espace | O(n log n) heap sort, O(1) espace |
| Cache | O(1) lookup, O(n) espace | O(n) lookup, O(1) espace |

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Embedded Developer** | Minimiser la memoire sur microcontroleur |
| **HFT Developer** | Optimiser le temps au nanoseconde |
| **Mobile Developer** | Equilibrer batterie et reactivite |
| **Cloud Architect** | Cout = temps * memoire * instances |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python complexity_calculator.py

>>> analyze_loops("for i in n")
'O(n)'

>>> analyze_loops("for i in n: for j in n")
'O(n^2)'

>>> analyze_loops("for i in n: for j in n: for k in n")
'O(n^3)'

>>> analyze_loops("while n > 1: n = n/2")
'O(log n)'

>>> analyze_recursion("T(n) = T(n-1) + 1")
'O(n)'

>>> analyze_recursion("T(n) = 2T(n/2) + n")
'O(n log n)'

>>> analyze_recursion("T(n) = 2T(n-1)")
'O(2^n)'

>>> space_complexity("array of size n")
'O(n)'

>>> space_complexity("recursive call depth n")
'O(n)'

>>> space_complexity("constant variables only")
'O(1)'
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | single_loop | "for i in n" | "O(n)" | 10 | Loop |
| 2 | nested_loops | "for i in n: for j in n" | "O(n^2)" | 10 | Loop |
| 3 | triple_nested | "for i in n: for j in n: for k in n" | "O(n^3)" | 10 | Loop |
| 4 | log_loop | "while n > 1: n = n/2" | "O(log n)" | 10 | Loop |
| 5 | linear_recursion | "T(n) = T(n-1) + 1" | "O(n)" | 10 | Recursion |
| 6 | merge_sort_recurrence | "T(n) = 2T(n/2) + n" | "O(n log n)" | 10 | Recursion |
| 7 | exponential_recursion | "T(n) = 2T(n-1)" | "O(2^n)" | 10 | Recursion |
| 8 | space_linear | "array of size n" | "O(n)" | 10 | Space |
| 9 | space_constant | "constant variables" | "O(1)" | 10 | Space |
| 10 | tradeoff | memo vs no_memo | valid analysis | 10 | Tradeoff |

**Total : 100 points**

---

### 4.2 Tests unitaires

```python
import unittest
from complexity_calculator import analyze_loops, analyze_recursion, space_complexity

class TestComplexityCalculator(unittest.TestCase):

    def test_single_loop(self):
        self.assertEqual(analyze_loops("for i in n"), "O(n)")

    def test_nested_loops(self):
        self.assertEqual(analyze_loops("for i in n: for j in n"), "O(n^2)")

    def test_triple_nested(self):
        self.assertEqual(analyze_loops("for i in n: for j in n: for k in n"), "O(n^3)")

    def test_log_loop(self):
        self.assertEqual(analyze_loops("while n > 1: n = n/2"), "O(log n)")

    def test_linear_recursion(self):
        self.assertEqual(analyze_recursion("T(n) = T(n-1) + 1"), "O(n)")

    def test_merge_sort(self):
        self.assertEqual(analyze_recursion("T(n) = 2T(n/2) + n"), "O(n log n)")

    def test_exponential(self):
        self.assertEqual(analyze_recursion("T(n) = 2T(n-1)"), "O(2^n)")

    def test_space_linear(self):
        self.assertEqual(space_complexity("array of size n"), "O(n)")

    def test_space_constant(self):
        self.assertEqual(space_complexity("constant variables only"), "O(1)")

if __name__ == '__main__':
    unittest.main()
```

---

### 4.3 Solution de reference

```python
import re

def analyze_loops(loop_structure: str) -> str:
    """
    Analyse la complexite d'une structure de boucles.
    """
    structure = loop_structure.lower()

    # Count nested for loops
    for_count = structure.count("for")

    # Check for logarithmic pattern (divide by 2)
    if "n/2" in structure or "n = n/2" in structure or "n // 2" in structure:
        if for_count > 0:
            return "O(n log n)"
        return "O(log n)"

    # Check for while with division
    if "while" in structure and ("/2" in structure or "// 2" in structure):
        return "O(log n)"

    # Nested loops
    if for_count == 0:
        return "O(1)"
    elif for_count == 1:
        return "O(n)"
    elif for_count == 2:
        return "O(n^2)"
    elif for_count == 3:
        return "O(n^3)"
    else:
        return f"O(n^{for_count})"


def analyze_recursion(recurrence: str) -> str:
    """
    Analyse une relation de recurrence.
    """
    rec = recurrence.lower().replace(" ", "")

    # T(n) = 2T(n-1) -> Exponential
    if re.search(r'2t\(n-1\)', rec):
        return "O(2^n)"

    # T(n) = T(n-1) + 1 or T(n) = T(n-1) + O(1) -> Linear
    if re.search(r't\(n-1\)\+[o1c]', rec) or re.search(r't\(n-1\)\+1', rec):
        return "O(n)"

    # T(n) = T(n-1) + n -> Quadratic
    if re.search(r't\(n-1\)\+n', rec):
        return "O(n^2)"

    # T(n) = 2T(n/2) + n -> Linearithmic (merge sort)
    if re.search(r'2t\(n/2\)\+n', rec):
        return "O(n log n)"

    # T(n) = 2T(n/2) + 1 -> Linear
    if re.search(r'2t\(n/2\)\+[1o]', rec):
        return "O(n)"

    # T(n) = T(n/2) + 1 -> Logarithmic (binary search)
    if re.search(r't\(n/2\)\+[1o]', rec):
        return "O(log n)"

    # T(n) = T(n/2) + n -> Linear
    if re.search(r't\(n/2\)\+n', rec):
        return "O(n)"

    return "O(n)"


def space_complexity(description: str) -> str:
    """
    Determine la complexite spatiale.
    """
    desc = description.lower()

    # Quadratic space
    if "matrix" in desc or "2d array" in desc or "n x n" in desc:
        return "O(n^2)"

    # Linear space
    linear_keywords = ["array of size n", "list of n", "recursive call depth n",
                      "copy of array", "new array", "stack of n"]
    if any(kw in desc for kw in linear_keywords):
        return "O(n)"

    # Logarithmic space (recursive with divide)
    if "recursive" in desc and ("binary" in desc or "divide" in desc):
        return "O(log n)"

    # Constant space
    constant_keywords = ["constant", "fixed", "single variable", "few variables",
                        "in-place", "swap only"]
    if any(kw in desc for kw in constant_keywords):
        return "O(1)"

    return "O(n)"


def time_space_tradeoff(approach1: dict, approach2: dict) -> str:
    """
    Compare deux approches et retourne une analyse.
    """
    complexity_order = ["O(1)", "O(log n)", "O(n)", "O(n log n)", "O(n^2)", "O(2^n)"]

    def get_rank(c):
        try:
            return complexity_order.index(c)
        except ValueError:
            return 3  # Default to O(n)

    time1, space1 = get_rank(approach1["time"]), get_rank(approach1["space"])
    time2, space2 = get_rank(approach2["time"]), get_rank(approach2["space"])

    result = []
    result.append(f"{approach1['name']}: Time={approach1['time']}, Space={approach1['space']}")
    result.append(f"{approach2['name']}: Time={approach2['time']}, Space={approach2['space']}")

    if time1 < time2 and space1 > space2:
        result.append(f"Trade-off: {approach1['name']} is faster but uses more memory")
    elif time1 > time2 and space1 < space2:
        result.append(f"Trade-off: {approach2['name']} is faster but uses more memory")
    elif time1 + space1 < time2 + space2:
        result.append(f"{approach1['name']} is generally better")
    elif time1 + space1 > time2 + space2:
        result.append(f"{approach2['name']} is generally better")
    else:
        result.append("Both approaches are equivalent")

    return "\n".join(result)
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Logic) : Compte mal les boucles**

```python
# Mutant A: Compte "for" dans le mauvais sens
def analyze_loops(loop_structure: str) -> str:
    for_count = loop_structure.count("i")  # ERREUR: compte les 'i'
    return f"O(n^{for_count})"
```
**Pourquoi faux :** "for i in n" retournerait O(n^2) a cause des deux 'i'.

**Mutant B (Pattern) : Regex incorrecte**

```python
# Mutant B: Pattern trop permissif
def analyze_recursion(recurrence: str) -> str:
    if "2" in recurrence:  # ERREUR: trop vague
        return "O(2^n)"
```
**Pourquoi faux :** "T(n) = 2T(n/2) + n" retournerait O(2^n) au lieu de O(n log n).

**Mutant C (Missing) : Oublie les cas logarithmiques**

```python
# Mutant C: Pas de gestion du log
def analyze_loops(loop_structure: str) -> str:
    for_count = loop_structure.count("for")
    # MANQUE: verification de n/2
    return f"O(n^{max(1, for_count)})"
```
**Pourquoi faux :** "while n > 1: n = n/2" retournerait O(n) au lieu de O(log n).

**Mutant D (Space) : Confond temps et espace**

```python
# Mutant D: Analyse temporelle au lieu de spatiale
def space_complexity(description: str) -> str:
    if "loop" in description:  # ERREUR: loop = temps, pas espace
        return "O(n)"
    return "O(1)"
```
**Pourquoi faux :** L'espace depend des allocations, pas des boucles.

**Mutant E (Tradeoff) : Comparaison incorrecte**

```python
# Mutant E: Compare seulement le temps
def time_space_tradeoff(approach1: dict, approach2: dict) -> str:
    # ERREUR: ignore l'espace
    if approach1["time"] < approach2["time"]:
        return f"{approach1['name']} is better"
    return f"{approach2['name']} is better"
```
**Pourquoi faux :** Ignore completement le trade-off espace-temps.

---

## SECTION 5 : COMPRENDRE

### 5.1 Analyse des boucles

```
Boucle simple: O(n)
for i in range(n):
    operation()  # Execute n fois

Boucles imbriquees: O(n^k) pour k boucles
for i in range(n):
    for j in range(n):
        operation()  # Execute n * n = n^2 fois

Boucle avec division: O(log n)
while n > 1:
    n = n // 2  # Execute log2(n) fois
```

### 5.2 Analyse de recursion

```
Recurrence lineaire: T(n) = T(n-1) + O(1)
- Chaque appel fait un sous-appel
- Profondeur = n
- Complexite = O(n)

Recurrence binaire: T(n) = 2T(n/2) + O(n)
- Deux sous-appels de taille n/2
- Profondeur = log n
- Travail a chaque niveau = n
- Complexite = O(n log n)

Recurrence exponentielle: T(n) = 2T(n-1)
- Deux sous-appels de taille n-1
- Arbre binaire complet de profondeur n
- Complexite = O(2^n)
```

### 5.3 Complexite spatiale

```
O(1) - Constant:
- Variables scalaires fixes
- Modification in-place

O(log n) - Logarithmique:
- Pile de recursion pour binary search
- Arbres equilibres

O(n) - Lineaire:
- Copie d'un tableau
- Pile de recursion lineaire

O(n^2) - Quadratique:
- Matrice n x n
- Graphe en matrice d'adjacence
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier la recursion dans l'espace | Sous-estimer la memoire | Compter la pile d'appels |
| 2 | Confondre boucles sequentielles et imbriquees | O(2n) vs O(n^2) | O(n) + O(n) = O(n) |
| 3 | Ignorer le travail hors recursion | Mauvaise complexite | Inclure f(n) dans T(n) |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle est la complexite de deux boucles FOR sequentielles (pas imbriquees)?

- A) O(n^2)
- B) O(2n)
- C) O(n)
- D) O(n + n)

**Reponse : C** - O(n) + O(n) = O(2n) = O(n).

### Question 2 (3 points)
Quelle est la complexite spatiale d'une recursion avec profondeur n?

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n^2)

**Reponse : C** - La pile d'appels utilise O(n) espace.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.15 |
| **Nom** | complexity_calculator |
| **Difficulte** | 3/10 |
| **Duree** | 40 min |
| **XP Base** | 75 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Analyse de boucles, recursion, espace |

---

*Document genere selon HACKBRAIN v5.5.2*
