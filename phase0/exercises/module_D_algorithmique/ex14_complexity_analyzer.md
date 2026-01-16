# Exercice D.14 : complexity_analyzer

**Module :**
D — Algorithmique

**Concept :**
14 — Analyse de complexite (Big O notation)

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Syntaxe de base Python
- Notion de boucles et fonctions
- Mathematiques de base (logarithmes)

**Domaines :**
Algo, Theory

**Duree estimee :**
30 min

**XP Base :**
60

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `complexity_analyzer.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | Toutes les fonctions built-in standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | Aucune restriction |

---

### 1.2 Consigne

#### Section Culture : "The Matrix of Efficiency"

Imagine que chaque operation de ton programme est une action dans la Matrix. Certaines actions sont instantanees (Neo esquive une balle), d'autres prennent du temps proportionnel au nombre d'ennemis (combattre chaque agent un par un), et certaines explosent exponentiellement (chaque agent se clone en deux).

Comprendre Big O, c'est comprendre comment ton programme se comportera quand les donnees grandissent. C'est la difference entre un programme qui repond en millisecondes et un qui ne finit jamais.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une fonction `classify_complexity(code_description: str) -> str` qui analyse une description textuelle d'un algorithme et retourne sa classe de complexite.

Les classes a identifier sont :
- `O(1)` : Temps constant
- `O(log n)` : Logarithmique
- `O(n)` : Lineaire
- `O(n log n)` : Linearithmique
- `O(n^2)` : Quadratique
- `O(2^n)` : Exponentielle

**Entree :**

```python
def classify_complexity(code_description: str) -> str:
    """
    Analyse une description d'algorithme et retourne sa complexite Big O.

    Args:
        code_description: Description textuelle de l'algorithme

    Returns:
        La classe de complexite: "O(1)", "O(log n)", "O(n)",
        "O(n log n)", "O(n^2)", ou "O(2^n)"
    """
    pass
```

**Sortie :**
- Une chaine representant la complexite

**Contraintes :**
- La description contiendra des mots-cles indicatifs
- Retourner la complexite dominante

**Exemples :**

| Description | Complexite | Explication |
|-------------|------------|-------------|
| "access array element by index" | O(1) | Acces direct |
| "binary search in sorted array" | O(log n) | Division par 2 a chaque etape |
| "iterate through all elements" | O(n) | Une passe sur tous les elements |
| "merge sort algorithm" | O(n log n) | Division + fusion |
| "nested loops over array" | O(n^2) | Boucle dans boucle |
| "recursive fibonacci without memo" | O(2^n) | Arbre d'appels double |

---

### 1.3 Prototype

```python
def classify_complexity(code_description: str) -> str:
    """
    Analyse une description d'algorithme et retourne sa complexite Big O.

    Args:
        code_description: Description textuelle de l'algorithme

    Returns:
        La classe de complexite
    """
    pass

def explain_complexity(complexity: str) -> str:
    """
    Retourne une explication de la complexite donnee.

    Args:
        complexity: Une classe de complexite (ex: "O(n)")

    Returns:
        Une explication textuelle
    """
    pass

def compare_complexities(c1: str, c2: str) -> int:
    """
    Compare deux complexites.

    Args:
        c1, c2: Deux classes de complexite

    Returns:
        -1 si c1 < c2, 0 si c1 == c2, 1 si c1 > c2
    """
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**L'origine de Big O**

La notation Big O a ete introduite par le mathematicien allemand Paul Bachmann en 1894, puis popularisee par Edmund Landau. Le "O" signifie "Ordnung" (ordre de grandeur en allemand).

**Pourquoi ca compte vraiment**

| n | O(1) | O(log n) | O(n) | O(n log n) | O(n^2) | O(2^n) |
|---|------|----------|------|------------|--------|--------|
| 10 | 1 | 3 | 10 | 33 | 100 | 1024 |
| 100 | 1 | 7 | 100 | 664 | 10000 | 10^30 |
| 1000 | 1 | 10 | 1000 | 9966 | 10^6 | 10^301 |

A 1 million d'operations par seconde, O(2^n) avec n=100 prendrait plus de temps que l'age de l'univers !

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Software Engineer** | Choisir le bon algorithme pour les contraintes de performance |
| **Data Engineer** | Optimiser les pipelines de traitement de donnees massives |
| **Game Developer** | Garantir 60 FPS malgre des milliers d'entites |
| **Backend Engineer** | Dimensionner les serveurs selon la charge attendue |
| **ML Engineer** | Evaluer la faisabilite de l'entrainement sur de gros datasets |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python complexity_analyzer.py

>>> classify_complexity("access array element by index")
'O(1)'

>>> classify_complexity("binary search in sorted array")
'O(log n)'

>>> classify_complexity("iterate through all elements once")
'O(n)'

>>> classify_complexity("quicksort average case")
'O(n log n)'

>>> classify_complexity("compare all pairs of elements")
'O(n^2)'

>>> classify_complexity("generate all subsets")
'O(2^n)'

>>> compare_complexities("O(n)", "O(n^2)")
-1

>>> explain_complexity("O(log n)")
'Logarithmique: Le temps augmente lentement quand n double'
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | constant_access | "array index access" | "O(1)" | 10 | Basic |
| 2 | logarithmic | "binary search" | "O(log n)" | 10 | Basic |
| 3 | linear | "single loop" | "O(n)" | 10 | Basic |
| 4 | linearithmic | "merge sort" | "O(n log n)" | 10 | Basic |
| 5 | quadratic | "nested loops" | "O(n^2)" | 10 | Basic |
| 6 | exponential | "recursive fib" | "O(2^n)" | 10 | Basic |
| 7 | compare_less | ("O(1)", "O(n)") | -1 | 10 | Compare |
| 8 | compare_equal | ("O(n)", "O(n)") | 0 | 10 | Compare |
| 9 | compare_greater | ("O(n^2)", "O(n)") | 1 | 10 | Compare |
| 10 | explain_valid | "O(n)" | contains "linear" | 10 | Explain |

**Total : 100 points**

---

### 4.2 Tests unitaires

```python
import unittest
from complexity_analyzer import classify_complexity, compare_complexities, explain_complexity

class TestComplexityAnalyzer(unittest.TestCase):

    def test_constant(self):
        self.assertEqual(classify_complexity("access array element by index"), "O(1)")
        self.assertEqual(classify_complexity("hash table lookup"), "O(1)")

    def test_logarithmic(self):
        self.assertEqual(classify_complexity("binary search in sorted array"), "O(log n)")
        self.assertEqual(classify_complexity("find in balanced BST"), "O(log n)")

    def test_linear(self):
        self.assertEqual(classify_complexity("iterate through all elements"), "O(n)")
        self.assertEqual(classify_complexity("linear search"), "O(n)")

    def test_linearithmic(self):
        self.assertEqual(classify_complexity("merge sort algorithm"), "O(n log n)")
        self.assertEqual(classify_complexity("heap sort"), "O(n log n)")

    def test_quadratic(self):
        self.assertEqual(classify_complexity("nested loops over array"), "O(n^2)")
        self.assertEqual(classify_complexity("bubble sort"), "O(n^2)")

    def test_exponential(self):
        self.assertEqual(classify_complexity("recursive fibonacci"), "O(2^n)")
        self.assertEqual(classify_complexity("generate all subsets"), "O(2^n)")

    def test_compare(self):
        self.assertEqual(compare_complexities("O(1)", "O(n)"), -1)
        self.assertEqual(compare_complexities("O(n)", "O(n)"), 0)
        self.assertEqual(compare_complexities("O(n^2)", "O(n)"), 1)
        self.assertEqual(compare_complexities("O(log n)", "O(n log n)"), -1)

    def test_explain(self):
        explanation = explain_complexity("O(n)")
        self.assertIn("linear", explanation.lower())

if __name__ == '__main__':
    unittest.main()
```

---

### 4.3 Solution de reference

```python
def classify_complexity(code_description: str) -> str:
    """
    Analyse une description d'algorithme et retourne sa complexite Big O.
    """
    desc = code_description.lower()

    # Check for exponential first (most specific)
    exponential_keywords = ["recursive fibonacci", "all subsets", "all permutations",
                           "2^n", "exponential", "brute force all combinations"]
    if any(kw in desc for kw in exponential_keywords):
        return "O(2^n)"

    # Check for quadratic
    quadratic_keywords = ["nested loops", "bubble sort", "selection sort",
                         "insertion sort", "compare all pairs", "n^2", "n squared"]
    if any(kw in desc for kw in quadratic_keywords):
        return "O(n^2)"

    # Check for linearithmic
    linearithmic_keywords = ["merge sort", "heap sort", "quicksort average",
                            "n log n", "divide and conquer sort"]
    if any(kw in desc for kw in linearithmic_keywords):
        return "O(n log n)"

    # Check for logarithmic
    logarithmic_keywords = ["binary search", "log n", "logarithmic",
                           "balanced bst", "divide by half", "binary tree search"]
    if any(kw in desc for kw in logarithmic_keywords):
        return "O(log n)"

    # Check for linear
    linear_keywords = ["iterate", "single loop", "linear search", "traverse",
                      "one pass", "scan all", "visit each"]
    if any(kw in desc for kw in linear_keywords):
        return "O(n)"

    # Check for constant
    constant_keywords = ["index access", "array element", "hash lookup",
                        "constant", "direct access", "push", "pop", "peek"]
    if any(kw in desc for kw in constant_keywords):
        return "O(1)"

    # Default to linear if unclear
    return "O(n)"


def explain_complexity(complexity: str) -> str:
    """
    Retourne une explication de la complexite donnee.
    """
    explanations = {
        "O(1)": "Constant: Le temps d'execution ne depend pas de la taille des donnees",
        "O(log n)": "Logarithmique: Le temps augmente lentement quand n double (ex: binary search)",
        "O(n)": "Lineaire: Le temps augmente proportionnellement a n (ex: parcourir une liste)",
        "O(n log n)": "Linearithmique: Typique des algorithmes de tri efficaces (ex: merge sort)",
        "O(n^2)": "Quadratique: Le temps explose avec n (ex: boucles imbriquees)",
        "O(2^n)": "Exponentielle: Croissance explosive, impraticable pour grand n"
    }
    return explanations.get(complexity, "Complexite non reconnue")


def compare_complexities(c1: str, c2: str) -> int:
    """
    Compare deux complexites.
    Returns -1 si c1 < c2, 0 si c1 == c2, 1 si c1 > c2
    """
    order = ["O(1)", "O(log n)", "O(n)", "O(n log n)", "O(n^2)", "O(2^n)"]

    try:
        idx1 = order.index(c1)
        idx2 = order.index(c2)
    except ValueError:
        return 0  # Unknown complexity

    if idx1 < idx2:
        return -1
    elif idx1 > idx2:
        return 1
    else:
        return 0
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de regex**

```python
import re

def classify_complexity(code_description: str) -> str:
    desc = code_description.lower()

    patterns = [
        (r'2\^n|exponential|all subsets|recursive fib', "O(2^n)"),
        (r'n\^2|nested|bubble|selection sort', "O(n^2)"),
        (r'n\s*log\s*n|merge sort|heap sort', "O(n log n)"),
        (r'log\s*n|binary search|bst', "O(log n)"),
        (r'iterate|linear|traverse|single loop', "O(n)"),
        (r'constant|index|hash|direct', "O(1)"),
    ]

    for pattern, complexity in patterns:
        if re.search(pattern, desc):
            return complexity

    return "O(n)"
```

---

### 4.5 Solutions refusees

**Refus 1 : Retourne toujours la meme valeur**

```python
# REFUSE : Ne fait pas d'analyse
def classify_complexity(code_description: str) -> str:
    return "O(n)"  # Toujours lineaire !
```
**Pourquoi refuse :** Ne distingue pas les differentes complexites.

**Refus 2 : Comparaison incorrecte**

```python
# REFUSE : Ordre incorrect
def compare_complexities(c1: str, c2: str) -> int:
    # Trie alphabetiquement au lieu de par complexite
    return -1 if c1 < c2 else (1 if c1 > c2 else 0)
```
**Pourquoi refuse :** "O(1)" viendrait apres "O(2^n)" alphabetiquement.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Logic) : Ordre de verification inverse**

```python
# Mutant A: Verifie constant avant exponential
def classify_complexity(code_description: str) -> str:
    desc = code_description.lower()
    # ERREUR: Constant trop tot, "constant" dans "exponential"
    if "constant" in desc or "access" in desc:
        return "O(1)"
    # ... reste du code
```
**Pourquoi faux :** "recursive fibonacci with constant base case" serait O(1).

**Mutant B (Boundary) : Keywords partiels**

```python
# Mutant B: Match partiel incorrect
def classify_complexity(code_description: str) -> str:
    desc = code_description.lower()
    if "log" in desc:  # ERREUR: "catalog" contient "log"
        return "O(log n)"
```
**Pourquoi faux :** "iterate through catalog" retournerait O(log n).

**Mutant C (Return) : Mauvais type de retour**

```python
# Mutant C: Retourne un int au lieu d'une string
def classify_complexity(code_description: str) -> str:
    # ... analyse
    return 1  # ERREUR: devrait etre "O(1)"
```
**Pourquoi faux :** Le type de retour doit etre une chaine.

**Mutant D (Comparison) : Comparaison inversee**

```python
# Mutant D: Compare dans le mauvais sens
def compare_complexities(c1: str, c2: str) -> int:
    order = ["O(1)", "O(log n)", "O(n)", "O(n log n)", "O(n^2)", "O(2^n)"]
    idx1, idx2 = order.index(c1), order.index(c2)
    if idx1 < idx2:
        return 1  # ERREUR: devrait etre -1
    elif idx1 > idx2:
        return -1  # ERREUR: devrait etre 1
    return 0
```
**Pourquoi faux :** O(1) < O(n) devrait retourner -1, pas 1.

**Mutant E (Missing) : Oublie une complexite**

```python
# Mutant E: Pas de gestion de O(n log n)
def classify_complexity(code_description: str) -> str:
    desc = code_description.lower()
    if "exponential" in desc: return "O(2^n)"
    if "nested" in desc: return "O(n^2)"
    # MANQUE: O(n log n)
    if "binary search" in desc: return "O(log n)"
    if "iterate" in desc: return "O(n)"
    return "O(1)"
```
**Pourquoi faux :** "merge sort" retournerait O(1) au lieu de O(n log n).

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Big O Notation | Mesure de croissance asymptotique | Fondamental |
| Classes de complexite | O(1), O(log n), O(n), etc. | Fondamental |
| Analyse d'algorithmes | Identifier la complexite dominante | Important |
| Comparaison | Hierarchie des complexites | Important |

---

### 5.2 Hierarchie des complexites

```
Complexite croissante (de meilleur a pire):

O(1) < O(log n) < O(n) < O(n log n) < O(n^2) < O(2^n)

Visualisation pour n = 1000:

O(1)      : |
O(log n)  : |=========| (10)
O(n)      : |=========...========| (1000)
O(n log n): |=========...========...| (10000)
O(n^2)    : |=========...========...========...| (1000000)
O(2^n)    : INFINI PRATIQUE (10^301)
```

---

### 5.3 Exemples par complexite

```
O(1) - Constant:
- Acces a un element de tableau par index
- Insertion/suppression en tete de liste chainee
- Push/pop sur une pile

O(log n) - Logarithmique:
- Recherche binaire
- Recherche dans un arbre binaire equilibre
- Calcul de puissance par exponentiation rapide

O(n) - Lineaire:
- Recherche lineaire
- Parcours d'un tableau
- Calcul de somme

O(n log n) - Linearithmique:
- Tri fusion (merge sort)
- Tri rapide (quicksort, cas moyen)
- Tri par tas (heap sort)

O(n^2) - Quadratique:
- Tri a bulles
- Tri par selection
- Comparer toutes les paires

O(2^n) - Exponentielle:
- Fibonacci recursif naif
- Generer tous les sous-ensembles
- Probleme du voyageur de commerce (brute force)
```

---

### 5.4 Les pieges

| Piege | Exemple | Solution |
|-------|---------|----------|
| Confondre O(log n) et O(n) | "diviser par 2 c'est lineaire" | Diviser = logarithmique |
| Ignorer les constantes | "2n c'est O(2n)" | 2n = O(n), on ignore les constantes |
| Mauvais ordre de check | Verifier O(1) avant O(n) | Du plus specifique au plus general |
| Match partiel | "log" dans "catalog" | Utiliser des mots complets |

---

## SECTION 6 : RECAPITULATIF DES PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Ordre de verification | Mauvaise classification | Exponential -> Constant |
| 2 | Keywords partiels | Faux positifs | Mots complets ou regex |
| 3 | Oubli de complexite | Erreur pour certains inputs | Couvrir tous les cas |
| 4 | Comparaison inversee | Resultat inverse | Verifier le sens |

---

## SECTION 7 : QCM

### Question 1 (2 points)
Quelle est la complexite de l'acces a un element par index dans un tableau?

- A) O(n)
- B) O(log n)
- C) O(1)
- D) O(n^2)

**Reponse : C** - L'acces par index est direct et instantane.

### Question 2 (3 points)
Quelle complexite est meilleure: O(n log n) ou O(n^2)?

- A) O(n^2)
- B) O(n log n)
- C) Elles sont equivalentes
- D) Ca depend de n

**Reponse : B** - O(n log n) croit plus lentement que O(n^2).

### Question 3 (3 points)
Pour n=1000, combien de fois O(n^2) est-il plus lent que O(n)?

- A) 2 fois
- B) 10 fois
- C) 100 fois
- D) 1000 fois

**Reponse : D** - O(n^2)/O(n) = n = 1000.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.14 |
| **Nom** | complexity_analyzer |
| **Difficulte** | 2/10 |
| **Duree** | 30 min |
| **XP Base** | 60 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Big O, complexite algorithmique |

---

*Document genere selon HACKBRAIN v5.5.2*
