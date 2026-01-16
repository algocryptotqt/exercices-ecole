# Exercice D.16 : array_operations

**Module :**
D — Algorithmique

**Concept :**
16 — Operations sur les tableaux

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
- Notion de complexite (ex14)

**Domaines :**
Algo, DataStruct

**Duree estimee :**
30 min

**XP Base :**
60

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `array_operations.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | Aucune methode de liste sauf len() |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | list.append, list.insert, list.remove, list.pop, list.index |

---

### 1.2 Consigne

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer les operations fondamentales sur un tableau (simule par une liste Python) sans utiliser les methodes built-in de liste.

**Entree :**

```python
def array_access(arr: list, index: int) -> any:
    """Acces a un element par index - O(1)"""
    pass

def array_search(arr: list, value: any) -> int:
    """Recherche lineaire - O(n), retourne l'index ou -1"""
    pass

def array_insert(arr: list, index: int, value: any) -> list:
    """Insertion a une position - O(n)"""
    pass

def array_delete(arr: list, index: int) -> list:
    """Suppression a une position - O(n)"""
    pass

def array_resize(arr: list, new_size: int, fill_value: any = None) -> list:
    """Redimensionne le tableau - O(n)"""
    pass
```

**Exemples :**

| Operation | Input | Output | Complexite |
|-----------|-------|--------|------------|
| access | ([1,2,3], 1) | 2 | O(1) |
| search | ([1,2,3], 2) | 1 | O(n) |
| search | ([1,2,3], 5) | -1 | O(n) |
| insert | ([1,3], 1, 2) | [1,2,3] | O(n) |
| delete | ([1,2,3], 1) | [1,3] | O(n) |
| resize | ([1,2], 4, 0) | [1,2,0,0] | O(n) |

---

### 1.3 Prototype

```python
def array_access(arr: list, index: int) -> any:
    """
    Accede a l'element a l'index donne.

    Args:
        arr: Le tableau
        index: L'index de l'element

    Returns:
        L'element a l'index, ou None si hors limites

    Complexity: O(1)
    """
    pass

def array_search(arr: list, value: any) -> int:
    """
    Recherche une valeur dans le tableau.

    Args:
        arr: Le tableau
        value: La valeur a chercher

    Returns:
        L'index de la premiere occurrence, ou -1 si non trouve

    Complexity: O(n)
    """
    pass

def array_insert(arr: list, index: int, value: any) -> list:
    """
    Insere une valeur a l'index donne.

    Args:
        arr: Le tableau original
        index: La position d'insertion
        value: La valeur a inserer

    Returns:
        Un nouveau tableau avec l'element insere

    Complexity: O(n)
    """
    pass

def array_delete(arr: list, index: int) -> list:
    """
    Supprime l'element a l'index donne.

    Args:
        arr: Le tableau original
        index: La position de suppression

    Returns:
        Un nouveau tableau sans l'element

    Complexity: O(n)
    """
    pass

def array_resize(arr: list, new_size: int, fill_value: any = None) -> list:
    """
    Redimensionne le tableau.

    Args:
        arr: Le tableau original
        new_size: La nouvelle taille
        fill_value: Valeur pour les nouveaux elements

    Returns:
        Un nouveau tableau de la taille specifiee

    Complexity: O(n)
    """
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi O(1) pour l'acces?**

Un tableau est stocke de maniere contigue en memoire. L'adresse de l'element i est:
```
adresse_base + i * taille_element
```
Un simple calcul arithmetique, donc O(1)!

**Pourquoi O(n) pour l'insertion?**

Inserer au milieu necessite de decaler tous les elements suivants. Dans le pire cas (insertion au debut), il faut decaler n elements.

```
Avant: [1, 2, 3, 4, 5]
              ↓ Inserer 9 a l'index 2
Apres: [1, 2, 9, 3, 4, 5]
              ← Tout decale
```

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Game Developer** | Tableaux de sprites, positions d'entites |
| **Data Scientist** | Manipulation de donnees tabulaires |
| **Systems Programmer** | Buffers de memoire |
| **Web Developer** | Manipulation du DOM (collections) |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python array_operations.py

>>> arr = [10, 20, 30, 40, 50]

>>> array_access(arr, 2)
30

>>> array_access(arr, 10)
None

>>> array_search(arr, 30)
2

>>> array_search(arr, 99)
-1

>>> array_insert(arr, 2, 25)
[10, 20, 25, 30, 40, 50]

>>> array_delete(arr, 2)
[10, 20, 40, 50]

>>> array_resize([1, 2, 3], 5, 0)
[1, 2, 3, 0, 0]

>>> array_resize([1, 2, 3, 4, 5], 3, 0)
[1, 2, 3]
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | access_valid | ([1,2,3], 1) | 2 | 10 | Access |
| 2 | access_first | ([1,2,3], 0) | 1 | 5 | Access |
| 3 | access_last | ([1,2,3], 2) | 3 | 5 | Access |
| 4 | access_out_of_bounds | ([1,2,3], 5) | None | 10 | Edge |
| 5 | search_found | ([1,2,3], 2) | 1 | 10 | Search |
| 6 | search_not_found | ([1,2,3], 5) | -1 | 10 | Search |
| 7 | insert_middle | ([1,3], 1, 2) | [1,2,3] | 10 | Insert |
| 8 | insert_start | ([2,3], 0, 1) | [1,2,3] | 10 | Insert |
| 9 | delete_middle | ([1,2,3], 1) | [1,3] | 10 | Delete |
| 10 | resize_grow | ([1,2], 4, 0) | [1,2,0,0] | 10 | Resize |
| 11 | resize_shrink | ([1,2,3,4], 2, 0) | [1,2] | 10 | Resize |

**Total : 100 points**

---

### 4.2 Tests unitaires

```python
import unittest
from array_operations import array_access, array_search, array_insert, array_delete, array_resize

class TestArrayOperations(unittest.TestCase):

    def test_access_valid(self):
        self.assertEqual(array_access([1, 2, 3], 1), 2)

    def test_access_out_of_bounds(self):
        self.assertIsNone(array_access([1, 2, 3], 5))
        self.assertIsNone(array_access([1, 2, 3], -1))

    def test_search_found(self):
        self.assertEqual(array_search([10, 20, 30], 20), 1)

    def test_search_not_found(self):
        self.assertEqual(array_search([10, 20, 30], 99), -1)

    def test_search_first_occurrence(self):
        self.assertEqual(array_search([1, 2, 2, 3], 2), 1)

    def test_insert_middle(self):
        self.assertEqual(array_insert([1, 3], 1, 2), [1, 2, 3])

    def test_insert_start(self):
        self.assertEqual(array_insert([2, 3], 0, 1), [1, 2, 3])

    def test_insert_end(self):
        self.assertEqual(array_insert([1, 2], 2, 3), [1, 2, 3])

    def test_delete_middle(self):
        self.assertEqual(array_delete([1, 2, 3], 1), [1, 3])

    def test_delete_start(self):
        self.assertEqual(array_delete([1, 2, 3], 0), [2, 3])

    def test_resize_grow(self):
        self.assertEqual(array_resize([1, 2], 4, 0), [1, 2, 0, 0])

    def test_resize_shrink(self):
        self.assertEqual(array_resize([1, 2, 3, 4], 2, 0), [1, 2])

if __name__ == '__main__':
    unittest.main()
```

---

### 4.3 Solution de reference

```python
def array_access(arr: list, index: int) -> any:
    """
    Accede a l'element a l'index donne.
    Complexity: O(1)
    """
    if index < 0 or index >= len(arr):
        return None
    return arr[index]


def array_search(arr: list, value: any) -> int:
    """
    Recherche une valeur dans le tableau.
    Complexity: O(n)
    """
    for i in range(len(arr)):
        if arr[i] == value:
            return i
    return -1


def array_insert(arr: list, index: int, value: any) -> list:
    """
    Insere une valeur a l'index donne.
    Complexity: O(n)
    """
    n = len(arr)
    # Clamp index to valid range
    if index < 0:
        index = 0
    if index > n:
        index = n

    # Create new array with one more element
    result = [None] * (n + 1)

    # Copy elements before insertion point
    for i in range(index):
        result[i] = arr[i]

    # Insert new element
    result[index] = value

    # Copy elements after insertion point
    for i in range(index, n):
        result[i + 1] = arr[i]

    return result


def array_delete(arr: list, index: int) -> list:
    """
    Supprime l'element a l'index donne.
    Complexity: O(n)
    """
    n = len(arr)
    if index < 0 or index >= n:
        return arr[:]  # Return copy if invalid index

    # Create new array with one less element
    result = [None] * (n - 1)

    # Copy elements before deletion point
    for i in range(index):
        result[i] = arr[i]

    # Copy elements after deletion point
    for i in range(index + 1, n):
        result[i - 1] = arr[i]

    return result


def array_resize(arr: list, new_size: int, fill_value: any = None) -> list:
    """
    Redimensionne le tableau.
    Complexity: O(n)
    """
    if new_size <= 0:
        return []

    result = [fill_value] * new_size

    # Copy existing elements (up to new_size)
    copy_count = min(len(arr), new_size)
    for i in range(copy_count):
        result[i] = arr[i]

    return result
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Off-by-one dans access**

```python
# Mutant A: Mauvaise verification des limites
def array_access(arr: list, index: int) -> any:
    if index < 0 or index > len(arr):  # ERREUR: > au lieu de >=
        return None
    return arr[index]  # IndexError quand index == len(arr)
```
**Pourquoi faux :** Pour arr de taille 3, index 3 passera la verification mais causera une erreur.

**Mutant B (Return) : Search retourne la valeur au lieu de l'index**

```python
# Mutant B: Retourne la valeur, pas l'index
def array_search(arr: list, value: any) -> int:
    for i in range(len(arr)):
        if arr[i] == value:
            return arr[i]  # ERREUR: retourne la valeur
    return -1
```
**Pourquoi faux :** Pour search([10, 20, 30], 20), retourne 20 au lieu de 1.

**Mutant C (Logic) : Insert ne decale pas correctement**

```python
# Mutant C: Oublie de decaler les elements
def array_insert(arr: list, index: int, value: any) -> list:
    result = arr[:]  # Copie
    result[index] = value  # ERREUR: ecrase au lieu d'inserer
    return result
```
**Pourquoi faux :** Pour insert([1,3], 1, 2), retourne [1,2] au lieu de [1,2,3].

**Mutant D (Size) : Delete ne reduit pas la taille**

```python
# Mutant D: Garde la meme taille avec None
def array_delete(arr: list, index: int) -> list:
    result = arr[:]
    result[index] = None  # ERREUR: met None au lieu de supprimer
    return result
```
**Pourquoi faux :** Pour delete([1,2,3], 1), retourne [1,None,3] au lieu de [1,3].

**Mutant E (Edge) : Resize ne gere pas le shrink**

```python
# Mutant E: Ne gere que l'agrandissement
def array_resize(arr: list, new_size: int, fill_value: any = None) -> list:
    if new_size > len(arr):
        result = arr[:]
        for _ in range(new_size - len(arr)):
            result = array_insert(result, len(result), fill_value)
        return result
    return arr  # ERREUR: retourne l'original si shrink
```
**Pourquoi faux :** Pour resize([1,2,3,4], 2, 0), retourne [1,2,3,4] au lieu de [1,2].

---

## SECTION 5 : COMPRENDRE

### 5.1 Complexites des operations sur tableaux

```
+------------------+---------------+----------------------------+
| Operation        | Complexite    | Explication                |
+------------------+---------------+----------------------------+
| Acces par index  | O(1)          | Calcul d'adresse direct    |
| Recherche        | O(n)          | Parcours sequentiel        |
| Insertion debut  | O(n)          | Decale tout                |
| Insertion fin    | O(1) amorti   | Si capacite suffisante     |
| Insertion milieu | O(n)          | Decale la moitie           |
| Suppression      | O(n)          | Decale pour combler        |
| Resize           | O(n)          | Copie tous les elements    |
+------------------+---------------+----------------------------+
```

### 5.2 Visualisation de l'insertion

```
Tableau initial: [10, 20, 30, 40, 50]
                   0   1   2   3   4

Inserer 25 a l'index 2:

Etape 1: Creer un nouveau tableau de taille n+1
         [  ,   ,   ,   ,   ,   ]
           0   1   2   3   4   5

Etape 2: Copier elements avant index 2
         [10, 20,   ,   ,   ,   ]

Etape 3: Inserer le nouvel element
         [10, 20, 25,   ,   ,   ]

Etape 4: Copier elements apres index 2
         [10, 20, 25, 30, 40, 50]
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Off-by-one | IndexError ou acces invalide | Utiliser < len, pas <= |
| 2 | Modifier l'original | Effets de bord inattendus | Toujours creer une copie |
| 3 | Oublier de decaler | Elements ecrases | Parcourir dans le bon sens |
| 4 | Index negatif | Comportement Python implicite | Verifier explicitement |

---

## SECTION 7 : QCM

### Question 1 (2 points)
Pourquoi l'acces par index est O(1)?

- A) Le tableau est trie
- B) Les elements sont contigus en memoire
- C) Python optimise automatiquement
- D) Le tableau est petit

**Reponse : B** - L'adresse se calcule par: base + index * taille.

### Question 2 (3 points)
Pourquoi l'insertion au debut est O(n)?

- A) Il faut rechercher l'element
- B) Il faut decaler tous les elements
- C) Il faut reallouer la memoire
- D) Il faut trier le tableau

**Reponse : B** - Tous les n elements doivent etre decales d'une position.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.16 |
| **Nom** | array_operations |
| **Difficulte** | 2/10 |
| **Duree** | 30 min |
| **XP Base** | 60 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Tableaux, acces O(1), insertion/deletion O(n) |

---

*Document genere selon HACKBRAIN v5.5.2*
