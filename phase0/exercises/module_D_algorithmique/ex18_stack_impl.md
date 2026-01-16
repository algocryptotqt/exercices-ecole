# Exercice D.18 : stack_impl

**Module :**
D — Algorithmique

**Concept :**
18 — Implementation d'une pile (Stack)

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Classes Python
- Operations sur tableaux ou listes chainees

**Domaines :**
Algo, DataStruct

**Duree estimee :**
25 min

**XP Base :**
50

**Complexite :**
T1 O(1) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `stack_impl.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | list.append, list.pop (pour version tableau) |

---

### 1.2 Consigne

#### Section Culture : "LIFO - Last In, First Out"

Imagine une pile d'assiettes dans un restaurant. La derniere assiette posee est la premiere retiree. C'est le principe LIFO (Last In, First Out).

Les piles sont partout en informatique:
- La pile d'appels de fonctions
- Le bouton "Annuler" (Undo)
- L'evaluation d'expressions mathematiques
- La navigation "retour" dans un navigateur

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une pile avec les operations fondamentales : push, pop, peek, isEmpty.

**Entree :**

```python
class Stack:
    def __init__(self):
        pass

    def push(self, value) -> None:
        """Ajoute un element au sommet - O(1)"""
        pass

    def pop(self) -> any:
        """Retire et retourne l'element au sommet - O(1)"""
        pass

    def peek(self) -> any:
        """Retourne l'element au sommet sans le retirer - O(1)"""
        pass

    def is_empty(self) -> bool:
        """Verifie si la pile est vide - O(1)"""
        pass

    def size(self) -> int:
        """Retourne le nombre d'elements - O(1)"""
        pass
```

**Exemples :**

| Operation | Pile avant | Pile apres | Retour |
|-----------|------------|------------|--------|
| push(1) | [] | [1] | - |
| push(2) | [1] | [1,2] | - |
| push(3) | [1,2] | [1,2,3] | - |
| peek() | [1,2,3] | [1,2,3] | 3 |
| pop() | [1,2,3] | [1,2] | 3 |
| pop() | [1,2] | [1] | 2 |
| is_empty() | [1] | [1] | False |
| pop() | [1] | [] | 1 |
| is_empty() | [] | [] | True |

---

### 1.3 Prototype

```python
class Stack:
    """
    Implementation d'une pile (LIFO).
    Toutes les operations sont O(1).
    """

    def __init__(self):
        """Initialise une pile vide."""
        pass

    def push(self, value) -> None:
        """
        Ajoute un element au sommet de la pile.

        Args:
            value: L'element a ajouter

        Complexity: O(1)
        """
        pass

    def pop(self) -> any:
        """
        Retire et retourne l'element au sommet.

        Returns:
            L'element au sommet, ou None si vide

        Complexity: O(1)
        """
        pass

    def peek(self) -> any:
        """
        Retourne l'element au sommet sans le retirer.

        Returns:
            L'element au sommet, ou None si vide

        Complexity: O(1)
        """
        pass

    def is_empty(self) -> bool:
        """
        Verifie si la pile est vide.

        Returns:
            True si vide, False sinon

        Complexity: O(1)
        """
        pass

    def size(self) -> int:
        """
        Retourne le nombre d'elements dans la pile.

        Returns:
            Le nombre d'elements

        Complexity: O(1)
        """
        pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**La pile d'appels (Call Stack)**

Quand tu appelles une fonction, son contexte (variables locales, adresse de retour) est empile. Quand la fonction termine, il est depile. C'est pourquoi une recursion trop profonde cause un "Stack Overflow" !

```python
def recursion(n):
    if n == 0:
        return
    recursion(n - 1)  # Empile un nouveau contexte
    # Depile quand on revient ici

recursion(10000)  # Stack overflow !
```

**Notation polonaise inverse (RPN)**

Les calculatrices HP utilisent une pile pour evaluer les expressions:
- `3 4 +` signifie `3 + 4`
- Push 3, Push 4, Pop 4 et 3, calcule 3+4=7, Push 7

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Compiler Engineer** | Pile d'appels, evaluation d'expressions |
| **Web Developer** | Navigation historique, undo/redo |
| **Game Developer** | Systemes de menus, etats de jeu |
| **Text Editor Developer** | Fonctionnalite undo/redo |
| **Algorithm Engineer** | Parcours en profondeur (DFS) |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python stack_impl.py

>>> s = Stack()
>>> s.is_empty()
True

>>> s.push(10)
>>> s.push(20)
>>> s.push(30)

>>> s.peek()
30

>>> s.size()
3

>>> s.pop()
30

>>> s.pop()
20

>>> s.peek()
10

>>> s.is_empty()
False

>>> s.pop()
10

>>> s.is_empty()
True

>>> s.pop()
None
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | empty_stack | new Stack | is_empty = True | 10 | Basic |
| 2 | push_one | push(1) | size = 1 | 10 | Push |
| 3 | push_many | push(1,2,3) | size = 3 | 10 | Push |
| 4 | pop_order | push(1,2,3), pop | 3,2,1 (LIFO) | 15 | LIFO |
| 5 | pop_empty | pop on [] | None | 10 | Edge |
| 6 | peek_no_remove | peek, size | same size | 10 | Peek |
| 7 | peek_empty | peek on [] | None | 10 | Edge |
| 8 | is_empty_after_ops | push,pop | True | 10 | State |
| 9 | size_accurate | various ops | correct size | 15 | Size |

**Total : 100 points**

---

### 4.2 Tests unitaires

```python
import unittest
from stack_impl import Stack

class TestStack(unittest.TestCase):

    def test_empty_stack(self):
        s = Stack()
        self.assertTrue(s.is_empty())
        self.assertEqual(s.size(), 0)

    def test_push_single(self):
        s = Stack()
        s.push(42)
        self.assertFalse(s.is_empty())
        self.assertEqual(s.size(), 1)
        self.assertEqual(s.peek(), 42)

    def test_push_multiple(self):
        s = Stack()
        s.push(1)
        s.push(2)
        s.push(3)
        self.assertEqual(s.size(), 3)
        self.assertEqual(s.peek(), 3)

    def test_pop_lifo_order(self):
        s = Stack()
        s.push(1)
        s.push(2)
        s.push(3)
        self.assertEqual(s.pop(), 3)
        self.assertEqual(s.pop(), 2)
        self.assertEqual(s.pop(), 1)

    def test_pop_empty(self):
        s = Stack()
        self.assertIsNone(s.pop())

    def test_peek_no_remove(self):
        s = Stack()
        s.push(42)
        self.assertEqual(s.peek(), 42)
        self.assertEqual(s.peek(), 42)
        self.assertEqual(s.size(), 1)

    def test_peek_empty(self):
        s = Stack()
        self.assertIsNone(s.peek())

    def test_is_empty_after_operations(self):
        s = Stack()
        s.push(1)
        s.push(2)
        s.pop()
        s.pop()
        self.assertTrue(s.is_empty())

    def test_size_tracking(self):
        s = Stack()
        self.assertEqual(s.size(), 0)
        s.push(1)
        self.assertEqual(s.size(), 1)
        s.push(2)
        self.assertEqual(s.size(), 2)
        s.pop()
        self.assertEqual(s.size(), 1)

if __name__ == '__main__':
    unittest.main()
```

---

### 4.3 Solution de reference

```python
class Stack:
    """
    Implementation d'une pile (LIFO) utilisant une liste Python.
    Toutes les operations sont O(1).
    """

    def __init__(self):
        """Initialise une pile vide."""
        self._data = []

    def push(self, value) -> None:
        """
        Ajoute un element au sommet de la pile.
        Complexity: O(1) amorti
        """
        self._data.append(value)

    def pop(self) -> any:
        """
        Retire et retourne l'element au sommet.
        Complexity: O(1)
        """
        if self.is_empty():
            return None
        return self._data.pop()

    def peek(self) -> any:
        """
        Retourne l'element au sommet sans le retirer.
        Complexity: O(1)
        """
        if self.is_empty():
            return None
        return self._data[-1]

    def is_empty(self) -> bool:
        """
        Verifie si la pile est vide.
        Complexity: O(1)
        """
        return len(self._data) == 0

    def size(self) -> int:
        """
        Retourne le nombre d'elements dans la pile.
        Complexity: O(1)
        """
        return len(self._data)

    def __len__(self) -> int:
        """Permet d'utiliser len(stack)."""
        return self.size()

    def __repr__(self) -> str:
        """Representation textuelle de la pile."""
        return f"Stack({self._data})"
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Implementation avec liste chainee**

```python
class Node:
    def __init__(self, value):
        self.value = value
        self.next = None

class Stack:
    def __init__(self):
        self._top = None
        self._size = 0

    def push(self, value) -> None:
        new_node = Node(value)
        new_node.next = self._top
        self._top = new_node
        self._size += 1

    def pop(self) -> any:
        if self._top is None:
            return None
        value = self._top.value
        self._top = self._top.next
        self._size -= 1
        return value

    def peek(self) -> any:
        if self._top is None:
            return None
        return self._top.value

    def is_empty(self) -> bool:
        return self._top is None

    def size(self) -> int:
        return self._size
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Order) : FIFO au lieu de LIFO**

```python
# Mutant A: Utilise pop(0) - c'est une queue !
def pop(self) -> any:
    if self.is_empty():
        return None
    return self._data.pop(0)  # ERREUR: retire au debut = FIFO
```
**Pourquoi faux :** pop(0) retire le premier element, pas le dernier. C'est FIFO, pas LIFO.

**Mutant B (Peek) : Peek modifie la pile**

```python
# Mutant B: Peek utilise pop
def peek(self) -> any:
    return self.pop()  # ERREUR: modifie la pile
```
**Pourquoi faux :** peek ne doit pas modifier la pile, juste regarder.

**Mutant C (Empty) : is_empty incorrect**

```python
# Mutant C: Logique inversee
def is_empty(self) -> bool:
    return len(self._data) != 0  # ERREUR: inversee
```
**Pourquoi faux :** Retourne True quand non vide et False quand vide.

**Mutant D (Size) : Size ne se met pas a jour**

```python
# Mutant D: Size calcule a chaque fois mais mal
def __init__(self):
    self._data = []
    self._size = 0

def push(self, value) -> None:
    self._data.append(value)
    # ERREUR: self._size += 1 manquant

def size(self) -> int:
    return self._size  # Toujours 0
```
**Pourquoi faux :** size retourne toujours 0.

**Mutant E (Pop) : Pop ne verifie pas si vide**

```python
# Mutant E: Pas de verification
def pop(self) -> any:
    return self._data.pop()  # ERREUR: IndexError si vide
```
**Pourquoi faux :** Crash avec IndexError si on pop une pile vide.

---

## SECTION 5 : COMPRENDRE

### 5.1 Le principe LIFO

```
LIFO = Last In, First Out

Push 1:  |   |      Push 2:  |   |      Push 3:  | 3 |
         | 1 |               | 2 |               | 2 |
         +---+               | 1 |               | 1 |
                             +---+               +---+

Pop:     | 2 |  -> 3    Pop:     | 1 |  -> 2    Pop:     |   |  -> 1
         | 1 |                   +---+                   +---+
         +---+
```

### 5.2 Complexites

```
+------------+-------------+
| Operation  | Complexite  |
+------------+-------------+
| push()     | O(1)*       |
| pop()      | O(1)        |
| peek()     | O(1)        |
| is_empty() | O(1)        |
| size()     | O(1)        |
+------------+-------------+
* O(1) amorti pour implementation tableau
```

### 5.3 Applications

```python
# Verification de parentheses equilibrees
def is_balanced(s: str) -> bool:
    stack = Stack()
    pairs = {')': '(', ']': '[', '}': '{'}

    for char in s:
        if char in '([{':
            stack.push(char)
        elif char in ')]}':
            if stack.is_empty() or stack.pop() != pairs[char]:
                return False

    return stack.is_empty()

# Test
print(is_balanced("([{}])"))  # True
print(is_balanced("([)]"))    # False
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Pop sans verification | IndexError | Verifier is_empty() |
| 2 | Peek qui modifie | Effet de bord | Ne pas utiliser pop |
| 3 | FIFO au lieu de LIFO | Mauvais ordre | append + pop() |
| 4 | Oublier de maj size | size() incorrect | Incrementer/decrementer |

---

## SECTION 7 : QCM

### Question 1 (2 points)
Que signifie LIFO?

- A) Last In First Out
- B) Linked In First Out
- C) List In File Out
- D) Last Index First Output

**Reponse : A** - Le dernier entre est le premier a sortir.

### Question 2 (3 points)
Quelle est la complexite de peek()?

- A) O(n)
- B) O(log n)
- C) O(1)
- D) O(n^2)

**Reponse : C** - On accede directement au sommet.

### Question 3 (3 points)
Apres push(1), push(2), push(3), pop(), que retourne peek()?

- A) 1
- B) 2
- C) 3
- D) None

**Reponse : B** - Apres pop() qui retire 3, le sommet est 2.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.18 |
| **Nom** | stack_impl |
| **Difficulte** | 2/10 |
| **Duree** | 25 min |
| **XP Base** | 50 |
| **Langage** | Python 3.14 |
| **Concepts cles** | LIFO, push, pop, peek, isEmpty |

---

*Document genere selon HACKBRAIN v5.5.2*
