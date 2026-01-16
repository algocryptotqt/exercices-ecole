# Exercice D.17 : linked_list

**Module :**
D — Algorithmique

**Concept :**
17 — Listes chainees

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Classes Python
- Notion de pointeurs/references
- Complexite (ex14)

**Domaines :**
Algo, DataStruct

**Duree estimee :**
45 min

**XP Base :**
80

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `linked_list.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | Toutes les fonctions built-in standard |

---

### 1.2 Consigne

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une liste chainee simple et une liste doublement chainee avec leurs operations de base.

**Entree :**

```python
class Node:
    """Noeud pour liste simplement chainee"""
    def __init__(self, value):
        self.value = value
        self.next = None

class DoublyNode:
    """Noeud pour liste doublement chainee"""
    def __init__(self, value):
        self.value = value
        self.next = None
        self.prev = None

class SinglyLinkedList:
    """Liste simplement chainee"""
    def __init__(self):
        self.head = None
        self.size = 0

    def insert_front(self, value) -> None: pass
    def insert_back(self, value) -> None: pass
    def insert_at(self, index: int, value) -> bool: pass
    def delete_front(self) -> any: pass
    def delete_back(self) -> any: pass
    def delete_at(self, index: int) -> any: pass
    def search(self, value) -> int: pass
    def get(self, index: int) -> any: pass

class DoublyLinkedList:
    """Liste doublement chainee"""
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def insert_front(self, value) -> None: pass
    def insert_back(self, value) -> None: pass
    def delete_front(self) -> any: pass
    def delete_back(self) -> any: pass
```

**Exemples :**

| Operation | Liste avant | Liste apres | Retour |
|-----------|-------------|-------------|--------|
| insert_front(1) | [] | [1] | - |
| insert_front(2) | [1] | [2,1] | - |
| insert_back(3) | [2,1] | [2,1,3] | - |
| delete_front() | [2,1,3] | [1,3] | 2 |
| delete_back() | [1,3] | [1] | 3 |
| search(1) | [1] | [1] | 0 |

---

### 1.3 Prototype

```python
class Node:
    def __init__(self, value):
        self.value = value
        self.next = None

class DoublyNode:
    def __init__(self, value):
        self.value = value
        self.next = None
        self.prev = None

class SinglyLinkedList:
    def __init__(self):
        self.head = None
        self.size = 0

    def insert_front(self, value) -> None:
        """Insere au debut - O(1)"""
        pass

    def insert_back(self, value) -> None:
        """Insere a la fin - O(n)"""
        pass

    def insert_at(self, index: int, value) -> bool:
        """Insere a une position - O(n)"""
        pass

    def delete_front(self) -> any:
        """Supprime au debut - O(1)"""
        pass

    def delete_back(self) -> any:
        """Supprime a la fin - O(n)"""
        pass

    def delete_at(self, index: int) -> any:
        """Supprime a une position - O(n)"""
        pass

    def search(self, value) -> int:
        """Recherche un element - O(n)"""
        pass

    def get(self, index: int) -> any:
        """Acces par index - O(n)"""
        pass

    def __len__(self) -> int:
        return self.size

    def to_list(self) -> list:
        """Convertit en liste Python"""
        pass

class DoublyLinkedList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def insert_front(self, value) -> None:
        """Insere au debut - O(1)"""
        pass

    def insert_back(self, value) -> None:
        """Insere a la fin - O(1)"""
        pass

    def delete_front(self) -> any:
        """Supprime au debut - O(1)"""
        pass

    def delete_back(self) -> any:
        """Supprime a la fin - O(1)"""
        pass

    def __len__(self) -> int:
        return self.size
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Liste chainee vs Tableau**

| Operation | Tableau | Liste chainee simple | Liste doublement chainee |
|-----------|---------|---------------------|-------------------------|
| Acces index | O(1) | O(n) | O(n) |
| Insert debut | O(n) | O(1) | O(1) |
| Insert fin | O(1)* | O(n) | O(1) |
| Delete debut | O(n) | O(1) | O(1) |
| Delete fin | O(1) | O(n) | O(1) |
| Recherche | O(n) | O(n) | O(n) |

*O(1) amorti pour tableau dynamique

**Ou sont utilisees les listes chainees?**

- Implementation de piles et files
- Undo/Redo dans les editeurs
- Gestion de la memoire (free lists)
- Playlists musicales
- Navigation historique des navigateurs

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Systems Programmer** | Allocateurs memoire, gestion des processus |
| **Game Developer** | Gestion des entites, particle systems |
| **Database Engineer** | Index, structures de donnees internes |
| **Embedded Developer** | Structures avec allocation dynamique limitee |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python linked_list.py

>>> lst = SinglyLinkedList()
>>> lst.insert_front(3)
>>> lst.insert_front(2)
>>> lst.insert_front(1)
>>> lst.to_list()
[1, 2, 3]

>>> lst.insert_back(4)
>>> lst.to_list()
[1, 2, 3, 4]

>>> lst.delete_front()
1
>>> lst.to_list()
[2, 3, 4]

>>> lst.search(3)
1

>>> lst.get(1)
3

>>> dlst = DoublyLinkedList()
>>> dlst.insert_back(1)
>>> dlst.insert_back(2)
>>> dlst.insert_front(0)
>>> dlst.delete_back()
2
>>> len(dlst)
2
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | insert_front_empty | insert(1) on [] | [1] | 10 | Insert |
| 2 | insert_front_multi | insert(1,2,3) | [3,2,1] | 10 | Insert |
| 3 | insert_back | insert_back(1,2,3) | [1,2,3] | 10 | Insert |
| 4 | insert_at_middle | insert_at(1, x) | correct | 10 | Insert |
| 5 | delete_front | delete from [1,2,3] | [2,3], ret 1 | 10 | Delete |
| 6 | delete_back | delete from [1,2,3] | [1,2], ret 3 | 10 | Delete |
| 7 | delete_empty | delete from [] | None | 5 | Edge |
| 8 | search_found | search(2) in [1,2,3] | 1 | 10 | Search |
| 9 | search_not_found | search(5) in [1,2,3] | -1 | 5 | Search |
| 10 | get_valid | get(1) in [1,2,3] | 2 | 10 | Access |
| 11 | doubly_insert_back_O1 | insert_back | O(1) | 10 | Doubly |

**Total : 100 points**

---

### 4.2 Tests unitaires

```python
import unittest
from linked_list import Node, DoublyNode, SinglyLinkedList, DoublyLinkedList

class TestSinglyLinkedList(unittest.TestCase):

    def test_insert_front(self):
        lst = SinglyLinkedList()
        lst.insert_front(1)
        lst.insert_front(2)
        lst.insert_front(3)
        self.assertEqual(lst.to_list(), [3, 2, 1])

    def test_insert_back(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        lst.insert_back(3)
        self.assertEqual(lst.to_list(), [1, 2, 3])

    def test_insert_at(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(3)
        lst.insert_at(1, 2)
        self.assertEqual(lst.to_list(), [1, 2, 3])

    def test_delete_front(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        lst.insert_back(3)
        self.assertEqual(lst.delete_front(), 1)
        self.assertEqual(lst.to_list(), [2, 3])

    def test_delete_back(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        lst.insert_back(3)
        self.assertEqual(lst.delete_back(), 3)
        self.assertEqual(lst.to_list(), [1, 2])

    def test_delete_empty(self):
        lst = SinglyLinkedList()
        self.assertIsNone(lst.delete_front())

    def test_search(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        lst.insert_back(3)
        self.assertEqual(lst.search(2), 1)
        self.assertEqual(lst.search(5), -1)

    def test_get(self):
        lst = SinglyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        lst.insert_back(3)
        self.assertEqual(lst.get(1), 2)
        self.assertIsNone(lst.get(10))

class TestDoublyLinkedList(unittest.TestCase):

    def test_insert_front(self):
        lst = DoublyLinkedList()
        lst.insert_front(1)
        lst.insert_front(2)
        self.assertEqual(lst.head.value, 2)
        self.assertEqual(lst.tail.value, 1)

    def test_insert_back(self):
        lst = DoublyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        self.assertEqual(lst.head.value, 1)
        self.assertEqual(lst.tail.value, 2)

    def test_delete_front(self):
        lst = DoublyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        self.assertEqual(lst.delete_front(), 1)
        self.assertEqual(lst.head.value, 2)

    def test_delete_back(self):
        lst = DoublyLinkedList()
        lst.insert_back(1)
        lst.insert_back(2)
        self.assertEqual(lst.delete_back(), 2)
        self.assertEqual(lst.tail.value, 1)

if __name__ == '__main__':
    unittest.main()
```

---

### 4.3 Solution de reference

```python
class Node:
    """Noeud pour liste simplement chainee"""
    def __init__(self, value):
        self.value = value
        self.next = None


class DoublyNode:
    """Noeud pour liste doublement chainee"""
    def __init__(self, value):
        self.value = value
        self.next = None
        self.prev = None


class SinglyLinkedList:
    """Liste simplement chainee"""

    def __init__(self):
        self.head = None
        self.size = 0

    def insert_front(self, value) -> None:
        """Insere au debut - O(1)"""
        new_node = Node(value)
        new_node.next = self.head
        self.head = new_node
        self.size += 1

    def insert_back(self, value) -> None:
        """Insere a la fin - O(n)"""
        new_node = Node(value)
        if self.head is None:
            self.head = new_node
        else:
            current = self.head
            while current.next is not None:
                current = current.next
            current.next = new_node
        self.size += 1

    def insert_at(self, index: int, value) -> bool:
        """Insere a une position - O(n)"""
        if index < 0 or index > self.size:
            return False

        if index == 0:
            self.insert_front(value)
            return True

        new_node = Node(value)
        current = self.head
        for _ in range(index - 1):
            current = current.next

        new_node.next = current.next
        current.next = new_node
        self.size += 1
        return True

    def delete_front(self) -> any:
        """Supprime au debut - O(1)"""
        if self.head is None:
            return None

        value = self.head.value
        self.head = self.head.next
        self.size -= 1
        return value

    def delete_back(self) -> any:
        """Supprime a la fin - O(n)"""
        if self.head is None:
            return None

        if self.head.next is None:
            value = self.head.value
            self.head = None
            self.size -= 1
            return value

        current = self.head
        while current.next.next is not None:
            current = current.next

        value = current.next.value
        current.next = None
        self.size -= 1
        return value

    def delete_at(self, index: int) -> any:
        """Supprime a une position - O(n)"""
        if index < 0 or index >= self.size:
            return None

        if index == 0:
            return self.delete_front()

        current = self.head
        for _ in range(index - 1):
            current = current.next

        value = current.next.value
        current.next = current.next.next
        self.size -= 1
        return value

    def search(self, value) -> int:
        """Recherche un element - O(n)"""
        current = self.head
        index = 0
        while current is not None:
            if current.value == value:
                return index
            current = current.next
            index += 1
        return -1

    def get(self, index: int) -> any:
        """Acces par index - O(n)"""
        if index < 0 or index >= self.size:
            return None

        current = self.head
        for _ in range(index):
            current = current.next
        return current.value

    def __len__(self) -> int:
        return self.size

    def to_list(self) -> list:
        """Convertit en liste Python"""
        result = []
        current = self.head
        while current is not None:
            result.append(current.value)
            current = current.next
        return result


class DoublyLinkedList:
    """Liste doublement chainee"""

    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def insert_front(self, value) -> None:
        """Insere au debut - O(1)"""
        new_node = DoublyNode(value)
        if self.head is None:
            self.head = new_node
            self.tail = new_node
        else:
            new_node.next = self.head
            self.head.prev = new_node
            self.head = new_node
        self.size += 1

    def insert_back(self, value) -> None:
        """Insere a la fin - O(1)"""
        new_node = DoublyNode(value)
        if self.tail is None:
            self.head = new_node
            self.tail = new_node
        else:
            new_node.prev = self.tail
            self.tail.next = new_node
            self.tail = new_node
        self.size += 1

    def delete_front(self) -> any:
        """Supprime au debut - O(1)"""
        if self.head is None:
            return None

        value = self.head.value
        self.head = self.head.next

        if self.head is None:
            self.tail = None
        else:
            self.head.prev = None

        self.size -= 1
        return value

    def delete_back(self) -> any:
        """Supprime a la fin - O(1)"""
        if self.tail is None:
            return None

        value = self.tail.value
        self.tail = self.tail.prev

        if self.tail is None:
            self.head = None
        else:
            self.tail.next = None

        self.size -= 1
        return value

    def __len__(self) -> int:
        return self.size
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Pointer) : Oublie de mettre a jour head**

```python
# Mutant A: Ne met pas a jour head
def insert_front(self, value) -> None:
    new_node = Node(value)
    new_node.next = self.head
    # ERREUR: self.head = new_node manquant
    self.size += 1
```
**Pourquoi faux :** head reste None, la liste semble toujours vide.

**Mutant B (Link) : Oublie de lier le nouveau noeud**

```python
# Mutant B: Oublie de lier
def insert_front(self, value) -> None:
    new_node = Node(value)
    # ERREUR: new_node.next = self.head manquant
    self.head = new_node
    self.size += 1
```
**Pourquoi faux :** On perd l'ancien head et tout ce qui suit.

**Mutant C (Size) : Oublie d'incrementer size**

```python
# Mutant C: size pas mis a jour
def insert_front(self, value) -> None:
    new_node = Node(value)
    new_node.next = self.head
    self.head = new_node
    # ERREUR: self.size += 1 manquant
```
**Pourquoi faux :** len() retourne toujours 0.

**Mutant D (Delete) : Ne gere pas le cas single element**

```python
# Mutant D: delete_back sur un seul element
def delete_back(self) -> any:
    if self.head is None:
        return None
    current = self.head
    while current.next.next is not None:  # ERREUR: crash si un seul element
        current = current.next
    value = current.next.value
    current.next = None
    return value
```
**Pourquoi faux :** NoneType has no attribute 'next' si un seul element.

**Mutant E (Doubly) : Oublie prev dans doubly**

```python
# Mutant E: Oublie de mettre a jour prev
def insert_back(self, value) -> None:
    new_node = DoublyNode(value)
    if self.tail is None:
        self.head = new_node
        self.tail = new_node
    else:
        # ERREUR: new_node.prev = self.tail manquant
        self.tail.next = new_node
        self.tail = new_node
    self.size += 1
```
**Pourquoi faux :** Parcours en arriere impossible.

---

## SECTION 5 : COMPRENDRE

### 5.1 Structure d'un noeud

```
Liste simplement chainee:
+-------+------+    +-------+------+    +-------+------+
| value | next |--->| value | next |--->| value | next |---> None
+-------+------+    +-------+------+    +-------+------+
    ^
    |
   head

Liste doublement chainee:
None <---+------+-------+------+    +------+-------+------+    +------+-------+------+---> None
         | prev | value | next |--->| prev | value | next |--->| prev | value | next |
         +------+-------+------+<---+------+-------+------+<---+------+-------+------+
            ^                                                              ^
            |                                                              |
          head                                                           tail
```

### 5.2 Operations

```
Insert front (simplement chainee):
1. Creer nouveau noeud
2. new_node.next = head
3. head = new_node

Delete front (simplement chainee):
1. Sauvegarder head.value
2. head = head.next
3. Retourner la valeur

Insert back (doublement chainee) - O(1) grace a tail:
1. Creer nouveau noeud
2. new_node.prev = tail
3. tail.next = new_node
4. tail = new_node
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier de lier les noeuds | Perte de donnees | Verifier tous les pointeurs |
| 2 | Ne pas gerer liste vide | NullPointerException | if head is None |
| 3 | Oublier de maj size | len() incorrect | Incrementer/decrementer |
| 4 | Cas single element | Crash sur delete | Verifier head.next |

---

## SECTION 7 : QCM

### Question 1 (2 points)
Quelle est la complexite de delete_back() pour une liste simplement chainee?

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n^2)

**Reponse : C** - Il faut parcourir jusqu'a l'avant-dernier element.

### Question 2 (3 points)
Pourquoi une liste doublement chainee peut faire delete_back() en O(1)?

- A) Elle est triee
- B) Elle a un pointeur tail
- C) Elle utilise plus de memoire
- D) Elle est plus rapide

**Reponse : B** - Le pointeur tail permet un acces direct a la fin.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.17 |
| **Nom** | linked_list |
| **Difficulte** | 3/10 |
| **Duree** | 45 min |
| **XP Base** | 80 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Noeuds, pointeurs, simplement/doublement chainee |

---

*Document genere selon HACKBRAIN v5.5.2*
