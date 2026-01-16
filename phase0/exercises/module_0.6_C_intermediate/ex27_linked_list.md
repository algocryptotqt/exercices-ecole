# Exercice 0.6.4-a : linked_list

**Module :**
0.6.4 — Liste Chainee Simple

**Concept :**
a-f — struct Node, Insert head, Insert tail, Delete, Search, Reverse

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
2 — Integration concepts

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc_basics), pointeurs

**Domaines :**
Structures, Algo, Mem

**Duree estimee :**
240 min

**XP Base :**
300

**Complexite :**
T2 O(n) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `linked_list.c`
- `linked_list.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `free()`, `printf()`

### 1.2 Consigne

Implementer une liste simplement chainee avec toutes les operations fondamentales.

**Ta mission :**

Creer une structure de liste chainee complete avec insertion, suppression, recherche et inversion.

**Structures :**
```c
typedef struct Node {
    int data;
    struct Node *next;
} Node;

typedef struct {
    Node *head;
    size_t size;
} LinkedList;
```

**Prototypes :**
```c
// Creation et destruction
LinkedList *list_create(void);
void list_destroy(LinkedList *list);

// Insertion
bool list_insert_head(LinkedList *list, int value);
bool list_insert_tail(LinkedList *list, int value);
bool list_insert_at(LinkedList *list, size_t index, int value);

// Suppression
bool list_delete_head(LinkedList *list);
bool list_delete_tail(LinkedList *list);
bool list_delete_at(LinkedList *list, size_t index);
bool list_delete_value(LinkedList *list, int value);

// Acces et recherche
int list_get(const LinkedList *list, size_t index, bool *success);
bool list_contains(const LinkedList *list, int value);
int list_index_of(const LinkedList *list, int value);

// Modification
bool list_set(LinkedList *list, size_t index, int value);

// Operations sur la liste
void list_reverse(LinkedList *list);
void list_print(const LinkedList *list);
size_t list_size(const LinkedList *list);
bool list_is_empty(const LinkedList *list);
void list_clear(LinkedList *list);
```

**Comportement :**
- `list_create` alloue et initialise une liste vide
- `list_destroy` libere tous les noeuds et la structure
- `list_insert_head` ajoute au debut en O(1)
- `list_insert_tail` ajoute a la fin en O(n)
- `list_insert_at` insere a l'index donne (0 = head)
- `list_delete_value` supprime la premiere occurrence
- `list_get` avec index invalide retourne 0 avec *success = false
- `list_index_of` retourne -1 si non trouve
- `list_reverse` inverse la liste sur place
- `list_print` affiche: [1, 2, 3] ou [] si vide

**Exemples :**
```
LinkedList *list = list_create();     // []
list_insert_head(list, 10);           // [10]
list_insert_tail(list, 30);           // [10, 30]
list_insert_at(list, 1, 20);          // [10, 20, 30]
list_get(list, 1, &ok);               // returns 20, ok=true
list_contains(list, 20);              // returns true
list_delete_head(list);               // [20, 30]
list_reverse(list);                   // [30, 20]
list_print(list);                     // "[30, 20]"
list_destroy(list);
```

**Contraintes :**
- Gerer le cas liste vide pour toutes les operations
- Gerer les index hors limites gracieusement
- Liberer toute la memoire correctement
- Ne pas avoir de memory leaks

### 1.3 Prototype

```c
// linked_list.h
#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stddef.h>
#include <stdbool.h>

typedef struct Node {
    int data;
    struct Node *next;
} Node;

typedef struct {
    Node *head;
    size_t size;
} LinkedList;

LinkedList *list_create(void);
void list_destroy(LinkedList *list);

bool list_insert_head(LinkedList *list, int value);
bool list_insert_tail(LinkedList *list, int value);
bool list_insert_at(LinkedList *list, size_t index, int value);

bool list_delete_head(LinkedList *list);
bool list_delete_tail(LinkedList *list);
bool list_delete_at(LinkedList *list, size_t index);
bool list_delete_value(LinkedList *list, int value);

int list_get(const LinkedList *list, size_t index, bool *success);
bool list_contains(const LinkedList *list, int value);
int list_index_of(const LinkedList *list, int value);

bool list_set(LinkedList *list, size_t index, int value);

void list_reverse(LinkedList *list);
void list_print(const LinkedList *list);
size_t list_size(const LinkedList *list);
bool list_is_empty(const LinkedList *list);
void list_clear(LinkedList *list);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Liste vs Tableau

| Operation | Liste chainee | Tableau dynamique |
|-----------|---------------|-------------------|
| Insert head | O(1) | O(n) |
| Insert tail | O(n)* | O(1) amorti |
| Access [i] | O(n) | O(1) |
| Search | O(n) | O(n) |
| Delete head | O(1) | O(n) |

*O(1) avec pointeur tail

### 2.2 Pourquoi les listes chainees ?

- **Insertion/suppression rapide** au debut
- **Pas de reallocation** comme les tableaux
- **Taille flexible** sans pre-allocation
- Base pour stacks, queues, etc.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Kernel Developer**

Les listes chainees sont omnipresentes dans Linux:
- Liste des processus (task_struct)
- File d'attente d'I/O
- Gestion des pages memoire

**Metier : Game Developer**

Utilisation courante:
- Liste d'entites actives
- Systeme de particules
- Undo/redo actions

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_list test_main.c linked_list.c
$ ./test_list
Creating empty list...
  list_is_empty: true
  list_size: 0

Inserting 10, 20, 30 at head...
  list_print: [30, 20, 10]
  list_size: 3

Inserting 40 at tail...
  list_print: [30, 20, 10, 40]

Inserting 25 at index 2...
  list_print: [30, 20, 25, 10, 40]

Testing get...
  list_get(0): 30
  list_get(2): 25
  list_get(10): failed (out of bounds)

Testing search...
  list_contains(25): true
  list_contains(99): false
  list_index_of(10): 3

Reversing list...
  list_print: [40, 10, 25, 20, 30]

Deleting head...
  list_print: [10, 25, 20, 30]

Deleting value 25...
  list_print: [10, 20, 30]

Clearing list...
  list_is_empty: true

All tests passed!
$ valgrind --leak-check=full ./test_list
==12345== All heap blocks were freed -- no leaks are possible
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer une liste doublement chainee.

```c
typedef struct DNode {
    int data;
    struct DNode *next;
    struct DNode *prev;
} DNode;

typedef struct {
    DNode *head;
    DNode *tail;
    size_t size;
} DoublyLinkedList;

// Insert tail en O(1) grace au pointeur tail
bool dlist_insert_tail(DoublyLinkedList *list, int value);

// Parcours en sens inverse
void dlist_print_reverse(const DoublyLinkedList *list);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | create returns non-NULL | Valid ptr | 5 |
| T02 | empty list size = 0 | 0 | 5 |
| T03 | insert_head works | Correct order | 10 |
| T04 | insert_tail works | At end | 10 |
| T05 | insert_at middle | Correct position | 10 |
| T06 | delete_head works | Removes first | 10 |
| T07 | delete_tail works | Removes last | 10 |
| T08 | delete_value works | Removes first match | 10 |
| T09 | get valid index | Correct value | 5 |
| T10 | get invalid index | success=false | 5 |
| T11 | reverse works | Order reversed | 10 |
| T12 | destroy frees all | No leaks | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include "linked_list.h"

int main(void)
{
    int pass = 0, fail = 0;
    bool ok;

    // T01: create
    LinkedList *list = list_create();
    if (list != NULL)
    {
        printf("T01 PASS: list_create returned non-NULL\n");
        pass++;
    }
    else
    {
        printf("T01 FAIL\n");
        fail++;
        return 1;
    }

    // T02: empty list
    if (list_size(list) == 0 && list_is_empty(list))
    {
        printf("T02 PASS: empty list size=0, is_empty=true\n");
        pass++;
    }
    else
    {
        printf("T02 FAIL\n");
        fail++;
    }

    // T03: insert_head
    list_insert_head(list, 10);
    list_insert_head(list, 20);
    list_insert_head(list, 30);
    // Should be [30, 20, 10]
    if (list_get(list, 0, &ok) == 30 &&
        list_get(list, 1, &ok) == 20 &&
        list_get(list, 2, &ok) == 10)
    {
        printf("T03 PASS: insert_head order correct\n");
        pass++;
    }
    else
    {
        printf("T03 FAIL\n");
        fail++;
    }

    // T04: insert_tail
    list_insert_tail(list, 5);
    // Should be [30, 20, 10, 5]
    if (list_get(list, 3, &ok) == 5)
    {
        printf("T04 PASS: insert_tail at end\n");
        pass++;
    }
    else
    {
        printf("T04 FAIL\n");
        fail++;
    }

    // T05: insert_at
    list_insert_at(list, 2, 15);
    // Should be [30, 20, 15, 10, 5]
    if (list_get(list, 2, &ok) == 15 && list_size(list) == 5)
    {
        printf("T05 PASS: insert_at middle\n");
        pass++;
    }
    else
    {
        printf("T05 FAIL\n");
        fail++;
    }

    // T06: delete_head
    list_delete_head(list);
    // Should be [20, 15, 10, 5]
    if (list_get(list, 0, &ok) == 20 && list_size(list) == 4)
    {
        printf("T06 PASS: delete_head\n");
        pass++;
    }
    else
    {
        printf("T06 FAIL\n");
        fail++;
    }

    // T07: delete_tail
    list_delete_tail(list);
    // Should be [20, 15, 10]
    if (list_size(list) == 3 && list_get(list, 2, &ok) == 10)
    {
        printf("T07 PASS: delete_tail\n");
        pass++;
    }
    else
    {
        printf("T07 FAIL\n");
        fail++;
    }

    // T08: delete_value
    list_delete_value(list, 15);
    // Should be [20, 10]
    if (list_size(list) == 2 &&
        list_get(list, 0, &ok) == 20 &&
        list_get(list, 1, &ok) == 10)
    {
        printf("T08 PASS: delete_value\n");
        pass++;
    }
    else
    {
        printf("T08 FAIL\n");
        fail++;
    }

    // T09: get valid
    int val = list_get(list, 0, &ok);
    if (ok && val == 20)
    {
        printf("T09 PASS: get valid index\n");
        pass++;
    }
    else
    {
        printf("T09 FAIL\n");
        fail++;
    }

    // T10: get invalid
    list_get(list, 100, &ok);
    if (!ok)
    {
        printf("T10 PASS: get invalid returns success=false\n");
        pass++;
    }
    else
    {
        printf("T10 FAIL\n");
        fail++;
    }

    // T11: reverse
    list_clear(list);
    list_insert_tail(list, 1);
    list_insert_tail(list, 2);
    list_insert_tail(list, 3);
    list_reverse(list);
    // Should be [3, 2, 1]
    if (list_get(list, 0, &ok) == 3 &&
        list_get(list, 1, &ok) == 2 &&
        list_get(list, 2, &ok) == 1)
    {
        printf("T11 PASS: reverse\n");
        pass++;
    }
    else
    {
        printf("T11 FAIL\n");
        fail++;
    }

    // T12: destroy
    list_destroy(list);
    printf("T12 PASS: destroy completed (check valgrind)\n");
    pass++;

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * linked_list.c
 * Implementation de liste simplement chainee
 * Exercice ex27_linked_list
 */

#include "linked_list.h"
#include <stdio.h>
#include <stdlib.h>

static Node *create_node(int value)
{
    Node *node = malloc(sizeof(*node));
    if (node != NULL)
    {
        node->data = value;
        node->next = NULL;
    }
    return node;
}

LinkedList *list_create(void)
{
    LinkedList *list = malloc(sizeof(*list));
    if (list != NULL)
    {
        list->head = NULL;
        list->size = 0;
    }
    return list;
}

void list_destroy(LinkedList *list)
{
    if (list == NULL)
    {
        return;
    }
    list_clear(list);
    free(list);
}

bool list_insert_head(LinkedList *list, int value)
{
    if (list == NULL)
    {
        return false;
    }

    Node *node = create_node(value);
    if (node == NULL)
    {
        return false;
    }

    node->next = list->head;
    list->head = node;
    list->size++;
    return true;
}

bool list_insert_tail(LinkedList *list, int value)
{
    if (list == NULL)
    {
        return false;
    }

    Node *node = create_node(value);
    if (node == NULL)
    {
        return false;
    }

    if (list->head == NULL)
    {
        list->head = node;
    }
    else
    {
        Node *current = list->head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = node;
    }
    list->size++;
    return true;
}

bool list_insert_at(LinkedList *list, size_t index, int value)
{
    if (list == NULL || index > list->size)
    {
        return false;
    }

    if (index == 0)
    {
        return list_insert_head(list, value);
    }

    Node *node = create_node(value);
    if (node == NULL)
    {
        return false;
    }

    Node *current = list->head;
    for (size_t i = 0; i < index - 1; i++)
    {
        current = current->next;
    }

    node->next = current->next;
    current->next = node;
    list->size++;
    return true;
}

bool list_delete_head(LinkedList *list)
{
    if (list == NULL || list->head == NULL)
    {
        return false;
    }

    Node *old_head = list->head;
    list->head = old_head->next;
    free(old_head);
    list->size--;
    return true;
}

bool list_delete_tail(LinkedList *list)
{
    if (list == NULL || list->head == NULL)
    {
        return false;
    }

    if (list->head->next == NULL)
    {
        return list_delete_head(list);
    }

    Node *current = list->head;
    while (current->next->next != NULL)
    {
        current = current->next;
    }

    free(current->next);
    current->next = NULL;
    list->size--;
    return true;
}

bool list_delete_at(LinkedList *list, size_t index)
{
    if (list == NULL || index >= list->size)
    {
        return false;
    }

    if (index == 0)
    {
        return list_delete_head(list);
    }

    Node *current = list->head;
    for (size_t i = 0; i < index - 1; i++)
    {
        current = current->next;
    }

    Node *to_delete = current->next;
    current->next = to_delete->next;
    free(to_delete);
    list->size--;
    return true;
}

bool list_delete_value(LinkedList *list, int value)
{
    if (list == NULL || list->head == NULL)
    {
        return false;
    }

    if (list->head->data == value)
    {
        return list_delete_head(list);
    }

    Node *current = list->head;
    while (current->next != NULL && current->next->data != value)
    {
        current = current->next;
    }

    if (current->next == NULL)
    {
        return false;  // Not found
    }

    Node *to_delete = current->next;
    current->next = to_delete->next;
    free(to_delete);
    list->size--;
    return true;
}

int list_get(const LinkedList *list, size_t index, bool *success)
{
    if (list == NULL || index >= list->size)
    {
        if (success) *success = false;
        return 0;
    }

    Node *current = list->head;
    for (size_t i = 0; i < index; i++)
    {
        current = current->next;
    }

    if (success) *success = true;
    return current->data;
}

bool list_contains(const LinkedList *list, int value)
{
    if (list == NULL)
    {
        return false;
    }

    Node *current = list->head;
    while (current != NULL)
    {
        if (current->data == value)
        {
            return true;
        }
        current = current->next;
    }
    return false;
}

int list_index_of(const LinkedList *list, int value)
{
    if (list == NULL)
    {
        return -1;
    }

    Node *current = list->head;
    int index = 0;
    while (current != NULL)
    {
        if (current->data == value)
        {
            return index;
        }
        current = current->next;
        index++;
    }
    return -1;
}

bool list_set(LinkedList *list, size_t index, int value)
{
    if (list == NULL || index >= list->size)
    {
        return false;
    }

    Node *current = list->head;
    for (size_t i = 0; i < index; i++)
    {
        current = current->next;
    }

    current->data = value;
    return true;
}

void list_reverse(LinkedList *list)
{
    if (list == NULL || list->head == NULL)
    {
        return;
    }

    Node *prev = NULL;
    Node *current = list->head;
    Node *next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }

    list->head = prev;
}

void list_print(const LinkedList *list)
{
    printf("[");
    if (list != NULL && list->head != NULL)
    {
        Node *current = list->head;
        printf("%d", current->data);
        current = current->next;

        while (current != NULL)
        {
            printf(", %d", current->data);
            current = current->next;
        }
    }
    printf("]\n");
}

size_t list_size(const LinkedList *list)
{
    return list ? list->size : 0;
}

bool list_is_empty(const LinkedList *list)
{
    return list == NULL || list->size == 0;
}

void list_clear(LinkedList *list)
{
    if (list == NULL)
    {
        return;
    }

    Node *current = list->head;
    while (current != NULL)
    {
        Node *next = current->next;
        free(current);
        current = next;
    }

    list->head = NULL;
    list->size = 0;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Memory leak dans insert_at (echec apres allocation)
bool list_insert_at(LinkedList *list, size_t index, int value)
{
    Node *node = create_node(value);  // Alloue
    if (index > list->size)
    {
        return false;  // LEAK! node n'est pas libere
    }
    // ...
}
// Raison: Fuite memoire si validation echoue apres malloc

// REFUSE 2: Pas de free dans delete
bool list_delete_head(LinkedList *list)
{
    if (list->head == NULL) return false;
    list->head = list->head->next;  // LEAK! L'ancien head n'est pas libere
    list->size--;
    return true;
}
// Raison: Memory leak

// REFUSE 3: Reverse qui cree une nouvelle liste
void list_reverse(LinkedList *list)
{
    LinkedList *new_list = list_create();
    Node *current = list->head;
    while (current != NULL)
    {
        list_insert_head(new_list, current->data);
        current = current->next;
    }
    // Fuite de l'ancienne liste, pas de mise a jour de list
}
// Raison: Doit reverser sur place, memory leak

// REFUSE 4: Boucle infinie dans list_clear
void list_clear(LinkedList *list)
{
    while (list->head != NULL)
    {
        Node *current = list->head;
        free(current);
        // Oubli: list->head = current->next;
    }
}
// Raison: Boucle infinie, free invalide apres premiere iteration
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.4-a",
  "name": "linked_list",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["linked_list.c", "linked_list.h"],
    "test": ["test_linked_list.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_list"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "operations": ["insert", "delete", "search", "reverse"]
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 70,
    "memory_safety": 20
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Memory): Oubli de free dans delete_head
bool list_delete_head(LinkedList *list)
{
    if (list == NULL || list->head == NULL) return false;
    list->head = list->head->next;  // Oubli free!
    list->size--;
    return true;
}
// Detection: Valgrind memory leak

// MUTANT 2 (Logic): Reverse ne met pas a jour head
void list_reverse(LinkedList *list)
{
    Node *prev = NULL;
    Node *current = list->head;
    while (current != NULL)
    {
        Node *next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    // Oubli: list->head = prev;
}
// Detection: list_get(0) retourne ancienne valeur

// MUTANT 3 (Boundary): insert_at avec index == size echoue
bool list_insert_at(LinkedList *list, size_t index, int value)
{
    if (index >= list->size)  // >= au lieu de >
    {
        return false;  // Ne peut pas inserer a la fin!
    }
    // ...
}
// Detection: insert_at(list, size, val) devrait fonctionner

// MUTANT 4 (Safety): delete_tail sur liste de 1 element
bool list_delete_tail(LinkedList *list)
{
    if (list->head == NULL) return false;
    // Manque: if (list->head->next == NULL) return list_delete_head();
    Node *current = list->head;
    while (current->next->next != NULL)  // Crash si un seul element
    {
        current = current->next;
    }
    // ...
}
// Detection: delete_tail sur liste avec 1 element crash

// MUTANT 5 (Logic): index_of retourne mauvais type
int list_index_of(const LinkedList *list, int value)
{
    size_t index = 0;  // size_t au lieu de int
    // ...
    return index;  // Conversion implicite problematique
    // Pour liste vide ou non trouve, devrait retourner -1
}
// Detection: Valeur de retour incorrecte pour "not found"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des listes chainees**:

1. **struct Node** - Structure recursive avec pointeur next
2. **Insert head** - Insertion au debut en O(1)
3. **Insert tail** - Insertion a la fin en O(n)
4. **Delete** - Suppression avec gestion de la memoire
5. **Search** - Parcours lineaire
6. **Reverse** - Inversion sur place

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION inserer_tete(liste, valeur):
DEBUT
    noeud <- allouer_noeud(valeur)

    SI noeud est NULL ALORS
        RETOURNER ECHEC
    FIN SI

    noeud.suivant <- liste.tete
    liste.tete <- noeud
    liste.taille <- liste.taille + 1

    RETOURNER SUCCES
FIN

FONCTION inverser(liste):
DEBUT
    precedent <- NULL
    courant <- liste.tete

    TANT QUE courant n'est pas NULL:
        suivant <- courant.suivant
        courant.suivant <- precedent
        precedent <- courant
        courant <- suivant
    FIN TANT QUE

    liste.tete <- precedent
FIN
```

### 5.3 Visualisation ASCII

```
Liste vide:
LinkedList
+------+------+
| head | size |
| NULL |  0   |
+------+------+

Apres insert_head(10), insert_head(20), insert_head(30):

LinkedList          Node           Node           Node
+------+------+     +----+----+    +----+----+    +----+------+
| head | size | --> | 30 | *--|-->| 20 | *--|-->| 10 | NULL |
+------+------+     +----+----+    +----+----+    +----+------+
             3

Reverse en action:
Etape 1: prev=NULL, curr=[30]->...
         [30]->NULL (detache)
Etape 2: prev=[30], curr=[20]->...
         [20]->[30]->NULL
Etape 3: prev=[20]->[30], curr=[10]->NULL
         [10]->[20]->[30]->NULL
Final: head = [10]
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier de mettre a jour head
```c
// FAUX
void list_delete_head(LinkedList *list)
{
    free(list->head);  // head pointe maintenant vers memoire liberee!
}

// CORRECT
void list_delete_head(LinkedList *list)
{
    Node *old = list->head;
    list->head = list->head->next;  // Mise a jour AVANT free
    free(old);
}
```

#### Piege 2: Cas special liste a 1 element
```c
// FAUX - Crash sur liste avec 1 seul element
void list_delete_tail(LinkedList *list)
{
    Node *curr = list->head;
    while (curr->next->next != NULL)  // curr->next peut etre NULL!
    {
        curr = curr->next;
    }
}

// CORRECT
void list_delete_tail(LinkedList *list)
{
    if (list->head->next == NULL)  // Cas special: 1 element
    {
        free(list->head);
        list->head = NULL;
        return;
    }
    // ... reste du code
}
```

#### Piege 3: Perdre la reference pendant le parcours
```c
// FAUX
void list_clear(LinkedList *list)
{
    while (list->head != NULL)
    {
        free(list->head);  // On perd list->head->next!
        list->head = list->head->next;  // Use-after-free
    }
}

// CORRECT
void list_clear(LinkedList *list)
{
    while (list->head != NULL)
    {
        Node *next = list->head->next;  // Sauvegarder d'abord
        free(list->head);
        list->head = next;
    }
}
```

### 5.5 Cours Complet

#### 5.5.1 Structure auto-referencee

```c
typedef struct Node {
    int data;
    struct Node *next;  // Pointe vers le meme type
} Node;
```

Le mot-cle `struct Node` est necessaire car le typedef n'est pas encore complet.

#### 5.5.2 Complexite des operations

| Operation | Complexite | Raison |
|-----------|------------|--------|
| insert_head | O(1) | Pas de parcours |
| insert_tail | O(n) | Parcours complet |
| insert_at(k) | O(k) | Parcours jusqu'a k |
| delete_head | O(1) | Acces direct |
| delete_tail | O(n) | Trouver avant-dernier |
| get(k) | O(k) | Parcours jusqu'a k |
| search | O(n) | Pire cas: fin de liste |
| reverse | O(n) | Parcours complet |

#### 5.5.3 Pattern de parcours

```c
// Pattern standard
Node *current = list->head;
while (current != NULL)
{
    // Traitement de current
    current = current->next;
}

// Pattern avec element precedent
Node *prev = NULL;
Node *current = list->head;
while (current != NULL)
{
    // prev est le noeud avant current
    prev = current;
    current = current->next;
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Toujours check NULL | Liste ou noeud peut etre NULL | `if (list == NULL)` |
| Sauvegarder next avant free | Evite use-after-free | `next = curr->next; free(curr);` |
| Cas special 1 element | Evite deref NULL | `if (head->next == NULL)` |
| Mettre a jour size | Compteur coherent | `list->size++` |

### 5.7 Simulation avec trace d'execution

```
list_insert_head(list, 10):
1. create_node(10) -> Node{data=10, next=NULL} a l'adresse 0x1000
2. node->next = list->head (NULL)
3. list->head = node (0x1000)
4. list->size = 1

Etat: head -> [10|NULL], size=1

list_insert_head(list, 20):
1. create_node(20) -> Node{data=20, next=NULL} a 0x2000
2. node->next = list->head (0x1000)
3. list->head = node (0x2000)
4. list->size = 2

Etat: head -> [20|*] -> [10|NULL], size=2

list_reverse(list):
Initial: prev=NULL, curr=0x2000[20]
Iter 1: next=0x1000, [20]->NULL, prev=0x2000, curr=0x1000
Iter 2: next=NULL, [10]->[20], prev=0x1000, curr=NULL
Final: list->head = 0x1000

Etat: head -> [10|*] -> [20|NULL], size=2
```

### 5.8 Mnemotechniques

**"SNF" - Supprimer un noeud**
- **S**auvegarder le suivant
- **N**ettoyer les liens
- **F**ree le noeud

**"PCC" - Pattern de parcours**
- **P**ointeur courant
- **C**ondition != NULL
- **C**ourant = suivant

### 5.9 Applications pratiques

1. **Historique navigateur**: Previous/Next pages
2. **Playlist musicale**: Chanson suivante/precedente
3. **Undo/Redo**: Actions dans un editeur
4. **Memory allocator**: Liste de blocs libres

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Use-after-free | Crash ou donnees corrompues | Sauvegarder next avant free |
| NULL deref | Crash | Check NULL avant acces |
| Oubli mise a jour head | Liste incorrecte | Toujours mettre a jour head |
| Memory leak | RAM croissante | Free chaque noeud |
| Cas 1 element | Crash sur delete_tail | Cas special explicite |

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de insert_head dans une liste chainee ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n^2)
E) O(n log n)

**Reponse correcte: A**

### Question 2
Pourquoi faut-il sauvegarder next avant de free un noeud ?

A) Pour economiser de la memoire
B) Pour eviter un use-after-free
C) Pour accelerer l'execution
D) C'est une convention de style
E) Ce n'est pas necessaire

**Reponse correcte: B**

### Question 3
Combien de pointeurs faut-il pour inverser une liste chainee sur place ?

A) 1 (current)
B) 2 (prev, current)
C) 3 (prev, current, next)
D) 4
E) Il faut une nouvelle liste

**Reponse correcte: C**

### Question 4
Quelle est la complexite de la recherche dans une liste chainee non triee ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n^2)
E) O(n log n)

**Reponse correcte: C**

### Question 5
Pourquoi utilise-t-on `struct Node *next` et non `Node *next` dans la definition ?

A) Pour economiser de la memoire
B) Le typedef n'est pas encore complet a ce stade
C) C'est plus rapide
D) Pour la compatibilite C89
E) Il n'y a pas de difference

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Operation | Complexite | Implementation |
|-----------|------------|----------------|
| insert_head | O(1) | node->next = head; head = node |
| insert_tail | O(n) | Parcours + last->next = node |
| delete_head | O(1) | head = head->next; free(old) |
| delete_tail | O(n) | Trouver avant-dernier |
| get(index) | O(n) | Parcours jusqu'a index |
| search | O(n) | Parcours avec comparaison |
| reverse | O(n) | prev/curr/next pattern |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.4-a",
    "name": "linked_list",
    "module": "0.6.4",
    "phase": 0,
    "difficulty": 4,
    "xp": 300,
    "time_minutes": 240
  },
  "metadata": {
    "concepts": ["struct_node", "insert", "delete", "search", "reverse"],
    "prerequisites": ["0.6.1", "pointers"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "linked_list.c",
    "header": "linked_list.h",
    "solution": "linked_list_solution.c",
    "test": "test_linked_list.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "complexity_analysis": true
  }
}
```
