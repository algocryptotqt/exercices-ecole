# Exercice 0.6.5-a : stack_impl

**Module :**
0.6.5 — Implementation de Pile (Stack)

**Concept :**
a-e — push(), pop(), peek(), isEmpty(), LIFO

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
2 — Integration concepts

**Langage :**
C17

**Prerequis :**
0.6.4 (linked_list)

**Domaines :**
Structures, Algo, Mem

**Duree estimee :**
150 min

**XP Base :**
200

**Complexite :**
T1 O(1) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `stack.c`
- `stack.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `free()`, `printf()`

### 1.2 Consigne

Implementer une pile (stack) utilisant une liste chainee avec toutes les operations en O(1).

**Ta mission :**

Creer une structure de pile complete suivant le principe LIFO (Last In, First Out).

**Structures :**
```c
typedef struct StackNode {
    int data;
    struct StackNode *next;
} StackNode;

typedef struct {
    StackNode *top;
    size_t size;
} Stack;
```

**Prototypes :**
```c
// Creation et destruction
Stack *stack_create(void);
void stack_destroy(Stack *stack);

// Operations principales
bool stack_push(Stack *stack, int value);
int stack_pop(Stack *stack, bool *success);
int stack_peek(const Stack *stack, bool *success);

// Utilitaires
bool stack_is_empty(const Stack *stack);
size_t stack_size(const Stack *stack);
void stack_clear(Stack *stack);
void stack_print(const Stack *stack);
```

**Comportement :**
- `stack_create` alloue et initialise une pile vide
- `stack_destroy` libere tous les noeuds et la structure
- `stack_push` ajoute au sommet en O(1)
- `stack_pop` retire et retourne le sommet en O(1)
- `stack_peek` retourne le sommet sans le retirer
- `stack_pop/peek` sur pile vide: *success = false, retourne 0
- `stack_print` affiche de haut en bas: [top] -> 3 -> 2 -> 1 -> [bottom]

**Exemples :**
```
Stack *s = stack_create();     // []
stack_is_empty(s);             // true
stack_push(s, 10);             // [10]
stack_push(s, 20);             // [20, 10]
stack_push(s, 30);             // [30, 20, 10]
stack_peek(s, &ok);            // returns 30, stack unchanged
stack_pop(s, &ok);             // returns 30, [20, 10]
stack_size(s);                 // returns 2
stack_pop(s, &ok);             // returns 20, [10]
stack_pop(s, &ok);             // returns 10, []
stack_pop(s, &ok);             // returns 0, ok=false
stack_destroy(s);
```

**Contraintes :**
- Toutes les operations push/pop/peek en O(1)
- Gerer le cas pile vide gracieusement
- Pas de memory leaks
- Implementation basee sur liste chainee (pas de tableau)

### 1.3 Prototype

```c
// stack.h
#ifndef STACK_H
#define STACK_H

#include <stddef.h>
#include <stdbool.h>

typedef struct StackNode {
    int data;
    struct StackNode *next;
} StackNode;

typedef struct {
    StackNode *top;
    size_t size;
} Stack;

Stack *stack_create(void);
void stack_destroy(Stack *stack);

bool stack_push(Stack *stack, int value);
int stack_pop(Stack *stack, bool *success);
int stack_peek(const Stack *stack, bool *success);

bool stack_is_empty(const Stack *stack);
size_t stack_size(const Stack *stack);
void stack_clear(Stack *stack);
void stack_print(const Stack *stack);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 LIFO - Last In, First Out

La pile fonctionne comme une pile d'assiettes:
- On pose (push) une assiette sur le dessus
- On retire (pop) l'assiette du dessus
- L'assiette du bas est la derniere accessible

### 2.2 Applications des piles

- **Call stack**: Gestion des appels de fonctions
- **Undo/Redo**: Historique d'actions
- **Parsing**: Verification de parentheses
- **Backtracking**: Algorithmes de recherche (DFS)

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Compiler Engineer**

Les compilateurs utilisent des piles pour:
- Analyse syntaxique (parsing)
- Evaluation d'expressions
- Gestion des scopes

**Metier : Systems Programmer**

Le CPU utilise une pile materielle:
- Registre ESP/RSP (Stack Pointer)
- Sauvegarde des registres
- Passage de parametres (conventions d'appel)

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_stack test_main.c stack.c
$ ./test_stack
Creating stack...
  stack_is_empty: true
  stack_size: 0

Pushing 10, 20, 30...
  stack_print: [top] -> 30 -> 20 -> 10 -> [bottom]
  stack_size: 3

Testing peek...
  stack_peek: 30 (stack unchanged)
  stack_size still: 3

Testing pop...
  stack_pop: 30
  stack_pop: 20
  stack_pop: 10
  stack_is_empty: true

Testing pop on empty stack...
  stack_pop: failed (ok=false)

All tests passed!
$ valgrind --leak-check=full ./test_stack
==12345== All heap blocks were freed -- no leaks are possible
```

### 3.1 Application: Verification de parentheses

```c
bool check_parentheses(const char *expr)
{
    Stack *s = stack_create();
    bool valid = true;

    for (int i = 0; expr[i] && valid; i++)
    {
        if (expr[i] == '(' || expr[i] == '[' || expr[i] == '{')
        {
            stack_push(s, expr[i]);
        }
        else if (expr[i] == ')' || expr[i] == ']' || expr[i] == '}')
        {
            bool ok;
            int top = stack_pop(s, &ok);
            if (!ok || !matches(top, expr[i]))
            {
                valid = false;
            }
        }
    }

    valid = valid && stack_is_empty(s);
    stack_destroy(s);
    return valid;
}
```

### 3.2 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

#### 3.2.1 Consigne Bonus

Implementer une pile avec capacite minimale et maximale.

```c
typedef struct {
    StackNode *top;
    size_t size;
    size_t min_capacity;
    size_t max_capacity;
} BoundedStack;

// Retourne false si pile pleine
bool bounded_push(BoundedStack *stack, int value);

// Retourne true si pile a atteint sa capacite max
bool stack_is_full(const BoundedStack *stack);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | create returns non-NULL | Valid ptr | 10 |
| T02 | empty stack size = 0 | 0 | 10 |
| T03 | push increases size | size++ | 15 |
| T04 | pop returns top | Correct LIFO | 15 |
| T05 | peek doesn't remove | Size unchanged | 10 |
| T06 | pop empty fails | success=false | 10 |
| T07 | peek empty fails | success=false | 10 |
| T08 | LIFO order correct | 3,2,1 -> pop 3,2,1 | 10 |
| T09 | destroy frees all | No leaks | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include "stack.h"

int main(void)
{
    int pass = 0, fail = 0;
    bool ok;

    // T01: create
    Stack *stack = stack_create();
    if (stack != NULL)
    {
        printf("T01 PASS: stack_create returned non-NULL\n");
        pass++;
    }
    else
    {
        printf("T01 FAIL\n");
        fail++;
        return 1;
    }

    // T02: empty stack
    if (stack_size(stack) == 0 && stack_is_empty(stack))
    {
        printf("T02 PASS: empty stack size=0, is_empty=true\n");
        pass++;
    }
    else
    {
        printf("T02 FAIL\n");
        fail++;
    }

    // T03: push
    stack_push(stack, 10);
    stack_push(stack, 20);
    stack_push(stack, 30);
    if (stack_size(stack) == 3)
    {
        printf("T03 PASS: push increases size\n");
        pass++;
    }
    else
    {
        printf("T03 FAIL\n");
        fail++;
    }

    // T04: pop returns top
    int val = stack_pop(stack, &ok);
    if (ok && val == 30)
    {
        printf("T04 PASS: pop returns top (30)\n");
        pass++;
    }
    else
    {
        printf("T04 FAIL: expected 30, got %d\n", val);
        fail++;
    }

    // T05: peek doesn't remove
    val = stack_peek(stack, &ok);
    size_t size_before = stack_size(stack);
    stack_peek(stack, &ok);  // Peek again
    size_t size_after = stack_size(stack);
    if (val == 20 && size_before == size_after)
    {
        printf("T05 PASS: peek doesn't remove (20)\n");
        pass++;
    }
    else
    {
        printf("T05 FAIL\n");
        fail++;
    }

    // Vider la pile
    stack_pop(stack, &ok);  // 20
    stack_pop(stack, &ok);  // 10

    // T06: pop empty
    val = stack_pop(stack, &ok);
    if (!ok)
    {
        printf("T06 PASS: pop empty returns success=false\n");
        pass++;
    }
    else
    {
        printf("T06 FAIL\n");
        fail++;
    }

    // T07: peek empty
    val = stack_peek(stack, &ok);
    if (!ok)
    {
        printf("T07 PASS: peek empty returns success=false\n");
        pass++;
    }
    else
    {
        printf("T07 FAIL\n");
        fail++;
    }

    // T08: LIFO order
    stack_push(stack, 1);
    stack_push(stack, 2);
    stack_push(stack, 3);
    int v1 = stack_pop(stack, &ok);
    int v2 = stack_pop(stack, &ok);
    int v3 = stack_pop(stack, &ok);
    if (v1 == 3 && v2 == 2 && v3 == 1)
    {
        printf("T08 PASS: LIFO order correct (3,2,1)\n");
        pass++;
    }
    else
    {
        printf("T08 FAIL: got %d,%d,%d\n", v1, v2, v3);
        fail++;
    }

    // T09: destroy
    stack_destroy(stack);
    printf("T09 PASS: destroy completed (check valgrind)\n");
    pass++;

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * stack.c
 * Implementation de pile (stack) avec liste chainee
 * Exercice ex28_stack_impl
 */

#include "stack.h"
#include <stdio.h>
#include <stdlib.h>

static StackNode *create_node(int value)
{
    StackNode *node = malloc(sizeof(*node));
    if (node != NULL)
    {
        node->data = value;
        node->next = NULL;
    }
    return node;
}

Stack *stack_create(void)
{
    Stack *stack = malloc(sizeof(*stack));
    if (stack != NULL)
    {
        stack->top = NULL;
        stack->size = 0;
    }
    return stack;
}

void stack_destroy(Stack *stack)
{
    if (stack == NULL)
    {
        return;
    }
    stack_clear(stack);
    free(stack);
}

bool stack_push(Stack *stack, int value)
{
    if (stack == NULL)
    {
        return false;
    }

    StackNode *node = create_node(value);
    if (node == NULL)
    {
        return false;
    }

    node->next = stack->top;
    stack->top = node;
    stack->size++;
    return true;
}

int stack_pop(Stack *stack, bool *success)
{
    if (stack == NULL || stack->top == NULL)
    {
        if (success) *success = false;
        return 0;
    }

    StackNode *old_top = stack->top;
    int value = old_top->data;

    stack->top = old_top->next;
    stack->size--;

    free(old_top);

    if (success) *success = true;
    return value;
}

int stack_peek(const Stack *stack, bool *success)
{
    if (stack == NULL || stack->top == NULL)
    {
        if (success) *success = false;
        return 0;
    }

    if (success) *success = true;
    return stack->top->data;
}

bool stack_is_empty(const Stack *stack)
{
    return stack == NULL || stack->size == 0;
}

size_t stack_size(const Stack *stack)
{
    return stack ? stack->size : 0;
}

void stack_clear(Stack *stack)
{
    if (stack == NULL)
    {
        return;
    }

    while (stack->top != NULL)
    {
        StackNode *next = stack->top->next;
        free(stack->top);
        stack->top = next;
    }
    stack->size = 0;
}

void stack_print(const Stack *stack)
{
    printf("[top]");
    if (stack != NULL)
    {
        StackNode *current = stack->top;
        while (current != NULL)
        {
            printf(" -> %d", current->data);
            current = current->next;
        }
    }
    printf(" -> [bottom]\n");
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Push qui ajoute a la fin (pas O(1))
bool stack_push(Stack *stack, int value)
{
    StackNode *node = create_node(value);
    if (stack->top == NULL)
    {
        stack->top = node;
    }
    else
    {
        StackNode *curr = stack->top;
        while (curr->next != NULL)  // O(n)!
        {
            curr = curr->next;
        }
        curr->next = node;
    }
    return true;
}
// Raison: Push doit etre O(1), pas O(n)

// REFUSE 2: Pop qui ne libere pas la memoire
int stack_pop(Stack *stack, bool *success)
{
    if (stack->top == NULL)
    {
        *success = false;
        return 0;
    }
    int value = stack->top->data;
    stack->top = stack->top->next;  // LEAK! Ancien top pas libere
    *success = true;
    return value;
}
// Raison: Memory leak

// REFUSE 3: Peek qui modifie la pile
int stack_peek(const Stack *stack, bool *success)
{
    return stack_pop((Stack*)stack, success);  // Modifie la pile!
}
// Raison: peek ne doit pas modifier la pile

// REFUSE 4: Implementation avec tableau fixe
typedef struct {
    int data[100];  // Taille fixe!
    int top;
} Stack;
// Raison: Doit utiliser liste chainee, pas tableau
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.5-a",
  "name": "stack_impl",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["stack.c", "stack.h"],
    "test": ["test_stack.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_stack"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "complexity": {
      "push": "O(1)",
      "pop": "O(1)",
      "peek": "O(1)"
    }
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 60,
    "memory_safety": 20,
    "complexity": 10
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Memory): Pop ne libere pas le noeud
int stack_pop(Stack *stack, bool *success)
{
    if (stack->top == NULL)
    {
        *success = false;
        return 0;
    }
    int value = stack->top->data;
    stack->top = stack->top->next;  // Oubli free!
    stack->size--;
    *success = true;
    return value;
}
// Detection: Valgrind memory leak

// MUTANT 2 (Logic): Push ajoute apres top au lieu de devenir top
bool stack_push(Stack *stack, int value)
{
    StackNode *node = create_node(value);
    if (stack->top != NULL)
    {
        node->next = stack->top->next;  // Mauvais!
        stack->top->next = node;
    }
    else
    {
        stack->top = node;
    }
    stack->size++;
    return true;
}
// Detection: LIFO order incorrect

// MUTANT 3 (Boundary): Pop ne verifie pas stack NULL
int stack_pop(Stack *stack, bool *success)
{
    // Manque: if (stack == NULL)
    if (stack->top == NULL)  // Crash si stack == NULL
    {
        *success = false;
        return 0;
    }
    // ...
}
// Detection: Crash sur stack_pop(NULL, &ok)

// MUTANT 4 (Logic): size non mis a jour
bool stack_push(Stack *stack, int value)
{
    StackNode *node = create_node(value);
    node->next = stack->top;
    stack->top = node;
    // Oubli: stack->size++;
    return true;
}
// Detection: stack_size() retourne mauvaise valeur

// MUTANT 5 (Safety): Peek avec success non verifie
int stack_peek(const Stack *stack, bool *success)
{
    if (stack->top == NULL)
    {
        *success = false;  // Crash si success == NULL
        return 0;
    }
    *success = true;
    return stack->top->data;
}
// Detection: Crash si stack_peek(s, NULL)
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des piles (stacks)**:

1. **push()** - Empiler un element au sommet
2. **pop()** - Depiler et retourner le sommet
3. **peek()** - Observer le sommet sans depiler
4. **isEmpty()** - Verifier si la pile est vide
5. **LIFO** - Last In, First Out (principe fondamental)

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION push(pile, valeur):
DEBUT
    noeud <- creer_noeud(valeur)

    SI noeud est NULL ALORS
        RETOURNER ECHEC
    FIN SI

    noeud.suivant <- pile.sommet
    pile.sommet <- noeud
    pile.taille <- pile.taille + 1

    RETOURNER SUCCES
FIN

FONCTION pop(pile):
DEBUT
    SI pile.sommet est NULL ALORS
        RETOURNER ECHEC
    FIN SI

    ancien_sommet <- pile.sommet
    valeur <- ancien_sommet.donnee
    pile.sommet <- ancien_sommet.suivant
    pile.taille <- pile.taille - 1
    liberer(ancien_sommet)

    RETOURNER valeur
FIN
```

### 5.3 Visualisation ASCII

```
Push 10, puis 20, puis 30:

Etape 1: push(10)
+-----+
| top |---> [10|NULL]
+-----+

Etape 2: push(20)
+-----+
| top |---> [20|*]---> [10|NULL]
+-----+

Etape 3: push(30)
+-----+
| top |---> [30|*]---> [20|*]---> [10|NULL]
+-----+

Pop:
+-----+
| top |---> [30|*]  <- retire et free
+-----+    |
           v
        [20|*]---> [10|NULL]  <- nouveau top

Resultat apres pop:
+-----+
| top |---> [20|*]---> [10|NULL]
+-----+
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier de free dans pop
```c
// FAUX
int stack_pop(Stack *stack, bool *success)
{
    int val = stack->top->data;
    stack->top = stack->top->next;  // Memory leak!
    return val;
}

// CORRECT
int stack_pop(Stack *stack, bool *success)
{
    StackNode *old = stack->top;
    int val = old->data;
    stack->top = old->next;
    free(old);  // Liberer l'ancien sommet
    return val;
}
```

#### Piege 2: Peek qui modifie la pile
```c
// FAUX - peek ne doit pas modifier
int stack_peek(Stack *stack, bool *success)
{
    return stack_pop(stack, success);  // Modifie la pile!
}

// CORRECT
int stack_peek(const Stack *stack, bool *success)
{
    if (stack->top == NULL) { *success = false; return 0; }
    *success = true;
    return stack->top->data;  // Lecture seule
}
```

#### Piege 3: Push en O(n) au lieu de O(1)
```c
// FAUX - O(n) complexity
bool stack_push(Stack *stack, int value)
{
    StackNode *node = create_node(value);
    if (stack->top == NULL)
    {
        stack->top = node;
    }
    else
    {
        StackNode *curr = stack->top;
        while (curr->next != NULL)  // Parcours inutile!
            curr = curr->next;
        curr->next = node;
    }
    return true;
}

// CORRECT - O(1)
bool stack_push(Stack *stack, int value)
{
    StackNode *node = create_node(value);
    node->next = stack->top;
    stack->top = node;
    return true;
}
```

### 5.5 Cours Complet

#### 5.5.1 Pile vs Liste chainee

| Aspect | Liste chainee | Pile |
|--------|---------------|------|
| Operations | Insert/Delete anywhere | Push/Pop au sommet |
| Acces | O(n) n'importe ou | O(1) sommet seulement |
| Semantique | Collection generale | LIFO specifique |
| Cas d'usage | Stockage flexible | Call stack, undo |

#### 5.5.2 La pile d'appels (Call Stack)

```c
void func_c(void) { /* ... */ }
void func_b(void) { func_c(); }
void func_a(void) { func_b(); }
int main(void) { func_a(); return 0; }
```

```
Call Stack:
+--------+
| func_c | <- sommet (en cours)
+--------+
| func_b |
+--------+
| func_a |
+--------+
|  main  |
+--------+
```

#### 5.5.3 Complexite des operations

| Operation | Complexite | Explication |
|-----------|------------|-------------|
| push | O(1) | Ajout direct au sommet |
| pop | O(1) | Retrait direct du sommet |
| peek | O(1) | Lecture du sommet |
| isEmpty | O(1) | Verification du pointeur top |
| size | O(1) | Lecture du compteur |
| clear | O(n) | Parcours pour free |

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Push au sommet | O(1) garanti | `node->next = top; top = node` |
| Free dans pop | Evite memory leak | `free(old_top)` |
| const pour peek | Indique lecture seule | `const Stack *stack` |
| Check NULL | Robustesse | `if (stack == NULL)` |

### 5.7 Simulation avec trace d'execution

```
stack_push(s, 10):
1. create_node(10) -> 0x1000 {data=10, next=NULL}
2. node->next = s->top (NULL)
3. s->top = node (0x1000)
4. s->size = 1

Etat: top -> [10|NULL], size=1

stack_push(s, 20):
1. create_node(20) -> 0x2000 {data=20, next=NULL}
2. node->next = s->top (0x1000)
3. s->top = node (0x2000)
4. s->size = 2

Etat: top -> [20|*] -> [10|NULL], size=2

stack_pop(s):
1. old_top = s->top (0x2000)
2. value = old_top->data (20)
3. s->top = old_top->next (0x1000)
4. s->size = 1
5. free(0x2000)
6. return 20

Etat: top -> [10|NULL], size=1
```

### 5.8 Mnemotechniques

**"LIFO" - Last In, First Out**
- Le dernier entre est le premier sorti
- Comme une pile d'assiettes

**"TOP" - Three Operations Principal**
- **T**op (peek) - regarder
- **O**ut (pop) - retirer
- **P**ut (push) - ajouter

### 5.9 Applications pratiques

1. **Undo/Redo**: Historique d'actions dans un editeur
2. **Navigation web**: Bouton "Back" du navigateur
3. **Expressions**: Evaluation infixe -> postfixe
4. **Recursion**: Simulation iterative avec pile explicite
5. **DFS**: Parcours en profondeur de graphes

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Oubli free pop | Memory leak | Free ancien sommet |
| Peek modifie pile | Comportement incorrect | Lecture seule, const |
| Push O(n) | Performance | Ajouter au sommet, pas a la fin |
| Pop sur vide | Crash | Verifier top != NULL |
| size non mis a jour | Compteur faux | Incrementer/decrementer |

---

## SECTION 7 : QCM

### Question 1
Quel principe definit le fonctionnement d'une pile ?

A) FIFO - First In, First Out
B) LIFO - Last In, First Out
C) FILO - First In, Last Out
D) Random access
E) Priority-based

**Reponse correcte: B**

### Question 2
Quelle est la complexite de push dans une pile implementee avec liste chainee ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n^2)
E) Ca depend de l'implementation

**Reponse correcte: A**

### Question 3
Quelle est la difference entre pop et peek ?

A) pop est plus rapide
B) peek ne retire pas l'element
C) pop ne retourne pas de valeur
D) Il n'y a pas de difference
E) peek modifie la pile differemment

**Reponse correcte: B**

### Question 4
Pourquoi utiliser une liste chainee plutot qu'un tableau pour une pile ?

A) Les tableaux ne supportent pas les piles
B) Pas besoin de connaitre la taille maximale a l'avance
C) C'est plus rapide
D) Ca utilise moins de memoire
E) C'est impose par le standard C

**Reponse correcte: B**

### Question 5
Que se passe-t-il si on appelle pop sur une pile vide ?

A) Le programme crash automatiquement
B) Ca retourne 0 et le comportement depend de l'implementation
C) Le compilateur refuse
D) Ca retourne le dernier element depile
E) Ca cree un nouvel element

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Operation | Description | Complexite |
|-----------|-------------|------------|
| push(val) | Ajoute val au sommet | O(1) |
| pop() | Retire et retourne sommet | O(1) |
| peek() | Retourne sommet sans retirer | O(1) |
| isEmpty() | Verifie si pile vide | O(1) |
| size() | Nombre d'elements | O(1) |
| clear() | Vide la pile | O(n) |

| Principe | Description |
|----------|-------------|
| LIFO | Last In, First Out |
| Top | Seul element accessible |
| Push/Pop | Operations symetriques |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.5-a",
    "name": "stack_impl",
    "module": "0.6.5",
    "phase": 0,
    "difficulty": 3,
    "xp": 200,
    "time_minutes": 150
  },
  "metadata": {
    "concepts": ["push", "pop", "peek", "isEmpty", "LIFO"],
    "prerequisites": ["0.6.4"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "stack.c",
    "header": "stack.h",
    "solution": "stack_solution.c",
    "test": "test_stack.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "complexity_check": {
      "push": "O(1)",
      "pop": "O(1)",
      "peek": "O(1)"
    }
  }
}
```
