# Exercice D.0.23-a : greedy_algorithms

**Module :**
D.0.23 — Algorithmes Gloutons

**Concept :**
a-e — Activity selection, fractional knapsack, Huffman coding, coin change, job scheduling

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Melange concepts

**Langage :**
C17

**Prerequis :**
D.0.07 (sorting), D.0.06 (recursion)

**Domaines :**
Algo

**Duree estimee :**
180 min

**XP Base :**
175

**Complexite :**
T[N] O(n log n) x S[N] O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `greedy.c`
- `greedy.h`

### 1.2 Consigne

Implementer des algorithmes gloutons (greedy) classiques. Un algorithme glouton fait toujours le choix localement optimal a chaque etape, esperant trouver l'optimum global.

**Ta mission :**

```c
// Structure pour une activite (debut, fin)
typedef struct s_activity {
    int start;
    int finish;
    int id;
} t_activity;

// Structure pour un item (fractional knapsack)
typedef struct s_item {
    int weight;
    int value;
    double ratio;  // value/weight
} t_item;

// Structure pour un job (scheduling)
typedef struct s_job {
    int id;
    int deadline;
    int profit;
} t_job;

// Structure pour un noeud Huffman
typedef struct s_huffman_node {
    char character;
    unsigned frequency;
    struct s_huffman_node *left;
    struct s_huffman_node *right;
} t_huffman_node;

// Activity Selection: selectionne le maximum d'activites non-chevauchantes
int activity_selection(t_activity *activities, int n, int *selected);

// Fractional Knapsack: maximise la valeur avec poids fractionnables
double fractional_knapsack(t_item *items, int n, int capacity);

// Coin Change (greedy): nombre minimum de pieces (approche gloutonne)
int coin_change_greedy(int *coins, int n_coins, int amount, int *result);

// Job Scheduling: maximise le profit avec deadlines
int job_scheduling(t_job *jobs, int n, int *schedule);

// Huffman: construit l'arbre de codage
t_huffman_node *build_huffman_tree(char *chars, int *freqs, int n);

// Huffman: encode un caractere
char *huffman_encode(t_huffman_node *root, char c);

// Huffman: libere l'arbre
void free_huffman_tree(t_huffman_node *root);
```

**Comportement:**

1. `activity_selection` -> retourne le nombre max d'activites compatibles
2. `fractional_knapsack` -> retourne la valeur maximale (peut etre decimale)
3. `coin_change_greedy` -> retourne le nombre de pieces (-1 si impossible)
4. `job_scheduling` -> retourne le profit maximum

**Exemples:**
```
Activity Selection:
activities = [(1,4), (3,5), (0,6), (5,7), (3,9), (5,9), (6,10), (8,11)]
Selected: (1,4), (5,7), (8,11) -> 3 activites

Fractional Knapsack:
items = [(10, 60), (20, 100), (30, 120)]  // (weight, value)
capacity = 50
Take: item2 full (20kg, 100$) + item3 full (30kg, 120$) = 220$
ou: item1 full + item2 full + 2/3 item3 = 60 + 100 + 80 = 240$

Coin Change (greedy):
coins = [25, 10, 5, 1], amount = 63
Result: 2x25 + 1x10 + 0x5 + 3x1 = 6 pieces

Job Scheduling:
jobs = [(1, 2, 100), (2, 1, 19), (3, 2, 27), (4, 1, 25), (5, 3, 15)]
Schedule: job1 at slot2, job3 at slot1, job5 at slot3 = 142 profit
```

### 1.3 Prototype

```c
// greedy.h
#ifndef GREEDY_H
#define GREEDY_H

typedef struct s_activity {
    int start;
    int finish;
    int id;
} t_activity;

typedef struct s_item {
    int weight;
    int value;
    double ratio;
} t_item;

typedef struct s_job {
    int id;
    int deadline;
    int profit;
} t_job;

typedef struct s_huffman_node {
    char character;
    unsigned frequency;
    struct s_huffman_node *left;
    struct s_huffman_node *right;
} t_huffman_node;

int activity_selection(t_activity *activities, int n, int *selected);
double fractional_knapsack(t_item *items, int n, int capacity);
int coin_change_greedy(int *coins, int n_coins, int amount, int *result);
int job_scheduling(t_job *jobs, int n, int *schedule);
t_huffman_node *build_huffman_tree(char *chars, int *freqs, int n);
char *huffman_encode(t_huffman_node *root, char c);
void free_huffman_tree(t_huffman_node *root);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | activity_selection basic | 3 activities | 15 |
| T02 | activity_selection overlapping | correct | 10 |
| T03 | fractional_knapsack basic | 240.0 | 15 |
| T04 | fractional_knapsack exact fit | correct | 10 |
| T05 | coin_change_greedy standard | 6 coins | 15 |
| T06 | job_scheduling basic | max profit | 15 |
| T07 | huffman_tree construction | valid tree | 10 |
| T08 | edge cases (empty, single) | handled | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "greedy.h"

// Comparateur pour trier activites par temps de fin
static int compare_activities(const void *a, const void *b)
{
    t_activity *act1 = (t_activity *)a;
    t_activity *act2 = (t_activity *)b;
    return act1->finish - act2->finish;
}

// Activity Selection Problem
// Strategie: toujours choisir l'activite qui finit le plus tot
int activity_selection(t_activity *activities, int n, int *selected)
{
    if (n <= 0)
        return 0;

    // Copier et trier par temps de fin
    t_activity *sorted = malloc(n * sizeof(t_activity));
    memcpy(sorted, activities, n * sizeof(t_activity));
    qsort(sorted, n, sizeof(t_activity), compare_activities);

    int count = 1;
    selected[0] = sorted[0].id;
    int last_finish = sorted[0].finish;

    for (int i = 1; i < n; i++)
    {
        // Si l'activite commence apres la fin de la precedente
        if (sorted[i].start >= last_finish)
        {
            selected[count] = sorted[i].id;
            last_finish = sorted[i].finish;
            count++;
        }
    }

    free(sorted);
    return count;
}

// Comparateur pour trier items par ratio valeur/poids decroissant
static int compare_items(const void *a, const void *b)
{
    t_item *item1 = (t_item *)a;
    t_item *item2 = (t_item *)b;
    if (item2->ratio > item1->ratio)
        return 1;
    if (item2->ratio < item1->ratio)
        return -1;
    return 0;
}

// Fractional Knapsack
// Strategie: prendre les items avec le meilleur ratio valeur/poids
double fractional_knapsack(t_item *items, int n, int capacity)
{
    if (n <= 0 || capacity <= 0)
        return 0.0;

    // Copier et calculer les ratios
    t_item *sorted = malloc(n * sizeof(t_item));
    for (int i = 0; i < n; i++)
    {
        sorted[i] = items[i];
        sorted[i].ratio = (double)items[i].value / items[i].weight;
    }

    // Trier par ratio decroissant
    qsort(sorted, n, sizeof(t_item), compare_items);

    double total_value = 0.0;
    int remaining_capacity = capacity;

    for (int i = 0; i < n && remaining_capacity > 0; i++)
    {
        if (sorted[i].weight <= remaining_capacity)
        {
            // Prendre l'item entier
            total_value += sorted[i].value;
            remaining_capacity -= sorted[i].weight;
        }
        else
        {
            // Prendre une fraction de l'item
            double fraction = (double)remaining_capacity / sorted[i].weight;
            total_value += sorted[i].value * fraction;
            remaining_capacity = 0;
        }
    }

    free(sorted);
    return total_value;
}

// Coin Change (Greedy)
// Strategie: toujours utiliser la plus grande piece possible
// Note: Ne donne pas toujours l'optimal (ex: coins=[1,3,4], amount=6)
int coin_change_greedy(int *coins, int n_coins, int amount, int *result)
{
    if (amount < 0 || n_coins <= 0)
        return -1;
    if (amount == 0)
        return 0;

    // Copier et trier les pieces en ordre decroissant
    int *sorted = malloc(n_coins * sizeof(int));
    memcpy(sorted, coins, n_coins * sizeof(int));

    // Tri decroissant (bubble sort simple)
    for (int i = 0; i < n_coins - 1; i++)
    {
        for (int j = 0; j < n_coins - i - 1; j++)
        {
            if (sorted[j] < sorted[j + 1])
            {
                int temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
            }
        }
    }

    int total_coins = 0;
    int remaining = amount;

    for (int i = 0; i < n_coins && remaining > 0; i++)
    {
        int count = remaining / sorted[i];
        if (count > 0)
        {
            if (result)
                result[i] = count;
            total_coins += count;
            remaining -= count * sorted[i];
        }
        else if (result)
        {
            result[i] = 0;
        }
    }

    free(sorted);

    if (remaining > 0)
        return -1;  // Impossible de faire l'appoint

    return total_coins;
}

// Comparateur pour trier jobs par profit decroissant
static int compare_jobs(const void *a, const void *b)
{
    t_job *job1 = (t_job *)a;
    t_job *job2 = (t_job *)b;
    return job2->profit - job1->profit;
}

// Job Scheduling with Deadlines
// Strategie: trier par profit decroissant, placer au plus tard possible
int job_scheduling(t_job *jobs, int n, int *schedule)
{
    if (n <= 0)
        return 0;

    // Copier et trier par profit decroissant
    t_job *sorted = malloc(n * sizeof(t_job));
    memcpy(sorted, jobs, n * sizeof(t_job));
    qsort(sorted, n, sizeof(t_job), compare_jobs);

    // Trouver le deadline maximum
    int max_deadline = 0;
    for (int i = 0; i < n; i++)
    {
        if (sorted[i].deadline > max_deadline)
            max_deadline = sorted[i].deadline;
    }

    // Slots disponibles (-1 = libre)
    int *slots = malloc((max_deadline + 1) * sizeof(int));
    for (int i = 0; i <= max_deadline; i++)
        slots[i] = -1;

    int total_profit = 0;
    int scheduled_count = 0;

    for (int i = 0; i < n; i++)
    {
        // Chercher un slot libre avant le deadline (du plus tard au plus tot)
        for (int j = sorted[i].deadline; j > 0; j--)
        {
            if (slots[j] == -1)
            {
                slots[j] = sorted[i].id;
                total_profit += sorted[i].profit;
                if (schedule)
                    schedule[scheduled_count] = sorted[i].id;
                scheduled_count++;
                break;
            }
        }
    }

    free(sorted);
    free(slots);
    return total_profit;
}

// Creer un noeud Huffman
static t_huffman_node *create_huffman_node(char c, unsigned freq)
{
    t_huffman_node *node = malloc(sizeof(t_huffman_node));
    node->character = c;
    node->frequency = freq;
    node->left = NULL;
    node->right = NULL;
    return node;
}

// Min-heap simple pour Huffman
static void min_heapify(t_huffman_node **heap, int size, int i)
{
    int smallest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < size && heap[left]->frequency < heap[smallest]->frequency)
        smallest = left;
    if (right < size && heap[right]->frequency < heap[smallest]->frequency)
        smallest = right;

    if (smallest != i)
    {
        t_huffman_node *temp = heap[i];
        heap[i] = heap[smallest];
        heap[smallest] = temp;
        min_heapify(heap, size, smallest);
    }
}

static t_huffman_node *extract_min(t_huffman_node **heap, int *size)
{
    t_huffman_node *min = heap[0];
    heap[0] = heap[*size - 1];
    (*size)--;
    min_heapify(heap, *size, 0);
    return min;
}

static void insert_heap(t_huffman_node **heap, int *size, t_huffman_node *node)
{
    (*size)++;
    int i = *size - 1;
    heap[i] = node;

    while (i > 0 && heap[(i - 1) / 2]->frequency > heap[i]->frequency)
    {
        t_huffman_node *temp = heap[i];
        heap[i] = heap[(i - 1) / 2];
        heap[(i - 1) / 2] = temp;
        i = (i - 1) / 2;
    }
}

// Build Huffman Tree
// Strategie: toujours combiner les deux noeuds de plus basse frequence
t_huffman_node *build_huffman_tree(char *chars, int *freqs, int n)
{
    if (n <= 0)
        return NULL;

    // Creer un min-heap
    t_huffman_node **heap = malloc(n * sizeof(t_huffman_node *));
    int heap_size = 0;

    for (int i = 0; i < n; i++)
    {
        insert_heap(heap, &heap_size, create_huffman_node(chars[i], freqs[i]));
    }

    // Construire l'arbre
    while (heap_size > 1)
    {
        t_huffman_node *left = extract_min(heap, &heap_size);
        t_huffman_node *right = extract_min(heap, &heap_size);

        t_huffman_node *internal = create_huffman_node('\0',
            left->frequency + right->frequency);
        internal->left = left;
        internal->right = right;

        insert_heap(heap, &heap_size, internal);
    }

    t_huffman_node *root = heap[0];
    free(heap);
    return root;
}

// Helper pour encoder
static int huffman_encode_helper(t_huffman_node *node, char c,
                                  char *code, int depth)
{
    if (!node)
        return 0;

    // Feuille
    if (!node->left && !node->right)
    {
        if (node->character == c)
        {
            code[depth] = '\0';
            return 1;
        }
        return 0;
    }

    // Essayer a gauche (0)
    code[depth] = '0';
    if (huffman_encode_helper(node->left, c, code, depth + 1))
        return 1;

    // Essayer a droite (1)
    code[depth] = '1';
    if (huffman_encode_helper(node->right, c, code, depth + 1))
        return 1;

    return 0;
}

char *huffman_encode(t_huffman_node *root, char c)
{
    if (!root)
        return NULL;

    char *code = malloc(256);  // Max depth
    if (!huffman_encode_helper(root, c, code, 0))
    {
        free(code);
        return NULL;
    }

    return code;
}

void free_huffman_tree(t_huffman_node *root)
{
    if (!root)
        return;
    free_huffman_tree(root->left);
    free_huffman_tree(root->right);
    free(root);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: activity_selection sans tri par temps de fin
int activity_selection(t_activity *activities, int n, int *selected)
{
    // Trie par temps de DEBUT au lieu de FIN
    // Ne donne pas l'optimal!
    qsort(activities, n, sizeof(t_activity), compare_by_start);
    // ...
}

// MUTANT 2: fractional_knapsack trie par valeur au lieu de ratio
double fractional_knapsack(t_item *items, int n, int capacity)
{
    // Trie par valeur decroissante au lieu de ratio
    // items = [(50, 100), (30, 90)]
    // Par valeur: prend (50,100) -> 100
    // Par ratio: prend (30,90) + 20/50*(100) -> 90 + 40 = 130
}

// MUTANT 3: coin_change_greedy ne detecte pas l'impossibilite
int coin_change_greedy(int *coins, int n_coins, int amount, int *result)
{
    // Ne verifie pas remaining > 0 a la fin
    // coins = [5, 10], amount = 3
    // Retourne 0 au lieu de -1
    return total_coins;  // Meme si remaining != 0
}

// MUTANT 4: job_scheduling place au plus tot au lieu du plus tard
int job_scheduling(t_job *jobs, int n, int *schedule)
{
    // Cherche slot du debut au lieu de la fin
    for (int j = 1; j <= sorted[i].deadline; j++)  // j=1 au lieu de j=deadline
    {
        if (slots[j] == -1)
        {
            // Peut bloquer des jobs plus profitables
        }
    }
}

// MUTANT 5: huffman sans min-heap (mauvaise selection)
t_huffman_node *build_huffman_tree(char *chars, int *freqs, int n)
{
    // Combine toujours les deux premiers au lieu des deux minimums
    // Ne produit pas un arbre optimal
    while (n > 1)
    {
        t_huffman_node *node = combine(nodes[0], nodes[1]);  // PAS min!
        // ...
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **algorithmes gloutons**:

1. **Choix glouton** - Prendre le meilleur choix local a chaque etape
2. **Propriete du choix glouton** - Un choix local mene a une solution globale
3. **Sous-structure optimale** - Solution optimale contient sous-solutions optimales
4. **Limites** - Greedy ne garantit pas toujours l'optimal (ex: coin change)

### 5.3 Visualisation ASCII

```
ACTIVITY SELECTION:
Timeline: 0  1  2  3  4  5  6  7  8  9  10 11
          |--|--|--|--|--|--|--|--|--|--|--|
Act 1:    [======]           (1-4)
Act 2:       [=====]         (3-5)  X (chevauche 1)
Act 3:    [==========]       (0-6)  X (chevauche 1)
Act 4:             [===]     (5-7)  OK!
Act 5:       [=========]     (3-9)  X (chevauche 4)
Act 6:             [======]  (5-9)  X (chevauche 4)
Act 7:                [=====](6-10) X (chevauche 4)
Act 8:                   [===](8-11) OK!

Selection: Act1, Act4, Act8 = 3 activites max
Strategie: Toujours choisir celle qui FINIT le plus tot!

FRACTIONAL KNAPSACK:
Items:         Weight  Value  Ratio
Item A:        10      60     6.0  <-- Best ratio
Item B:        20      100    5.0
Item C:        30      120    4.0

Capacity = 50
Greedy selection:
1. Take Item A (10kg): value=60, remaining=40
2. Take Item B (20kg): value=60+100=160, remaining=20
3. Take 2/3 of C (20kg): value=160+80=240, remaining=0

Total: 240 (optimal!)

HUFFMAN ENCODING:
Characters: a(5) b(9) c(12) d(13) e(16) f(45)

Step 1: Combine a(5) + b(9) = ab(14)
        [c:12] [d:13] [ab:14] [e:16] [f:45]

Step 2: Combine c(12) + d(13) = cd(25)
        [ab:14] [e:16] [cd:25] [f:45]

Step 3: Combine ab(14) + e(16) = abe(30)
        [cd:25] [abe:30] [f:45]

Step 4: Combine cd(25) + abe(30) = cdabe(55)
        [f:45] [cdabe:55]

Step 5: Combine f(45) + cdabe(55) = root(100)

Tree:          (100)
              /     \
           f(45)   (55)
                  /    \
               (25)    (30)
              /   \    /   \
            c(12) d(13) (14) e(16)
                       /   \
                     a(5)  b(9)

Codes: f=0, c=100, d=101, a=1100, b=1101, e=111

JOB SCHEDULING:
Jobs: (id, deadline, profit)
J1(1, 2, 100)  J2(2, 1, 19)  J3(3, 2, 27)  J4(4, 1, 25)  J5(5, 3, 15)

Sorted by profit: J1(100) > J3(27) > J4(25) > J2(19) > J5(15)

Slots:    [  1  ][  2  ][  3  ]

J1(d=2): Place at slot 2    [    ][ J1 ][    ]
J3(d=2): Place at slot 1    [ J3 ][ J1 ][    ]  (slot 2 taken)
J4(d=1): Cannot place       [ J3 ][ J1 ][    ]  (slot 1 taken)
J2(d=1): Cannot place       [ J3 ][ J1 ][    ]
J5(d=3): Place at slot 3    [ J3 ][ J1 ][ J5 ]

Total profit: 27 + 100 + 15 = 142
```

---

## SECTION 7 : QCM

### Question 1
Quelle propriete est NECESSAIRE pour qu'un algorithme glouton donne la solution optimale ?

A) La complexite doit etre O(n log n)
B) Le probleme doit avoir la propriete du choix glouton
C) Les donnees doivent etre triees
D) Il faut utiliser une structure de tas
E) Le probleme doit etre de type NP-complet

**Reponse correcte: B**

**Explication:** La propriete du choix glouton garantit qu'un choix localement optimal mene a une solution globalement optimale. Sans cette propriete, l'algorithme glouton peut donner une solution sous-optimale.

### Question 2
Pour le probleme du rendu de monnaie avec les pieces [1, 3, 4] et un montant de 6, quelle est la difference entre la solution gloutonne et la solution optimale ?

A) Greedy: 3 pieces (4+1+1), Optimal: 2 pieces (3+3)
B) Greedy: 2 pieces, Optimal: 2 pieces
C) Greedy: 2 pieces, Optimal: 3 pieces
D) Greedy: 6 pieces (1+1+1+1+1+1), Optimal: 2 pieces
E) Les deux solutions sont identiques

**Reponse correcte: A**

**Explication:** L'algorithme glouton choisit d'abord la plus grande piece (4), puis deux fois 1, donnant 3 pieces. La solution optimale utilise deux pieces de 3 (3+3=6). Cet exemple montre que le greedy ne garantit pas toujours l'optimal pour le coin change.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.23-a",
  "name": "greedy_algorithms",
  "language": "c",
  "language_version": "c17",
  "difficulty": 5,
  "xp": 175,
  "complexity": {
    "time": "O(n log n)",
    "space": "O(n)"
  },
  "files": ["greedy.c", "greedy.h"],
  "tests": {
    "activity_selection": "activity_tests",
    "fractional_knapsack": "knapsack_tests",
    "coin_change": "coin_tests",
    "job_scheduling": "job_tests",
    "huffman": "huffman_tests"
  },
  "prerequisites": ["D.0.07", "D.0.06"],
  "tags": ["greedy", "optimization", "algorithms", "huffman", "scheduling"]
}
```
