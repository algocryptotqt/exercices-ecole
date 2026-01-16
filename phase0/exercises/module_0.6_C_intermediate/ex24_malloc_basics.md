# Exercice 0.6.1-a : malloc_basics

**Module :**
0.6.1 — Allocation Dynamique de Base

**Concept :**
a-e — malloc(size), calloc(n,size), free(ptr), NULL check, sizeof(*ptr)

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5 (bases C), pointeurs

**Domaines :**
Mem, Pointeurs, Heap

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T1 O(1) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `malloc_basics.c`
- `malloc_basics.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stddef.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `free()`, `printf()`, `memcpy()`, `memset()`

### 1.2 Consigne

Implementer des fonctions d'allocation memoire securisees avec verification systematique des erreurs.

**Ta mission :**

Creer un ensemble de fonctions qui encapsulent les operations d'allocation dynamique avec gestion d'erreurs robuste.

**Prototypes :**
```c
// Alloue un tableau de n entiers (non initialise)
int *alloc_int_array(size_t n);

// Alloue un tableau de n entiers initialises a zero
int *alloc_int_array_zeroed(size_t n);

// Alloue et copie une chaine de caracteres (comme strdup)
char *alloc_string_copy(const char *src);

// Alloue une matrice 2D de dimensions rows x cols
int **alloc_matrix(size_t rows, size_t cols);

// Libere une matrice 2D
void free_matrix(int **matrix, size_t rows);

// Alloue un buffer de taille size avec valeur par defaut
void *alloc_buffer_init(size_t size, unsigned char init_value);
```

**Comportement :**
- Si l'allocation echoue (malloc/calloc retourne NULL), la fonction retourne NULL
- Les fonctions doivent verifier que les parametres sont valides (n > 0, src != NULL, etc.)
- `alloc_int_array_zeroed` doit utiliser `calloc` pour l'initialisation a zero
- `alloc_matrix` doit liberer toute memoire deja allouee en cas d'echec partiel
- `free_matrix` doit gerer le cas ou matrix est NULL

**Exemples :**
```
alloc_int_array(5)         -> pointeur vers 5 int non initialises
alloc_int_array(0)         -> NULL (taille invalide)
alloc_int_array_zeroed(3)  -> pointeur vers {0, 0, 0}
alloc_string_copy("hello") -> pointeur vers copie de "hello"
alloc_string_copy(NULL)    -> NULL
alloc_matrix(2, 3)         -> matrice 2x3
free_matrix(NULL, 5)       -> ne fait rien (safe)
```

**Contraintes :**
- Toujours verifier le retour de malloc/calloc
- Utiliser `sizeof(*ptr)` plutot que `sizeof(type)` pour la portabilite
- Ne jamais acceder a la memoire apres free
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// malloc_basics.h
#ifndef MALLOC_BASICS_H
#define MALLOC_BASICS_H

#include <stddef.h>

int *alloc_int_array(size_t n);
int *alloc_int_array_zeroed(size_t n);
char *alloc_string_copy(const char *src);
int **alloc_matrix(size_t rows, size_t cols);
void free_matrix(int **matrix, size_t rows);
void *alloc_buffer_init(size_t size, unsigned char init_value);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Heap vs Stack

La memoire d'un programme est divisee en plusieurs segments:
- **Stack** : Variables locales, taille limitee (~1-8 MB), allocation automatique
- **Heap** : Allocation dynamique, taille limitee par la RAM, allocation manuelle

### 2.2 Pourquoi malloc peut echouer ?

`malloc()` peut retourner NULL si:
- La memoire disponible est insuffisante
- Le systeme est sous pression memoire
- L'argument size est excessivement grand
- Fragmentation de la memoire

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Systems Programmer**

La gestion memoire manuelle est cruciale pour:
- Developpement de noyaux OS (Linux kernel utilise kmalloc)
- Bases de donnees (PostgreSQL, Redis)
- Moteurs de jeux video (allocateurs custom)

**Metier : Embedded Developer**

Sur microcontroleurs avec memoire limitee:
- Pas de malloc standard parfois
- Pools de memoire pre-alloues
- Gestion stricte des ressources

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_malloc test_main.c malloc_basics.c
$ ./test_malloc
Testing alloc_int_array(5)...
  Allocated at address: 0x55a4c8f012a0
  Values (uninitialized): may contain garbage
  PASS: allocation successful

Testing alloc_int_array_zeroed(3)...
  Allocated at address: 0x55a4c8f012c0
  Values: [0, 0, 0]
  PASS: all values are zero

Testing alloc_string_copy("hello")...
  Original: "hello" at 0x55a4c8f00004
  Copy: "hello" at 0x55a4c8f012e0
  PASS: strings are equal but different addresses

Testing alloc_matrix(2, 3)...
  Matrix allocated successfully
  PASS: 2x3 matrix created

All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer un allocateur avec tracking des allocations pour detecter les fuites memoire.

```c
// Wrapper malloc avec tracking
void *tracked_malloc(size_t size, const char *file, int line);

// Wrapper free avec tracking
void tracked_free(void *ptr, const char *file, int line);

// Affiche toutes les allocations non liberees
void print_memory_leaks(void);

// Retourne le nombre d'octets actuellement alloues
size_t get_allocated_bytes(void);

// Macros pour utilisation simplifiee
#define MALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define FREE(ptr) tracked_free(ptr, __FILE__, __LINE__)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | alloc_int_array normal | n=5 | non-NULL | 10 |
| T02 | alloc_int_array zero | n=0 | NULL | 10 |
| T03 | alloc_int_array_zeroed | n=3 | {0,0,0} | 15 |
| T04 | alloc_string_copy valid | "test" | copie "test" | 15 |
| T05 | alloc_string_copy NULL | NULL | NULL | 10 |
| T06 | alloc_matrix valid | 2x3 | non-NULL | 15 |
| T07 | free_matrix NULL safe | NULL, 5 | no crash | 10 |
| T08 | alloc_buffer_init | 10, 0xFF | filled 0xFF | 15 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "malloc_basics.h"

int main(void)
{
    int pass = 0, fail = 0;

    // T01: alloc_int_array normal
    int *arr = alloc_int_array(5);
    if (arr != NULL) {
        printf("T01 PASS: alloc_int_array(5) returned non-NULL\n");
        pass++;
        free(arr);
    } else {
        printf("T01 FAIL: alloc_int_array(5) returned NULL\n");
        fail++;
    }

    // T02: alloc_int_array zero
    arr = alloc_int_array(0);
    if (arr == NULL) {
        printf("T02 PASS: alloc_int_array(0) returned NULL\n");
        pass++;
    } else {
        printf("T02 FAIL: alloc_int_array(0) should return NULL\n");
        free(arr);
        fail++;
    }

    // T03: alloc_int_array_zeroed
    arr = alloc_int_array_zeroed(3);
    if (arr != NULL && arr[0] == 0 && arr[1] == 0 && arr[2] == 0) {
        printf("T03 PASS: alloc_int_array_zeroed(3) returned zeroed array\n");
        pass++;
        free(arr);
    } else {
        printf("T03 FAIL: alloc_int_array_zeroed(3) values not zero\n");
        if (arr) free(arr);
        fail++;
    }

    // T04: alloc_string_copy valid
    char *str = alloc_string_copy("test");
    if (str != NULL && strcmp(str, "test") == 0) {
        printf("T04 PASS: alloc_string_copy(\"test\") works\n");
        pass++;
        free(str);
    } else {
        printf("T04 FAIL: alloc_string_copy failed\n");
        if (str) free(str);
        fail++;
    }

    // T05: alloc_string_copy NULL
    str = alloc_string_copy(NULL);
    if (str == NULL) {
        printf("T05 PASS: alloc_string_copy(NULL) returned NULL\n");
        pass++;
    } else {
        printf("T05 FAIL: alloc_string_copy(NULL) should return NULL\n");
        free(str);
        fail++;
    }

    // T06: alloc_matrix valid
    int **matrix = alloc_matrix(2, 3);
    if (matrix != NULL && matrix[0] != NULL && matrix[1] != NULL) {
        printf("T06 PASS: alloc_matrix(2, 3) works\n");
        pass++;
        free_matrix(matrix, 2);
    } else {
        printf("T06 FAIL: alloc_matrix failed\n");
        if (matrix) free_matrix(matrix, 2);
        fail++;
    }

    // T07: free_matrix NULL safe
    free_matrix(NULL, 5);
    printf("T07 PASS: free_matrix(NULL, 5) did not crash\n");
    pass++;

    // T08: alloc_buffer_init
    unsigned char *buf = alloc_buffer_init(10, 0xFF);
    int all_ff = 1;
    if (buf != NULL) {
        for (int i = 0; i < 10; i++) {
            if (buf[i] != 0xFF) all_ff = 0;
        }
        if (all_ff) {
            printf("T08 PASS: alloc_buffer_init filled with 0xFF\n");
            pass++;
        } else {
            printf("T08 FAIL: buffer not filled correctly\n");
            fail++;
        }
        free(buf);
    } else {
        printf("T08 FAIL: alloc_buffer_init returned NULL\n");
        fail++;
    }

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * malloc_basics.c
 * Fonctions d'allocation memoire securisees
 * Exercice ex24_malloc_basics
 */

#include "malloc_basics.h"
#include <stdlib.h>
#include <string.h>

int *alloc_int_array(size_t n)
{
    if (n == 0)
    {
        return NULL;
    }

    int *arr = malloc(n * sizeof(*arr));
    return arr;  // NULL si echec, pointeur sinon
}

int *alloc_int_array_zeroed(size_t n)
{
    if (n == 0)
    {
        return NULL;
    }

    int *arr = calloc(n, sizeof(*arr));
    return arr;  // calloc initialise a zero
}

char *alloc_string_copy(const char *src)
{
    if (src == NULL)
    {
        return NULL;
    }

    size_t len = strlen(src) + 1;  // +1 pour '\0'
    char *copy = malloc(len * sizeof(*copy));

    if (copy != NULL)
    {
        memcpy(copy, src, len);
    }

    return copy;
}

int **alloc_matrix(size_t rows, size_t cols)
{
    if (rows == 0 || cols == 0)
    {
        return NULL;
    }

    // Allouer le tableau de pointeurs
    int **matrix = malloc(rows * sizeof(*matrix));
    if (matrix == NULL)
    {
        return NULL;
    }

    // Allouer chaque ligne
    for (size_t i = 0; i < rows; i++)
    {
        matrix[i] = calloc(cols, sizeof(**matrix));
        if (matrix[i] == NULL)
        {
            // Echec: liberer ce qui a deja ete alloue
            for (size_t j = 0; j < i; j++)
            {
                free(matrix[j]);
            }
            free(matrix);
            return NULL;
        }
    }

    return matrix;
}

void free_matrix(int **matrix, size_t rows)
{
    if (matrix == NULL)
    {
        return;
    }

    for (size_t i = 0; i < rows; i++)
    {
        free(matrix[i]);  // free(NULL) est safe
    }
    free(matrix);
}

void *alloc_buffer_init(size_t size, unsigned char init_value)
{
    if (size == 0)
    {
        return NULL;
    }

    void *buffer = malloc(size);
    if (buffer != NULL)
    {
        memset(buffer, init_value, size);
    }

    return buffer;
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: alloc_string_copy avec strcpy
char *alloc_string_copy(const char *src)
{
    if (src == NULL) return NULL;

    size_t len = strlen(src) + 1;
    char *copy = malloc(len);
    if (copy != NULL)
    {
        strcpy(copy, src);  // strcpy au lieu de memcpy
    }
    return copy;
}

// Alternative 2: alloc_matrix avec allocation contigue
int **alloc_matrix(size_t rows, size_t cols)
{
    if (rows == 0 || cols == 0) return NULL;

    // Allocation unique pour donnees + pointeurs
    int **matrix = malloc(rows * sizeof(int*) + rows * cols * sizeof(int));
    if (matrix == NULL) return NULL;

    int *data = (int*)(matrix + rows);
    for (size_t i = 0; i < rows; i++)
    {
        matrix[i] = data + i * cols;
    }
    memset(matrix[0], 0, rows * cols * sizeof(int));
    return matrix;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Pas de verification NULL apres malloc
int *alloc_int_array(size_t n)
{
    int *arr = malloc(n * sizeof(int));
    arr[0] = 0;  // DANGER: arr peut etre NULL!
    return arr;
}
// Raison: Segfault si malloc echoue

// REFUSE 2: sizeof(type) au lieu de sizeof(*ptr)
int *alloc_int_array(size_t n)
{
    int *arr = malloc(n * sizeof(int));  // Moins portable
    return arr;
}
// Raison: Si on change le type du pointeur, sizeof n'est pas mis a jour

// REFUSE 3: Pas de liberation en cas d'echec partiel
int **alloc_matrix(size_t rows, size_t cols)
{
    int **matrix = malloc(rows * sizeof(int*));
    for (size_t i = 0; i < rows; i++)
    {
        matrix[i] = malloc(cols * sizeof(int));
        if (matrix[i] == NULL)
            return NULL;  // FUITE: les lignes precedentes ne sont pas liberees!
    }
    return matrix;
}
// Raison: Memory leak si une allocation intermediaire echoue

// REFUSE 4: free_matrix sans check NULL
void free_matrix(int **matrix, size_t rows)
{
    for (size_t i = 0; i < rows; i++)
        free(matrix[i]);  // Crash si matrix == NULL
    free(matrix);
}
// Raison: Segfault si matrix est NULL
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.1-a",
  "name": "malloc_basics",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["malloc_basics.c", "malloc_basics.h"],
    "test": ["test_malloc_basics.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_malloc"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "leak_check": true
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
// MUTANT 1 (Safety): Pas de check size == 0
int *alloc_int_array(size_t n)
{
    // Manque: if (n == 0) return NULL;
    int *arr = malloc(n * sizeof(*arr));
    return arr;
}
// Detection: alloc_int_array(0) peut retourner non-NULL ou comportement indefini

// MUTANT 2 (Memory): Utilise malloc au lieu de calloc pour zeroed
int *alloc_int_array_zeroed(size_t n)
{
    if (n == 0) return NULL;
    int *arr = malloc(n * sizeof(*arr));  // Pas initialise!
    return arr;
}
// Detection: Valeurs non-zero dans le tableau

// MUTANT 3 (Logic): Oubli du +1 pour le '\0' dans string copy
char *alloc_string_copy(const char *src)
{
    if (src == NULL) return NULL;
    size_t len = strlen(src);  // Manque +1!
    char *copy = malloc(len * sizeof(*copy));
    if (copy != NULL) memcpy(copy, src, len);
    return copy;
}
// Detection: String sans terminateur, buffer overflow lecture

// MUTANT 4 (Memory): Fuite memoire dans alloc_matrix
int **alloc_matrix(size_t rows, size_t cols)
{
    if (rows == 0 || cols == 0) return NULL;
    int **matrix = malloc(rows * sizeof(*matrix));
    if (matrix == NULL) return NULL;
    for (size_t i = 0; i < rows; i++)
    {
        matrix[i] = calloc(cols, sizeof(**matrix));
        if (matrix[i] == NULL)
        {
            return NULL;  // Fuite! Pas de cleanup
        }
    }
    return matrix;
}
// Detection: Valgrind detecte la fuite

// MUTANT 5 (Boundary): free_matrix avec mauvais index
void free_matrix(int **matrix, size_t rows)
{
    if (matrix == NULL) return;
    for (size_t i = 0; i <= rows; i++)  // <= au lieu de <
    {
        free(matrix[i]);  // Acces hors limites!
    }
    free(matrix);
}
// Detection: Valgrind invalid read, possible crash
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux de l'allocation dynamique** en C:

1. **malloc(size)** - Alloue size octets non initialises
2. **calloc(n, size)** - Alloue n*size octets initialises a zero
3. **free(ptr)** - Libere la memoire pointee
4. **NULL check** - Verification obligatoire du retour
5. **sizeof(*ptr)** - Pattern portable pour calculer la taille

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION allouer_tableau_entiers(n: entier positif):
DEBUT
    SI n est zero ALORS
        RETOURNER NULL (taille invalide)
    FIN SI

    pointeur <- demander_memoire_heap(n * taille_entier)

    SI pointeur est NULL ALORS
        RETOURNER NULL (echec allocation)
    FIN SI

    RETOURNER pointeur
FIN
```

### 5.3 Visualisation ASCII

```
STACK                          HEAP
+------------------+           +---------------------------+
| main()           |           |                           |
|   int *arr ------+---------->| [0][1][2][3][4]           |
|   int **mat -----+--------+  | 20 bytes (5 * sizeof int) |
|                  |        |  |                           |
+------------------+        |  +---------------------------+
                            |  |                           |
                            +->| row_ptrs[0] -> [][][]     |
                               | row_ptrs[1] -> [][][]     |
                               |                           |
                               +---------------------------+

malloc(20):
1. Cherche bloc libre >= 20 bytes dans heap
2. Marque bloc comme utilise
3. Retourne adresse du debut

free(ptr):
1. Trouve le bloc correspondant
2. Marque comme libre
3. Peut fusionner avec blocs adjacents libres
```

### 5.4 Les pieges en detail

#### Piege 1: Pas de verification NULL
```c
// FAUX - Crash si allocation echoue
int *arr = malloc(n * sizeof(int));
arr[0] = 42;  // Segfault si arr == NULL

// CORRECT
int *arr = malloc(n * sizeof(int));
if (arr == NULL)
{
    // Gerer l'erreur
    return NULL;
}
arr[0] = 42;
```

#### Piege 2: sizeof(type) vs sizeof(*ptr)
```c
// MOINS PORTABLE
int *arr = malloc(n * sizeof(int));

// PLUS PORTABLE - type change automatiquement
int *arr = malloc(n * sizeof(*arr));

// Exemple de bug avec sizeof(type):
long *arr = malloc(n * sizeof(int));  // BUG! 4 bytes au lieu de 8
```

#### Piege 3: Oublier free()
```c
void process(void)
{
    int *arr = malloc(100 * sizeof(*arr));
    // ... utilisation ...
    // Oubli de free(arr) -> Memory leak!
}
```

#### Piege 4: Double free
```c
int *arr = malloc(10 * sizeof(*arr));
free(arr);
free(arr);  // ERREUR: Double free!
```

### 5.5 Cours Complet

#### 5.5.1 malloc - Memory ALLOCation

```c
void *malloc(size_t size);
```

- Alloue `size` octets sur le heap
- Retourne pointeur vers le debut ou NULL si echec
- Memoire NON initialisee (peut contenir n'importe quoi)
- Doit etre castee implicitement (en C, pas besoin de cast explicite)

```c
int *arr = malloc(5 * sizeof(*arr));  // 20 bytes sur systeme 32-bit
```

#### 5.5.2 calloc - Contiguous ALLOCation

```c
void *calloc(size_t nmemb, size_t size);
```

- Alloue `nmemb * size` octets sur le heap
- Memoire initialisee a ZERO
- Verifie le debordement de multiplication internement

```c
int *arr = calloc(5, sizeof(*arr));  // 5 entiers, tous a 0
```

#### 5.5.3 free - Liberation memoire

```c
void free(void *ptr);
```

- Libere la memoire allouee par malloc/calloc/realloc
- `free(NULL)` est safe (ne fait rien)
- Apres free, le pointeur devient INVALIDE

```c
int *arr = malloc(10 * sizeof(*arr));
// ... utilisation ...
free(arr);
arr = NULL;  // Bonne pratique: evite use-after-free
```

#### 5.5.4 Pattern sizeof(*ptr)

Pourquoi `sizeof(*ptr)` plutot que `sizeof(type)` ?

```c
// Si on change le type:
int *arr = malloc(n * sizeof(int));

// Plus tard, on change en long:
long *arr = malloc(n * sizeof(int));  // BUG! Toujours sizeof(int)

// Avec sizeof(*arr):
long *arr = malloc(n * sizeof(*arr));  // Correct automatiquement!
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Toujours verifier NULL | malloc peut echouer | `if (ptr == NULL) return;` |
| sizeof(*ptr) | Type-safe et portable | `malloc(n * sizeof(*arr))` |
| free puis NULL | Evite use-after-free | `free(p); p = NULL;` |
| Un free par malloc | Evite double free | Comptage reference |
| Liberer en ordre inverse | Evite dangling pointers | LIFO pour allocations |

### 5.7 Simulation avec trace d'execution

```
Programme: alloc_int_array(3)

1. Appel malloc(3 * sizeof(int)) = malloc(12)
2. Heap manager cherche bloc libre >= 12 bytes
3. Trouve bloc a adresse 0x1000, taille 16 (alignement)
4. Marque bloc utilise, ecrit metadata
5. Retourne 0x1000

   Heap:
   [metadata|0x1000: _ _ _ |padding]
            ^
            pointeur retourne

6. Verification: 0x1000 != NULL, OK
7. Retourne 0x1000 a l'appelant

Programme: free(arr)

1. Lit metadata avant 0x1000
2. Taille = 16, marque libre
3. Tente fusion avec blocs adjacents
4. Bloc disponible pour futures allocations
```

### 5.8 Mnemotechniques

**"MaCaFree" - Les 3 fonctions cles**
- **Ma**lloc - Alloue brut
- **Ca**lloc - Alloue Clean (zero)
- **Free** - Libere

**"NANS" - Regles d'or**
- **N**ull check toujours
- **A**llouer avant utiliser
- **N**e jamais use-after-free
- **S**ize avec sizeof(*ptr)

### 5.9 Applications pratiques

1. **Tableaux de taille variable**: Quand la taille n'est connue qu'a l'execution
2. **Structures de donnees**: Listes chainees, arbres, graphes
3. **Buffers d'E/S**: Lecture de fichiers de taille inconnue
4. **Cache applicatif**: Stockage temporaire de donnees

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de check NULL | Segfault aleatoire | `if (ptr == NULL)` |
| sizeof(type) | Mauvaise taille si type change | `sizeof(*ptr)` |
| Oubli free | Memory leak | Valgrind, ASAN |
| Double free | Crash ou corruption | `ptr = NULL` apres free |
| Use after free | Comportement indefini | Ne plus utiliser apres free |
| Fuite en cas d'echec | Leak si allocation partielle | Cleanup systematique |

---

## SECTION 7 : QCM

### Question 1
Que retourne malloc() si l'allocation echoue ?

A) -1
B) 0
C) NULL
D) Une adresse invalide
E) Le programme crash immediatement
F) Une exception est levee
G) Un pointeur vers la stack
H) ENOMEM
I) false
J) undefined

**Reponse correcte: C**

### Question 2
Quelle est la difference principale entre malloc et calloc ?

A) calloc est plus rapide
B) malloc peut allouer plus de memoire
C) calloc initialise la memoire a zero
D) malloc retourne un pointeur type
E) calloc ne peut pas echouer
F) malloc est thread-safe
G) calloc utilise moins de memoire
H) malloc est deprecie
I) calloc ne necessite pas free
J) Aucune difference

**Reponse correcte: C**

### Question 3
Pourquoi utiliser sizeof(*ptr) plutot que sizeof(int) ?

A) C'est plus rapide
B) Ca utilise moins de memoire
C) C'est portable si le type du pointeur change
D) C'est obligatoire en C17
E) malloc ne fonctionne qu'avec sizeof(*ptr)
F) Le compilateur refuse sizeof(int)
G) C'est plus lisible
H) Ca evite les warnings
I) C'est une convention de style
J) Il n'y a aucune raison

**Reponse correcte: C**

### Question 4
Que se passe-t-il si on appelle free(NULL) ?

A) Segmentation fault
B) Comportement indefini
C) Rien, c'est safe
D) Le programme se termine
E) Memory leak
F) Double free error
G) Le heap est corrompu
H) Une exception est levee
I) Compilation error
J) Warning a l'execution

**Reponse correcte: C**

### Question 5
Comment eviter les memory leaks dans une fonction qui alloue plusieurs ressources ?

A) Ne jamais utiliser malloc
B) Utiliser uniquement calloc
C) Liberer dans l'ordre inverse d'allocation en cas d'erreur
D) Ignorer les erreurs d'allocation
E) Utiliser des variables globales
F) Allouer tout sur la stack
G) Redemarrer le programme regulierement
H) Utiliser des pointeurs const
I) Eviter les fonctions avec plusieurs allocations
J) Utiliser goto pour sauter le code de liberation

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Fonction | Usage | Initialisation | Retour echec |
|----------|-------|----------------|--------------|
| malloc(size) | Allouer size bytes | Non | NULL |
| calloc(n, size) | Allouer n*size bytes | Oui (zero) | NULL |
| free(ptr) | Liberer memoire | N/A | N/A |

| Pattern | Description | Exemple |
|---------|-------------|---------|
| sizeof(*ptr) | Taille type-safe | `malloc(n * sizeof(*arr))` |
| NULL check | Verification obligatoire | `if (p == NULL) return;` |
| free + NULL | Securite post-free | `free(p); p = NULL;` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.1-a",
    "name": "malloc_basics",
    "module": "0.6.1",
    "phase": 0,
    "difficulty": 3,
    "xp": 250,
    "time_minutes": 180
  },
  "metadata": {
    "concepts": ["malloc", "calloc", "free", "NULL check", "sizeof"],
    "prerequisites": ["0.5", "pointers"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "malloc_basics.c",
    "header": "malloc_basics.h",
    "solution": "malloc_basics_solution.c",
    "test": "test_malloc_basics.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 70,
    "memory_weight": 20
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 4
  }
}
```
