# Exercice 0.6.3-a : memory_pitfalls

**Module :**
0.6.3 — Pieges Memoire et Debugging

**Concept :**
a-d — Double free, Memory leak, Use after free, Valgrind

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
2 — Integration concepts

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc_basics), 0.6.2 (dynamic_array)

**Domaines :**
Mem, Debug, Security

**Duree estimee :**
240 min

**XP Base :**
300

**Complexite :**
T1 O(1) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `memory_pitfalls.c`
- `memory_pitfalls.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `realloc()`, `free()`, `printf()`, `fprintf()`

### 1.2 Consigne

Implementer un allocateur memoire avec tracking qui detecte les erreurs courantes: double free, memory leaks, use after free.

**Ta mission :**

Creer un systeme de tracking des allocations memoire qui enregistre chaque allocation et liberation, et detecte les erreurs a l'execution.

**Structure interne :**
```c
typedef struct MemBlock {
    void *ptr;              // Adresse allouee
    size_t size;            // Taille allouee
    const char *file;       // Fichier source
    int line;               // Ligne source
    bool freed;             // Deja libere ?
    struct MemBlock *next;  // Bloc suivant
} MemBlock;
```

**Prototypes :**
```c
// Initialise le systeme de tracking
void mem_tracker_init(void);

// Nettoie le systeme de tracking
void mem_tracker_cleanup(void);

// Allocation avec tracking
void *tracked_malloc(size_t size, const char *file, int line);

// Liberation avec tracking
void tracked_free(void *ptr, const char *file, int line);

// Affiche les fuites memoire detectees
void mem_report_leaks(void);

// Retourne le nombre de bytes actuellement alloues
size_t mem_get_allocated(void);

// Retourne le nombre d'allocations actives
size_t mem_get_allocation_count(void);

// Active/desactive les messages de debug
void mem_set_verbose(bool verbose);

// Macros pour utilisation simplifiee
#define MALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define FREE(ptr) tracked_free(ptr, __FILE__, __LINE__)
```

**Comportement :**
- `tracked_malloc` enregistre chaque allocation avec fichier et ligne
- `tracked_free` verifie:
  - Le pointeur a bien ete alloue par tracked_malloc
  - Le pointeur n'a pas deja ete libere (double free)
- `mem_report_leaks` affiche toutes les allocations non liberees
- En mode verbose, chaque operation est affichee sur stderr
- Les erreurs sont signalees sur stderr avec fichier:ligne

**Format des messages :**
```
[MEM] malloc(100) at main.c:42 -> 0x1234
[MEM] free(0x1234) at main.c:50
[ERROR] Double free of 0x1234 at main.c:55 (originally allocated at main.c:42)
[ERROR] Free of unknown pointer 0x5678 at main.c:60
[LEAK] 100 bytes at 0x1234 allocated at main.c:42
```

**Exemples :**
```c
mem_tracker_init();
mem_set_verbose(true);

int *arr = MALLOC(10 * sizeof(int));  // [MEM] malloc(40) at test.c:5 -> 0x...
FREE(arr);                             // [MEM] free(0x...) at test.c:6
FREE(arr);                             // [ERROR] Double free of 0x... at test.c:7

char *str = MALLOC(100);               // [MEM] malloc(100) at test.c:9 -> 0x...
// Oubli de FREE(str)

mem_report_leaks();                    // [LEAK] 100 bytes at 0x... allocated at test.c:9
mem_tracker_cleanup();
```

**Contraintes :**
- Le tracker doit etre thread-unsafe (simplification)
- Utiliser une liste chainee pour stocker les blocs
- Ne pas modifier le comportement de malloc/free standard
- Les macros MALLOC/FREE doivent capturer __FILE__ et __LINE__

### 1.3 Prototype

```c
// memory_pitfalls.h
#ifndef MEMORY_PITFALLS_H
#define MEMORY_PITFALLS_H

#include <stddef.h>
#include <stdbool.h>

void mem_tracker_init(void);
void mem_tracker_cleanup(void);
void *tracked_malloc(size_t size, const char *file, int line);
void tracked_free(void *ptr, const char *file, int line);
void mem_report_leaks(void);
size_t mem_get_allocated(void);
size_t mem_get_allocation_count(void);
void mem_set_verbose(bool verbose);

#define MALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define FREE(ptr) tracked_free(ptr, __FILE__, __LINE__)

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Les 3 cavaliers de l'apocalypse memoire

1. **Memory Leak** : Memoire allouee jamais liberee
   - Symptome: Utilisation memoire croissante
   - Cause: Oubli de free, perte de pointeur

2. **Double Free** : Liberer deux fois la meme memoire
   - Symptome: Crash, corruption heap
   - Cause: Logique de cleanup defaillante

3. **Use After Free** : Utiliser memoire apres liberation
   - Symptome: Donnees corrompues, crash aleatoire
   - Cause: Pointeur non-reinitialise

### 2.2 Valgrind - L'outil indispensable

```bash
$ valgrind --leak-check=full ./my_program
==12345== HEAP SUMMARY:
==12345==     in use at exit: 100 bytes in 1 blocks
==12345==   total heap usage: 5 allocs, 4 frees, 1,024 bytes allocated
==12345==
==12345== 100 bytes in 1 blocks are definitely lost
==12345==    at 0x4C2AB80: malloc (vg_replace_malloc.c:299)
==12345==    by 0x400544: main (test.c:10)
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Security Researcher**

Les vulnerabilites memoire sont critiques:
- CVE-2021-44228 (Log4Shell) - pas memoire mais critique
- CVE-2021-3156 (Sudo) - heap overflow
- Use-after-free dans navigateurs web

**Outils professionnels:**
- Valgrind (Unix)
- AddressSanitizer (ASAN)
- Dr. Memory (Windows)
- Electric Fence

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -g -o test_mem test_main.c memory_pitfalls.c
$ ./test_mem
[MEM] Tracker initialized
[MEM] malloc(40) at test_main.c:12 -> 0x55a4c8f012a0
[MEM] malloc(100) at test_main.c:15 -> 0x55a4c8f012d0
[MEM] free(0x55a4c8f012a0) at test_main.c:18
[ERROR] Double free of 0x55a4c8f012a0 at test_main.c:21 (originally allocated at test_main.c:12)

Memory Report:
--------------
[LEAK] 100 bytes at 0x55a4c8f012d0 allocated at test_main.c:15

Summary:
  Total allocated: 100 bytes in 1 block(s)
  Total leaked: 100 bytes in 1 block(s)

[MEM] Tracker cleanup complete
$ echo $?
1
```

### 3.1 Integration avec Valgrind

```bash
$ valgrind --leak-check=full --show-leak-kinds=all ./test_mem
==12345== Memcheck, a memory error detector
==12345== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==12345==
[MEM] Tracker initialized
...
==12345== HEAP SUMMARY:
==12345==     in use at exit: 0 bytes in 0 blocks
==12345==   total heap usage: 10 allocs, 10 frees, 1,240 bytes allocated
==12345==
==12345== All heap blocks were freed -- no leaks are possible
```

### 3.2 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.2.1 Consigne Bonus

Ajouter la detection de buffer overflow avec des "canaries".

```c
// Structure avec canaries
// [CANARY_START][user_data][CANARY_END]

#define CANARY_VALUE 0xDEADBEEF

void *tracked_malloc_protected(size_t size, const char *file, int line);
bool mem_check_canaries(void *ptr);
void mem_check_all_canaries(void);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Init/cleanup sans alloc | No crash | 5 |
| T02 | Malloc retourne non-NULL | Valid ptr | 10 |
| T03 | Free valide | No error | 10 |
| T04 | Double free detecte | Error msg | 15 |
| T05 | Free unknown ptr | Error msg | 10 |
| T06 | Leak detection | Leak reported | 15 |
| T07 | get_allocated correct | Byte count | 10 |
| T08 | get_allocation_count | Block count | 10 |
| T09 | Multiple allocs | All tracked | 10 |
| T10 | Verbose on/off | Correct output | 5 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <string.h>
#include "memory_pitfalls.h"

int main(void)
{
    int pass = 0, fail = 0;

    // T01: Init/cleanup
    mem_tracker_init();
    mem_tracker_cleanup();
    printf("T01 PASS: Init/cleanup OK\n");
    pass++;

    // T02-T03: Basic malloc/free
    mem_tracker_init();
    mem_set_verbose(false);

    int *arr = MALLOC(10 * sizeof(int));
    if (arr != NULL)
    {
        printf("T02 PASS: Malloc returned non-NULL\n");
        pass++;
    }
    else
    {
        printf("T02 FAIL: Malloc returned NULL\n");
        fail++;
    }

    FREE(arr);
    printf("T03 PASS: Free completed\n");
    pass++;

    // T04: Double free
    // Redirect stderr to capture error message
    fprintf(stderr, "--- Testing double free (expect error) ---\n");
    FREE(arr);  // Should report double free
    printf("T04 PASS: Double free was attempted (check stderr)\n");
    pass++;

    // T05: Free unknown pointer
    fprintf(stderr, "--- Testing free unknown (expect error) ---\n");
    int local_var;
    FREE(&local_var);  // Should report unknown pointer
    printf("T05 PASS: Free unknown was attempted (check stderr)\n");
    pass++;

    // T06: Leak detection
    char *leaked = MALLOC(50);
    (void)leaked;  // Intentionally not freed
    printf("T06: Leak created, will be reported at cleanup\n");

    // T07: get_allocated
    size_t allocated = mem_get_allocated();
    if (allocated == 50)
    {
        printf("T07 PASS: get_allocated = %zu\n", allocated);
        pass++;
    }
    else
    {
        printf("T07 FAIL: get_allocated = %zu (expected 50)\n", allocated);
        fail++;
    }

    // T08: get_allocation_count
    size_t count = mem_get_allocation_count();
    if (count == 1)
    {
        printf("T08 PASS: allocation_count = %zu\n", count);
        pass++;
    }
    else
    {
        printf("T08 FAIL: allocation_count = %zu (expected 1)\n", count);
        fail++;
    }

    // T09: Multiple allocations
    void *p1 = MALLOC(10);
    void *p2 = MALLOC(20);
    void *p3 = MALLOC(30);
    if (mem_get_allocation_count() == 4 && mem_get_allocated() == 110)
    {
        printf("T09 PASS: Multiple allocs tracked\n");
        pass++;
    }
    else
    {
        printf("T09 FAIL: Multiple allocs not tracked correctly\n");
        fail++;
    }
    FREE(p1);
    FREE(p2);
    FREE(p3);

    // T10: Verbose mode
    mem_set_verbose(true);
    fprintf(stderr, "--- Verbose mode test ---\n");
    void *v = MALLOC(5);
    FREE(v);
    mem_set_verbose(false);
    printf("T10 PASS: Verbose mode tested (check stderr)\n");
    pass++;

    // Report and cleanup
    fprintf(stderr, "\n--- Memory Report ---\n");
    mem_report_leaks();
    mem_tracker_cleanup();

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * memory_pitfalls.c
 * Allocateur memoire avec tracking et detection d'erreurs
 * Exercice ex26_memory_pitfalls
 */

#include "memory_pitfalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemBlock {
    void *ptr;
    size_t size;
    const char *file;
    int line;
    bool freed;
    struct MemBlock *next;
} MemBlock;

static MemBlock *g_blocks = NULL;
static bool g_verbose = false;
static size_t g_total_allocated = 0;
static size_t g_allocation_count = 0;

void mem_tracker_init(void)
{
    g_blocks = NULL;
    g_verbose = false;
    g_total_allocated = 0;
    g_allocation_count = 0;

    if (g_verbose)
    {
        fprintf(stderr, "[MEM] Tracker initialized\n");
    }
}

void mem_tracker_cleanup(void)
{
    MemBlock *current = g_blocks;
    while (current != NULL)
    {
        MemBlock *next = current->next;
        if (!current->freed)
        {
            free(current->ptr);
        }
        free(current);
        current = next;
    }
    g_blocks = NULL;
    g_total_allocated = 0;
    g_allocation_count = 0;

    if (g_verbose)
    {
        fprintf(stderr, "[MEM] Tracker cleanup complete\n");
    }
}

static MemBlock *find_block(void *ptr)
{
    MemBlock *current = g_blocks;
    while (current != NULL)
    {
        if (current->ptr == ptr)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void *tracked_malloc(size_t size, const char *file, int line)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
    {
        return NULL;
    }

    MemBlock *block = malloc(sizeof(MemBlock));
    if (block == NULL)
    {
        free(ptr);
        return NULL;
    }

    block->ptr = ptr;
    block->size = size;
    block->file = file;
    block->line = line;
    block->freed = false;
    block->next = g_blocks;
    g_blocks = block;

    g_total_allocated += size;
    g_allocation_count++;

    if (g_verbose)
    {
        fprintf(stderr, "[MEM] malloc(%zu) at %s:%d -> %p\n",
                size, file, line, ptr);
    }

    return ptr;
}

void tracked_free(void *ptr, const char *file, int line)
{
    if (ptr == NULL)
    {
        return;  // free(NULL) is safe and does nothing
    }

    MemBlock *block = find_block(ptr);

    if (block == NULL)
    {
        fprintf(stderr, "[ERROR] Free of unknown pointer %p at %s:%d\n",
                ptr, file, line);
        return;
    }

    if (block->freed)
    {
        fprintf(stderr, "[ERROR] Double free of %p at %s:%d "
                "(originally allocated at %s:%d)\n",
                ptr, file, line, block->file, block->line);
        return;
    }

    block->freed = true;
    g_total_allocated -= block->size;
    g_allocation_count--;

    if (g_verbose)
    {
        fprintf(stderr, "[MEM] free(%p) at %s:%d\n", ptr, file, line);
    }

    free(ptr);
}

void mem_report_leaks(void)
{
    size_t leak_count = 0;
    size_t leak_bytes = 0;

    MemBlock *current = g_blocks;
    while (current != NULL)
    {
        if (!current->freed)
        {
            fprintf(stderr, "[LEAK] %zu bytes at %p allocated at %s:%d\n",
                    current->size, current->ptr,
                    current->file, current->line);
            leak_count++;
            leak_bytes += current->size;
        }
        current = current->next;
    }

    fprintf(stderr, "\nSummary:\n");
    fprintf(stderr, "  Total allocated: %zu bytes in %zu block(s)\n",
            g_total_allocated, g_allocation_count);
    fprintf(stderr, "  Total leaked: %zu bytes in %zu block(s)\n",
            leak_bytes, leak_count);
}

size_t mem_get_allocated(void)
{
    return g_total_allocated;
}

size_t mem_get_allocation_count(void)
{
    return g_allocation_count;
}

void mem_set_verbose(bool verbose)
{
    g_verbose = verbose;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Pas de verification double free
void tracked_free(void *ptr, const char *file, int line)
{
    MemBlock *block = find_block(ptr);
    if (block != NULL)
    {
        free(ptr);  // Pas de check block->freed!
        block->freed = true;
    }
}
// Raison: Ne detecte pas les double free

// REFUSE 2: Pas de tracking des metadata
void *tracked_malloc(size_t size, const char *file, int line)
{
    void *ptr = malloc(size);
    if (g_verbose)
    {
        printf("malloc(%zu)\n", size);
    }
    return ptr;  // Pas de stockage dans la liste!
}
// Raison: Impossible de detecter les leaks ou double free

// REFUSE 3: Memory leak dans le tracker lui-meme
void mem_tracker_cleanup(void)
{
    g_blocks = NULL;  // Ne libere pas les MemBlock!
    g_total_allocated = 0;
}
// Raison: Le tracker lui-meme a des fuites memoire

// REFUSE 4: Crash sur free(NULL)
void tracked_free(void *ptr, const char *file, int line)
{
    MemBlock *block = find_block(ptr);  // ptr peut etre NULL
    if (block->freed)  // Crash si block == NULL
    {
        // ...
    }
}
// Raison: free(NULL) doit etre safe
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.3-a",
  "name": "memory_pitfalls",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["memory_pitfalls.c", "memory_pitfalls.h"],
    "test": ["test_memory_pitfalls.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17", "-g"],
    "output": "test_mem"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "error_detection": ["double_free", "leak", "unknown_free"]
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "error_detection": 50,
    "reporting": 30,
    "self_cleanup": 10
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Logic): Ne detecte pas double free
void tracked_free(void *ptr, const char *file, int line)
{
    MemBlock *block = find_block(ptr);
    if (block == NULL)
    {
        fprintf(stderr, "[ERROR] Unknown pointer\n");
        return;
    }
    // Manque: if (block->freed) { ... }
    block->freed = true;
    free(ptr);
}
// Detection: Double free non signale

// MUTANT 2 (Memory): Fuite des MemBlock dans cleanup
void mem_tracker_cleanup(void)
{
    MemBlock *current = g_blocks;
    while (current != NULL)
    {
        MemBlock *next = current->next;
        if (!current->freed)
        {
            free(current->ptr);
        }
        // Oubli: free(current);
        current = next;
    }
    g_blocks = NULL;
}
// Detection: Valgrind detecte fuite des MemBlock

// MUTANT 3 (Logic): Mauvais comptage
void *tracked_malloc(size_t size, const char *file, int line)
{
    void *ptr = malloc(size);
    // ... creation block ...
    g_total_allocated += 1;  // Devrait etre += size
    g_allocation_count++;
    return ptr;
}
// Detection: get_allocated() retourne mauvaise valeur

// MUTANT 4 (Safety): Crash sur ptr NULL dans find_block
static MemBlock *find_block(void *ptr)
{
    MemBlock *current = g_blocks;
    while (current->ptr != ptr)  // Crash si current == NULL
    {
        current = current->next;
    }
    return current;
}
// Detection: Crash sur recherche de pointeur inexistant

// MUTANT 5 (Logic): Ne met pas a jour les compteurs sur free
void tracked_free(void *ptr, const char *file, int line)
{
    MemBlock *block = find_block(ptr);
    if (block && !block->freed)
    {
        block->freed = true;
        // Oubli: g_total_allocated -= block->size;
        // Oubli: g_allocation_count--;
        free(ptr);
    }
}
// Detection: get_allocated/count incorrects apres free
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **erreurs memoire classiques** et leur detection:

1. **Double free** - Liberer deux fois la meme memoire
2. **Memory leak** - Memoire allouee jamais liberee
3. **Use after free** - Utiliser memoire apres liberation
4. **Valgrind** - Outil de detection automatique

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION tracked_free(pointeur, fichier, ligne):
DEBUT
    SI pointeur est NULL ALORS
        RETOURNER (free(NULL) est safe)
    FIN SI

    bloc <- chercher_bloc(pointeur)

    SI bloc n'existe pas ALORS
        AFFICHER ERREUR "Pointeur inconnu"
        RETOURNER
    FIN SI

    SI bloc est deja libere ALORS
        AFFICHER ERREUR "Double free detecte"
        RETOURNER
    FIN SI

    Marquer bloc comme libere
    Mettre a jour compteurs
    Liberer memoire reelle
FIN
```

### 5.3 Visualisation ASCII

```
Etat normal:
+--------+     +--------+     +--------+
| Block1 | --> | Block2 | --> | Block3 | --> NULL
| ptr=A  |     | ptr=B  |     | ptr=C  |
| free=0 |     | free=0 |     | free=0 |
+--------+     +--------+     +--------+

Heap: [A: data][B: data][C: data]

Apres FREE(B):
+--------+     +--------+     +--------+
| Block1 | --> | Block2 | --> | Block3 | --> NULL
| ptr=A  |     | ptr=B  |     | ptr=C  |
| free=0 |     | free=1 |     | free=0 |
+--------+     +--------+     +--------+

Heap: [A: data][B: freed ][C: data]

Double free de B:
[ERROR] Block2.freed est deja true!

Memory leak (C non libere a la fin):
[LEAK] Block3: ptr=C, size=..., file:line
```

### 5.4 Les pieges en detail

#### Piege 1: Double Free
```c
int *ptr = malloc(100);
free(ptr);
// ... plus tard ...
free(ptr);  // DOUBLE FREE!

// Solution: Mettre a NULL apres free
free(ptr);
ptr = NULL;
free(ptr);  // Safe, free(NULL) ne fait rien
```

#### Piege 2: Use After Free
```c
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);
printf("%d\n", *ptr);  // USE AFTER FREE! Valeur indefinie

// Solution: Ne plus utiliser apres free
free(ptr);
ptr = NULL;  // Crash explicite si utilise
```

#### Piege 3: Memory Leak
```c
void leak_example(void)
{
    int *ptr = malloc(100);
    // ... utilisation ...
    // Oubli de free(ptr)!
}  // ptr sort du scope, memoire perdue

// Solution: Toujours free avant return/fin de scope
```

#### Piege 4: Perte de pointeur
```c
int *ptr = malloc(100);
ptr = malloc(200);  // Fuite! L'ancien pointeur est perdu

// Solution: Free avant reassignment
int *ptr = malloc(100);
free(ptr);
ptr = malloc(200);
```

### 5.5 Cours Complet

#### 5.5.1 Valgrind - Memcheck

Valgrind est un framework d'instrumentation binaire. Memcheck detecte:

```bash
# Utilisation basique
valgrind ./my_program

# Avec details sur les leaks
valgrind --leak-check=full ./my_program

# Tous les types de leaks
valgrind --leak-check=full --show-leak-kinds=all ./my_program

# Avec trace d'origine
valgrind --track-origins=yes ./my_program
```

#### 5.5.2 Types d'erreurs Valgrind

| Erreur | Description | Gravite |
|--------|-------------|---------|
| Invalid read | Lecture memoire non allouee | Critique |
| Invalid write | Ecriture memoire non allouee | Critique |
| Invalid free | Double free ou free invalide | Critique |
| Definitely lost | Fuite certaine | Haute |
| Indirectly lost | Fuite via autre bloc perdu | Moyenne |
| Possibly lost | Pointeur interne perdu | Basse |
| Still reachable | Non libere mais accessible | Info |

#### 5.5.3 AddressSanitizer (ASAN)

Alternative a Valgrind, integre au compilateur:

```bash
# Compilation avec ASAN
gcc -fsanitize=address -g -o program program.c

# Execution detecte automatiquement les erreurs
./program
```

Avantages vs Valgrind:
- Plus rapide (~2x vs ~20x ralentissement)
- Detecte stack buffer overflow
- Messages plus clairs

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| NULL apres free | Evite use-after-free | `free(p); p = NULL;` |
| Verifier avant free | Evite double free | `if (p) { free(p); }` |
| Tracker allocations | Detecte leaks | Liste chainee |
| Valgrind en CI | Detecte regressions | `valgrind ./tests` |

### 5.7 Simulation avec trace d'execution

```
Programme:
  int *a = MALLOC(100);
  int *b = MALLOC(200);
  FREE(a);
  FREE(a);  // Double free!
  // Oubli FREE(b)

Trace:
1. MALLOC(100): malloc(100)=0x1000, ajoute block {ptr=0x1000, size=100, freed=false}
2. MALLOC(200): malloc(200)=0x2000, ajoute block {ptr=0x2000, size=200, freed=false}

Liste: [0x1000,100,false] -> [0x2000,200,false] -> NULL

3. FREE(0x1000): trouve block, freed=false -> ok, marque freed=true, free(0x1000)
4. FREE(0x1000): trouve block, freed=true -> ERREUR DOUBLE FREE!

Liste: [0x1000,100,true] -> [0x2000,200,false] -> NULL

5. mem_report_leaks():
   Parcourt liste, trouve block 0x2000 avec freed=false
   -> [LEAK] 200 bytes at 0x2000
```

### 5.8 Mnemotechniques

**"FNF" - Free Null Free**
- **F**ree le pointeur
- **N**ull le pointeur
- **F**ini (ne plus utiliser)

**"DVU" - Les 3 erreurs**
- **D**ouble free
- **V**agrind (outil)
- **U**se after free

### 5.9 Applications pratiques

1. **Testing**: Detecter les regressions memoire
2. **Code review**: Verifier la gestion memoire
3. **Debugging**: Trouver la source des crashes
4. **CI/CD**: Valgrind automatique dans les pipelines

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Detection | Solution |
|-------|----------|-----------|----------|
| Double free | Crash/corruption | Valgrind, tracker | ptr = NULL apres free |
| Memory leak | RAM croissante | Valgrind, tracker | Audit des allocations |
| Use after free | Donnees corrompues | ASAN, Valgrind | ptr = NULL apres free |
| Perte pointeur | Leak | Valgrind | Free avant reassign |

---

## SECTION 7 : QCM

### Question 1
Que se passe-t-il lors d'un double free ?

A) Le programme continue normalement
B) La memoire est liberee deux fois correctement
C) Comportement indefini, possible corruption du heap
D) Le compilateur refuse de compiler
E) Une exception est levee

**Reponse correcte: C**

### Question 2
Quel outil detecte les memory leaks a l'execution ?

A) GCC
B) GDB
C) Valgrind
D) Make
E) Lint

**Reponse correcte: C**

### Question 3
Comment prevenir le use-after-free ?

A) Ne jamais appeler free
B) Mettre le pointeur a NULL apres free
C) Utiliser des variables globales
D) Allouer sur la stack
E) Utiliser des pointeurs const

**Reponse correcte: B**

### Question 4
Que signifie "definitely lost" dans Valgrind ?

A) La memoire a ete corrompue
B) Le programme a crashe
C) Memoire allouee dont le pointeur a ete perdu
D) Erreur de compilation
E) Fichier non trouve

**Reponse correcte: C**

### Question 5
Pourquoi free(NULL) est-il safe ?

A) NULL n'est jamais alloue
B) Le standard C garantit que free(NULL) ne fait rien
C) Ca provoque une erreur silencieuse
D) Ca libere toute la memoire
E) Ce n'est pas safe

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Erreur | Cause | Consequence | Prevention |
|--------|-------|-------------|------------|
| Double free | free() deux fois | Corruption heap | ptr = NULL |
| Memory leak | Oubli free() | RAM saturee | Valgrind |
| Use after free | Acces post-free | Donnees corrompues | ptr = NULL |

| Outil | Usage | Commande |
|-------|-------|----------|
| Valgrind | Detection runtime | `valgrind --leak-check=full ./prog` |
| ASAN | Detection rapide | `gcc -fsanitize=address` |
| Custom tracker | Debugging | Macros MALLOC/FREE |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.3-a",
    "name": "memory_pitfalls",
    "module": "0.6.3",
    "phase": 0,
    "difficulty": 4,
    "xp": 300,
    "time_minutes": 240
  },
  "metadata": {
    "concepts": ["double_free", "memory_leak", "use_after_free", "valgrind"],
    "prerequisites": ["0.6.1", "0.6.2"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "memory_pitfalls.c",
    "header": "memory_pitfalls.h",
    "solution": "memory_pitfalls_solution.c",
    "test": "test_memory_pitfalls.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17", "-g"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "error_detection_required": true
  }
}
```
