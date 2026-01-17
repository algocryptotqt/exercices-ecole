# Exercice 0.6.13-a : valgrind

**Module :**
0.6.13 — Debugging Memoire

**Concept :**
a-c — memory leaks, invalid reads, debugging

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
pratique

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc), 0.6.2 (memory pitfalls)

**Domaines :**
Debug, Mem, Outils

**Duree estimee :**
150 min

**XP Base :**
250

**Complexite :**
T1 O(n) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `memory_bugs.c` (version corrigee)
- `memory_bugs_report.txt` (rapport d'analyse)

**Outils autorises :**
- `valgrind`, `gcc`, editeur de texte

### 1.2 Consigne

Utiliser Valgrind pour detecter et corriger des bugs memoire dans un programme C.

**Ta mission :**

Analyser un programme bugge avec Valgrind, identifier tous les problemes memoire, et les corriger.

**Programme a analyser (memory_bugs.c fourni) :**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Memory leak
char *create_message(const char *name)
{
    char *msg = malloc(100);
    sprintf(msg, "Hello, %s!", name);
    return msg;
}

// Bug 2: Use after free
void process_data(void)
{
    int *data = malloc(10 * sizeof(int));
    for (int i = 0; i < 10; i++)
        data[i] = i * 2;
    free(data);
    printf("First value: %d\n", data[0]);  // Use after free!
}

// Bug 3: Invalid read (buffer overflow)
void read_overflow(void)
{
    int *arr = malloc(5 * sizeof(int));
    for (int i = 0; i < 5; i++)
        arr[i] = i;
    printf("Value at index 10: %d\n", arr[10]);  // Out of bounds!
    free(arr);
}

// Bug 4: Invalid write (buffer overflow)
void write_overflow(void)
{
    char *str = malloc(10);
    strcpy(str, "This string is way too long for the buffer");
    printf("String: %s\n", str);
    free(str);
}

// Bug 5: Double free
void double_free_bug(void)
{
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    free(ptr);  // Double free!
}

// Bug 6: Uninitialized value
void uninitialized_bug(void)
{
    int *arr = malloc(5 * sizeof(int));
    int sum = 0;
    for (int i = 0; i < 5; i++)
        sum += arr[i];  // Using uninitialized memory!
    printf("Sum: %d\n", sum);
    free(arr);
}

// Bug 7: Memory leak in error path
char *read_file_content(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL)
        return NULL;

    char *buffer = malloc(1000);
    if (buffer == NULL)
        return NULL;  // Leak: f not closed!

    // Simulate read error
    if (fread(buffer, 1, 1000, f) == 0)
    {
        fclose(f);
        return NULL;  // Leak: buffer not freed!
    }

    fclose(f);
    return buffer;
}

int main(void)
{
    printf("=== Memory Bug Demo ===\n\n");

    // Uncomment each to test:
    char *msg = create_message("World");
    printf("%s\n", msg);
    // Leak: msg never freed!

    process_data();
    read_overflow();
    write_overflow();
    double_free_bug();
    uninitialized_bug();

    return 0;
}
```

**Taches a realiser :**

1. Compiler avec symboles debug: `gcc -g -std=c17 memory_bugs.c -o memory_bugs`
2. Executer avec Valgrind: `valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./memory_bugs`
3. Analyser la sortie de Valgrind
4. Creer un rapport (memory_bugs_report.txt) documentant chaque bug
5. Corriger tous les bugs dans memory_bugs.c

**Format du rapport :**
```
BUG #1: [Type de bug]
Location: [fichier:ligne]
Valgrind message: [message exact]
Cause: [explication]
Fix: [correction appliquee]
---
```

**Criteres de succes :**
- Valgrind ne rapporte aucune erreur apres correction
- "All heap blocks were freed -- no leaks are possible"
- Rapport complet et precis

### 1.3 Commandes Valgrind utiles

```bash
# Detection complete des leaks
valgrind --leak-check=full --show-leak-kinds=all ./program

# Avec origine des valeurs non initialisees
valgrind --track-origins=yes ./program

# Sortie vers fichier
valgrind --log-file=valgrind.log ./program

# Mode verbose
valgrind -v --leak-check=full ./program

# Detection des acces invalides
valgrind --tool=memcheck ./program
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Types d'erreurs Valgrind

| Erreur | Description |
|--------|-------------|
| Invalid read | Lecture hors allocation |
| Invalid write | Ecriture hors allocation |
| Invalid free | Double free ou free invalide |
| Definitely lost | Memoire perdue, aucun pointeur |
| Indirectly lost | Perdue car parent perdu |
| Possibly lost | Pointeur interne existe |
| Still reachable | Pointeur existe mais pas free |

### 2.2 Memcheck vs autres outils

Valgrind inclut plusieurs outils:
- **memcheck** (defaut): Erreurs memoire
- **cachegrind**: Simulation cache CPU
- **callgrind**: Profiling d'appels
- **massif**: Profiling heap
- **helgrind**: Detection race conditions

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Quality Assurance Engineer**

Valgrind est utilise pour:
- Tests de regression memoire
- Certification de code (aviation, medical)
- Validation avant release

**Metier : Security Researcher**

Detection de vulnerabilites:
- Buffer overflows (exploitables)
- Use after free (exploitables)
- Information leaks (donnees non initialisees)

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -g -std=c17 memory_bugs.c -o memory_bugs
$ valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./memory_bugs
==12345== Memcheck, a memory error detector
==12345== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==12345== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==12345== Command: ./memory_bugs
==12345==
=== Memory Bug Demo ===

Hello, World!
==12345== Invalid read of size 4
==12345==    at 0x401234: process_data (memory_bugs.c:18)
==12345==    by 0x401567: main (memory_bugs.c:78)
==12345==  Address 0x4a47040 is 0 bytes inside a block of size 40 free'd
==12345==    at 0x483CA3F: free (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401230: process_data (memory_bugs.c:17)
==12345==    by 0x401567: main (memory_bugs.c:78)
==12345==
First value: 0
==12345== Invalid read of size 4
==12345==    at 0x401280: read_overflow (memory_bugs.c:26)
==12345==    by 0x401570: main (memory_bugs.c:79)
==12345==  Address 0x4a470a8 is 20 bytes after a block of size 20 alloc'd
==12345==
[...]
==12345== HEAP SUMMARY:
==12345==     in use at exit: 100 bytes in 1 blocks
==12345==   total heap usage: 8 allocs, 8 frees, 1,284 bytes allocated
==12345==
==12345== 100 bytes in 1 blocks are definitely lost in loss record 1 of 1
==12345==    at 0x483B7F3: malloc (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401150: create_message (memory_bugs.c:8)
==12345==    by 0x401550: main (memory_bugs.c:75)
==12345==
==12345== LEAK SUMMARY:
==12345==    definitely lost: 100 bytes in 1 blocks
==12345==    indirectly lost: 0 bytes in 0 blocks
==12345==      possibly lost: 0 bytes in 0 blocks
==12345==    still reachable: 0 bytes in 0 blocks
==12345==         suppressed: 0 bytes in 0 blocks
==12345==
==12345== ERROR SUMMARY: 5 errors from 5 contexts

# Apres correction:
$ gcc -g -std=c17 memory_bugs_fixed.c -o memory_bugs_fixed
$ valgrind --leak-check=full ./memory_bugs_fixed
==12346== Memcheck, a memory error detector
[...]
==12346== HEAP SUMMARY:
==12346==     in use at exit: 0 bytes in 0 blocks
==12346==   total heap usage: 6 allocs, 6 frees, 1,184 bytes allocated
==12346==
==12346== All heap blocks were freed -- no leaks are possible
==12346==
==12346== ERROR SUMMARY: 0 errors from 0 contexts
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Utiliser des outils avances de detection memoire.

```bash
# AddressSanitizer (plus rapide que Valgrind)
gcc -fsanitize=address -g memory_bugs.c -o memory_bugs_asan
./memory_bugs_asan

# MemorySanitizer (valeurs non initialisees)
clang -fsanitize=memory -g memory_bugs.c -o memory_bugs_msan
./memory_bugs_msan

# UndefinedBehaviorSanitizer
gcc -fsanitize=undefined -g memory_bugs.c -o memory_bugs_ubsan
./memory_bugs_ubsan
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Verification | Points |
|---------|-------------|--------------|--------|
| T01 | No memory leaks | LEAK SUMMARY: 0 lost | 20 |
| T02 | No invalid reads | No "Invalid read" | 15 |
| T03 | No invalid writes | No "Invalid write" | 15 |
| T04 | No double free | No "Invalid free" | 15 |
| T05 | No uninitialized | No "uninitialised" | 15 |
| T06 | Report complete | All bugs documented | 10 |
| T07 | Report accurate | Correct descriptions | 10 |

### 4.2 Script de test

```bash
#!/bin/bash

pass=0
fail=0

# Compile
gcc -g -std=c17 memory_bugs.c -o memory_bugs 2>/dev/null
if [ $? -ne 0 ]; then
    echo "FAIL: Compilation failed"
    exit 1
fi

# Run Valgrind
output=$(valgrind --leak-check=full --error-exitcode=1 ./memory_bugs 2>&1)

# T01: No memory leaks
if echo "$output" | grep -q "All heap blocks were freed"; then
    echo "T01 PASS: No memory leaks"
    ((pass++))
else
    echo "T01 FAIL: Memory leaks detected"
    ((fail++))
fi

# T02: No invalid reads
if ! echo "$output" | grep -q "Invalid read"; then
    echo "T02 PASS: No invalid reads"
    ((pass++))
else
    echo "T02 FAIL: Invalid reads detected"
    ((fail++))
fi

# T03: No invalid writes
if ! echo "$output" | grep -q "Invalid write"; then
    echo "T03 PASS: No invalid writes"
    ((pass++))
else
    echo "T03 FAIL: Invalid writes detected"
    ((fail++))
fi

# T04: No double free
if ! echo "$output" | grep -q "Invalid free"; then
    echo "T04 PASS: No double free"
    ((pass++))
else
    echo "T04 FAIL: Double free detected"
    ((fail++))
fi

# T05: No uninitialized values
if ! echo "$output" | grep -qi "uninitialised\|uninitialized"; then
    echo "T05 PASS: No uninitialized values"
    ((pass++))
else
    echo "T05 FAIL: Uninitialized values used"
    ((fail++))
fi

# T06: Report exists
if [ -f "memory_bugs_report.txt" ]; then
    echo "T06 PASS: Report exists"
    ((pass++))
else
    echo "T06 FAIL: Report missing"
    ((fail++))
fi

# T07: Report contains bug descriptions
if grep -q "BUG #" memory_bugs_report.txt 2>/dev/null; then
    echo "T07 PASS: Report contains bug descriptions"
    ((pass++))
else
    echo "T07 FAIL: Report incomplete"
    ((fail++))
fi

echo ""
echo "Results: $pass passed, $fail failed"
rm -f memory_bugs
exit $fail
```

### 4.3 Solution de reference (memory_bugs.c corrige)

```c
/*
 * memory_bugs.c (CORRECTED VERSION)
 * All memory bugs fixed
 * Exercice ex36_valgrind
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: FIXED - Caller must free the returned message
char *create_message(const char *name)
{
    char *msg = malloc(100);
    if (msg == NULL)
        return NULL;
    sprintf(msg, "Hello, %s!", name);
    return msg;
}

// Bug 2: FIXED - Don't use after free
void process_data(void)
{
    int *data = malloc(10 * sizeof(int));
    if (data == NULL)
        return;

    for (int i = 0; i < 10; i++)
        data[i] = i * 2;

    int first_value = data[0];  // Save before free
    free(data);
    printf("First value: %d\n", first_value);  // Use saved value
}

// Bug 3: FIXED - Stay within bounds
void read_overflow(void)
{
    int *arr = malloc(5 * sizeof(int));
    if (arr == NULL)
        return;

    for (int i = 0; i < 5; i++)
        arr[i] = i;

    printf("Value at index 4: %d\n", arr[4]);  // Last valid index
    free(arr);
}

// Bug 4: FIXED - Allocate enough space
void write_overflow(void)
{
    const char *long_str = "This string is way too long for the buffer";
    char *str = malloc(strlen(long_str) + 1);  // Correct size
    if (str == NULL)
        return;

    strcpy(str, long_str);
    printf("String: %s\n", str);
    free(str);
}

// Bug 5: FIXED - No double free
void double_free_bug(void)
{
    int *ptr = malloc(sizeof(int));
    if (ptr == NULL)
        return;

    *ptr = 42;
    printf("Value: %d\n", *ptr);
    free(ptr);
    ptr = NULL;  // Set to NULL after free (good practice)
    // Removed second free(ptr);
}

// Bug 6: FIXED - Initialize memory
void uninitialized_bug(void)
{
    int *arr = calloc(5, sizeof(int));  // Use calloc to zero-initialize
    if (arr == NULL)
        return;

    int sum = 0;
    for (int i = 0; i < 5; i++)
        sum += arr[i];  // Now using initialized memory

    printf("Sum: %d\n", sum);
    free(arr);
}

// Bug 7: FIXED - Proper cleanup in error paths
char *read_file_content(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL)
        return NULL;

    char *buffer = malloc(1000);
    if (buffer == NULL)
    {
        fclose(f);  // FIXED: Close file before returning
        return NULL;
    }

    if (fread(buffer, 1, 1000, f) == 0)
    {
        free(buffer);  // FIXED: Free buffer before returning
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buffer;
}

int main(void)
{
    printf("=== Memory Bug Demo (FIXED) ===\n\n");

    char *msg = create_message("World");
    if (msg != NULL)
    {
        printf("%s\n", msg);
        free(msg);  // FIXED: Free allocated message
    }

    process_data();
    read_overflow();
    write_overflow();
    double_free_bug();
    uninitialized_bug();

    return 0;
}
```

### 4.4 Rapport de reference (memory_bugs_report.txt)

```
MEMORY BUGS ANALYSIS REPORT
===========================
File: memory_bugs.c
Tool: Valgrind memcheck
Date: 2024-01-15

---
BUG #1: Memory Leak (Definitely Lost)
Location: memory_bugs.c:8 (create_message)
Valgrind message:
  100 bytes in 1 blocks are definitely lost
  at malloc (create_message, line 8)
  by main (line 75)
Cause: Allocated memory for message never freed by caller
Fix: Added free(msg) in main() after using the message
---

BUG #2: Use After Free (Invalid Read)
Location: memory_bugs.c:18 (process_data)
Valgrind message:
  Invalid read of size 4
  Address is 0 bytes inside a block of size 40 free'd
Cause: Accessing data[0] after calling free(data)
Fix: Saved data[0] to local variable before calling free()
---

BUG #3: Buffer Overflow Read (Invalid Read)
Location: memory_bugs.c:26 (read_overflow)
Valgrind message:
  Invalid read of size 4
  Address is 20 bytes after a block of size 20 alloc'd
Cause: Accessing arr[10] when only indices 0-4 are valid
Fix: Changed arr[10] to arr[4] (last valid index)
---

BUG #4: Buffer Overflow Write (Invalid Write)
Location: memory_bugs.c:34 (write_overflow)
Valgrind message:
  Invalid write of size 1
  Address is 10 bytes after a block of size 10 alloc'd
Cause: Copying string longer than allocated buffer
Fix: Allocated strlen(long_str) + 1 bytes instead of 10
---

BUG #5: Double Free (Invalid Free)
Location: memory_bugs.c:42 (double_free_bug)
Valgrind message:
  Invalid free() / delete / delete[] / realloc()
  Address is 0 bytes inside a block of size 4 free'd
Cause: Calling free(ptr) twice on same pointer
Fix: Removed second free(), set ptr = NULL after first free
---

BUG #6: Use of Uninitialized Value
Location: memory_bugs.c:51 (uninitialized_bug)
Valgrind message:
  Conditional jump or move depends on uninitialised value(s)
  Uninitialised value was created by a heap allocation
Cause: Reading from malloc'd memory without initialization
Fix: Changed malloc() to calloc() which zero-initializes
---

BUG #7: Memory Leak in Error Path
Location: memory_bugs.c:60-61 (read_file_content)
Valgrind message:
  (Would show if error path was triggered)
Cause: FILE handle not closed when malloc fails,
       buffer not freed when fread fails
Fix: Added fclose(f) before return NULL on malloc failure,
     added free(buffer) before return NULL on fread failure
---

SUMMARY
=======
Total bugs found: 7
- Memory leaks: 2 (Bug #1, #7)
- Invalid reads: 2 (Bug #2, #3)
- Invalid writes: 1 (Bug #4)
- Invalid frees: 1 (Bug #5)
- Uninitialized values: 1 (Bug #6)

All bugs have been fixed and verified with Valgrind.
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.13-a",
  "name": "valgrind",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["memory_bugs.c", "memory_bugs_report.txt"],
    "provided": ["memory_bugs_original.c"],
    "test": ["test_valgrind.sh"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-g", "-std=c17"]
  },
  "tests": {
    "type": "valgrind",
    "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
  },
  "scoring": {
    "total": 100,
    "no_leaks": 20,
    "no_invalid_access": 30,
    "no_double_free": 15,
    "no_uninitialized": 15,
    "report_quality": 20
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Leak): Oubli de free msg
int main(void)
{
    char *msg = create_message("World");
    printf("%s\n", msg);
    // Manque free(msg)!
    return 0;
}
// Detection: Valgrind "definitely lost"

// MUTANT 2 (UAF): Use after free persiste
void process_data(void)
{
    int *data = malloc(10 * sizeof(int));
    free(data);
    printf("%d\n", data[0]);  // Toujours UAF!
}
// Detection: Valgrind "Invalid read"

// MUTANT 3 (Overflow): Off by one
void read_overflow(void)
{
    int *arr = malloc(5 * sizeof(int));
    printf("%d\n", arr[5]);  // Index 5 invalide!
    free(arr);
}
// Detection: Valgrind "Invalid read"

// MUTANT 4 (Double free): NULL check insuffisant
void double_free_bug(void)
{
    int *ptr = malloc(sizeof(int));
    free(ptr);
    if (ptr != NULL)  // ptr != NULL meme apres free!
        free(ptr);
}
// Detection: Valgrind "Invalid free"

// MUTANT 5 (Uninit): malloc au lieu de calloc
void uninitialized_bug(void)
{
    int *arr = malloc(5 * sizeof(int));  // Pas initialise!
    int sum = arr[0] + arr[1];
    free(arr);
}
// Detection: Valgrind "uninitialised value"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux de Valgrind** :

1. **Memory leaks** - Detection de memoire non liberee
2. **Invalid reads/writes** - Acces hors limites
3. **Debugging** - Interpretation des messages

### 5.2 LDA - Traduction Litterale en Francais

```
PROCEDURE analyser_avec_valgrind(programme):
DEBUT
    executer("valgrind --leak-check=full " + programme)

    POUR CHAQUE erreur DANS sortie_valgrind FAIRE
        SI erreur EST "Invalid read" ALORS
            identifier_ligne_source()
            verifier_bornes_tableau()
            verifier_use_after_free()
        SINON SI erreur EST "definitely lost" ALORS
            identifier_allocation()
            ajouter_free_manquant()
        SINON SI erreur EST "Invalid free" ALORS
            verifier_double_free()
            verifier_free_stack_memory()
        FIN SI
    FIN POUR
FIN
```

### 5.3 Visualisation ASCII

```
MEMOIRE VUE PAR VALGRIND
========================

Heap apres malloc(20):
+------------------+
| Metadata (8 bytes)|  <- Valgrind tracking info
+------------------+
| Red zone (8 bytes)|  <- Guard zone before
+------------------+
|                  |
| User data        |  <- 20 bytes allocated
| (20 bytes)       |
|                  |
+------------------+
| Red zone (8 bytes)|  <- Guard zone after
+------------------+

DETECTION DES ERREURS:
======================

Invalid read (buffer overflow):
arr = malloc(20);  // 5 ints
arr[10] = 42;      // Acces a red zone!
                         |
+--------+--------+------v-----+--------+
| Header | Guard  | [5 ints]   | Guard  |
+--------+--------+------------+--------+
                              ^
                         Violation detectee!

Memory leak:
main() {
    ptr = malloc(100);  // Allocation tracee
    // ... pas de free ...
}  // Fin: ptr perdu mais memoire toujours allouee!

Valgrind liste:
- Adresse d'allocation
- Taille
- Call stack

Use After Free:
ptr = malloc(100);
free(ptr);          // Memoire marquee "freed"
*ptr = 42;          // Acces a memoire freed!
                         |
+--------+--------+------v----------------+
| Header | Guard  | FREED BLOCK           |
+--------+--------+-----------------------+
                  ^
           Violation detectee!
```

### 5.4 Les pieges en detail

#### Piege 1: Ignorer les warnings "possibly lost"
```
==12345== 100 bytes in 1 blocks are possibly lost
```
Signifie qu'un pointeur interne existe (ex: pointeur vers milieu de bloc).
Peut indiquer un bug subtil.

#### Piege 2: Ne pas utiliser -g
```bash
# FAUX - pas de numeros de ligne
gcc memory_bugs.c -o memory_bugs
valgrind ./memory_bugs

# CORRECT - avec symboles debug
gcc -g memory_bugs.c -o memory_bugs
valgrind ./memory_bugs
```

### 5.5 Cours Complet

#### 5.5.1 Options essentielles

```bash
# Detection complete
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         ./program
```

| Option | Description |
|--------|-------------|
| --leak-check=full | Details sur chaque leak |
| --show-leak-kinds=all | Tous types de leaks |
| --track-origins=yes | Origine des valeurs non-init |
| --error-exitcode=N | Exit code si erreurs |
| --log-file=FILE | Sortie vers fichier |

#### 5.5.2 Interpreter la sortie

```
==PID== Error type
==PID==    at 0x...: function_name (file.c:line)
==PID==    by 0x...: caller_function (file.c:line)
==PID==    by 0x...: main (file.c:line)
==PID==  Address 0x... is N bytes inside/after a block of size M
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Action |
|-------|-------------|--------|
| Compiler avec -g | Numeros de ligne | `gcc -g` |
| Analyser toute sortie | Ne pas ignorer warnings | Lire attentivement |
| Corriger par priorite | Cascading errors | Commencer par premier |
| Re-tester apres fix | Confirmer correction | `valgrind` apres chaque fix |

### 5.7 Simulation avec trace d'execution

```
$ valgrind ./memory_bugs

1. Valgrind demarre
   - Instrumente le binaire
   - Track toutes les allocations

2. malloc(100) dans create_message()
   - Valgrind enregistre:
     - Adresse: 0x4a47000
     - Taille: 100 bytes
     - Call stack: create_message <- main

3. printf("%s\n", msg)
   - Acces valide, dans les bornes

4. Programme termine sans free(msg)
   - Valgrind detecte 0x4a47000 jamais libere
   - Aucun pointeur ne reference plus ce bloc
   - -> "definitely lost"

5. Rapport final:
   LEAK SUMMARY:
      definitely lost: 100 bytes in 1 blocks
```

### 5.8 Mnemotechniques

**"DRUIF" - Types d'erreurs**
- **D**efinitely lost: Aucun pointeur
- **R**eachable: Pointeur existe, pas free
- **U**ninitialized: Valeur jamais initialisee
- **I**nvalid access: Read/write hors bornes
- **F**ree invalide: Double free ou mauvais ptr

**"GTL" - Workflow debug**
- **G**cc -g (symboles)
- **T**est avec Valgrind
- **L**ire et corriger

### 5.9 Applications pratiques

1. **CI/CD**: Tests automatises avec Valgrind
2. **Code review**: Verification memoire
3. **Security audit**: Detection vulnerabilites
4. **Performance**: Identification des leaks

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de -g | Pas de lignes | Compiler avec -g |
| Ignorer warnings | Bugs subtils | Analyser tout |
| Corriger sans re-test | Bug persiste | Re-valgrind |
| Leak dans error path | Fuite conditionnelle | Test tous chemins |

---

## SECTION 7 : QCM

### Question 1
Que signifie "definitely lost" dans Valgrind ?

A) Memoire corrompue
B) Memoire allouee mais pointeur perdu
C) Acces hors limites
D) Double free
E) Erreur de compilation

**Reponse correcte: B**

### Question 2
Pourquoi compiler avec -g avant d'utiliser Valgrind ?

A) Pour accelerer Valgrind
B) Pour avoir les numeros de ligne
C) C'est obligatoire
D) Pour eviter les faux positifs
E) Pour optimiser le code

**Reponse correcte: B**

### Question 3
Comment Valgrind detecte un buffer overflow ?

A) Il lit le code source
B) Il utilise des zones de garde autour des allocations
C) Il compare avec une reference
D) Il utilise le compilateur
E) Il ne peut pas le detecter

**Reponse correcte: B**

### Question 4
Que detecte --track-origins=yes ?

A) L'origine des memory leaks
B) L'origine des valeurs non initialisees
C) L'origine des fichiers sources
D) L'origine des threads
E) L'origine des erreurs de syntaxe

**Reponse correcte: B**

### Question 5
Quelle erreur Valgrind NE detecte PAS ?

A) Memory leak
B) Buffer overflow dynamique
C) Buffer overflow sur la stack (parfois)
D) Double free
E) Use after free

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Erreur Valgrind | Cause | Solution |
|-----------------|-------|----------|
| definitely lost | Pas de free | Ajouter free |
| Invalid read | Acces hors bornes | Verifier indices |
| Invalid write | Ecriture hors bornes | Verifier taille |
| Invalid free | Double free | Set ptr=NULL |
| uninitialised | Pas d'init | calloc ou init |

| Option | Description |
|--------|-------------|
| --leak-check=full | Details leaks |
| --track-origins=yes | Origine non-init |
| --error-exitcode=1 | Exit si erreur |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.13-a",
    "name": "valgrind",
    "module": "0.6.13",
    "phase": 0,
    "difficulty": 4,
    "xp": 250,
    "time_minutes": 150
  },
  "metadata": {
    "concepts": ["memory leaks", "invalid reads", "debugging"],
    "prerequisites": ["0.6.1", "0.6.2"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "memory_bugs.c",
    "report_template": "memory_bugs_report.txt",
    "solution": "memory_bugs_fixed.c",
    "test": "test_valgrind.sh"
  },
  "tools": {
    "required": ["valgrind", "gcc"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "no_errors_weight": 80,
    "report_weight": 20
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 5
  }
}
```
