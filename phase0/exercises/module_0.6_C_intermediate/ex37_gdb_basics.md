# Exercice 0.6.14-a : gdb_basics

**Module :**
0.6.14 — Debugging Interactif

**Concept :**
a-d — breakpoints, step, print, backtrace

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
pratique

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5 (bases C), ligne de commande

**Domaines :**
Debug, Outils, Developpement

**Duree estimee :**
150 min

**XP Base :**
250

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `debug_exercise.c` (version corrigee)
- `gdb_session.txt` (transcript de session GDB)

**Outils autorises :**
- `gdb`, `gcc`, editeur de texte

### 1.2 Consigne

Utiliser GDB pour debugger un programme C contenant des bugs logiques.

**Ta mission :**

Apprendre les commandes essentielles de GDB et les utiliser pour trouver et corriger des bugs dans un programme.

**Programme a debugger (debug_exercise.c) :**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Logic error in factorial
int factorial(int n)
{
    int result = 0;  // Bug: should be 1
    for (int i = 1; i <= n; i++)
    {
        result *= i;
    }
    return result;
}

// Bug 2: Off-by-one in array sum
int array_sum(int *arr, int size)
{
    int sum = 0;
    for (int i = 0; i <= size; i++)  // Bug: should be i < size
    {
        sum += arr[i];
    }
    return sum;
}

// Bug 3: Wrong condition in binary search
int binary_search(int *arr, int size, int target)
{
    int left = 0;
    int right = size - 1;

    while (left < right)  // Bug: should be left <= right
    {
        int mid = left + (right - left) / 2;
        if (arr[mid] == target)
            return mid;
        else if (arr[mid] < target)
            left = mid + 1;
        else
            right = mid - 1;
    }
    return -1;
}

// Bug 4: Infinite loop
void count_down(int n)
{
    while (n > 0)
    {
        printf("%d ", n);
        // Bug: missing n--;
    }
    printf("Blast off!\n");
}

// Bug 5: Wrong pointer arithmetic
void reverse_string(char *str)
{
    int len = strlen(str);
    char *start = str;
    char *end = str + len;  // Bug: should be str + len - 1

    while (start < end)
    {
        char temp = *start;
        *start = *end;
        *end = temp;
        start++;
        end--;
    }
}

// Bug 6: Segfault on NULL
int string_length(char *str)
{
    int len = 0;
    while (str[len] != '\0')  // Bug: no NULL check
    {
        len++;
    }
    return len;
}

int main(int argc, char *argv[])
{
    printf("=== GDB Debug Exercise ===\n\n");

    // Test factorial
    printf("Factorial(5) = %d (expected 120)\n", factorial(5));

    // Test array_sum
    int arr[] = {1, 2, 3, 4, 5};
    printf("Sum = %d (expected 15)\n", array_sum(arr, 5));

    // Test binary_search
    int sorted[] = {1, 3, 5, 7, 9, 11, 13};
    printf("Search 7: index %d (expected 3)\n", binary_search(sorted, 7, 7));
    printf("Search 1: index %d (expected 0)\n", binary_search(sorted, 7, 1));

    // Test count_down (commented out - infinite loop!)
    // count_down(5);

    // Test reverse_string
    char test[] = "hello";
    reverse_string(test);
    printf("Reversed: %s (expected olleh)\n", test);

    // Test string_length
    printf("Length of 'hello': %d\n", string_length("hello"));
    // printf("Length of NULL: %d\n", string_length(NULL));  // Would crash!

    return 0;
}
```

**Taches a realiser :**

1. Compiler avec debug: `gcc -g -O0 -std=c17 debug_exercise.c -o debug_exercise`
2. Demarrer GDB: `gdb ./debug_exercise`
3. Pour chaque bug:
   - Poser un breakpoint
   - Executer jusqu'au breakpoint
   - Inspecter les variables
   - Identifier le bug
   - Documenter dans gdb_session.txt
4. Corriger tous les bugs

**Commandes GDB requises :**
```
break (b)       - Poser un breakpoint
run (r)         - Lancer le programme
continue (c)    - Continuer l'execution
next (n)        - Executer ligne suivante (sans entrer dans fonctions)
step (s)        - Executer ligne suivante (entre dans fonctions)
print (p)       - Afficher valeur d'une variable
backtrace (bt)  - Afficher la pile d'appels
info locals     - Afficher variables locales
info args       - Afficher arguments de la fonction
watch           - Point d'arret sur modification de variable
quit (q)        - Quitter GDB
```

**Format du transcript (gdb_session.txt) :**
```
BUG #1: [Description]
======================
(gdb) break factorial
Breakpoint 1 at 0x401234: file debug_exercise.c, line 8.
(gdb) run
Starting program: ./debug_exercise

Breakpoint 1, factorial (n=5) at debug_exercise.c:8
8           int result = 0;
(gdb) next
9           for (int i = 1; i <= n; i++)
(gdb) print result
$1 = 0
(gdb) [... suite de la session ...]

Analysis: result is initialized to 0, causing multiplication to always be 0
Fix: Change "int result = 0" to "int result = 1"
---
```

### 1.3 Commandes GDB utiles

```bash
# Demarrer GDB
gdb ./program
gdb -tui ./program  # Mode interface texte

# Breakpoints
break main          # Sur fonction
break file.c:42     # Sur ligne
break func if x>10  # Conditionnel
delete 1            # Supprimer breakpoint 1
disable 1           # Desactiver
enable 1            # Reactiver
info breakpoints    # Lister

# Execution
run                 # Demarrer
run arg1 arg2       # Avec arguments
continue            # Continuer
next                # Ligne suivante
step                # Entrer dans fonction
finish              # Finir fonction courante
until               # Jusqu'a ligne suivante

# Inspection
print var           # Afficher variable
print *ptr          # Dereferencer
print arr[0]@5      # 5 elements de arr
display var         # Afficher a chaque stop
x/10xw addr         # Examiner memoire
info locals         # Variables locales
info args           # Arguments
backtrace           # Pile d'appels
frame 2             # Aller au frame 2

# Modification
set var = value     # Modifier variable
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 GDB vs autres debuggers

| Debugger | Plateforme | Interface |
|----------|------------|-----------|
| GDB | Linux, macOS, Windows | CLI, TUI |
| LLDB | macOS, Linux | CLI |
| Visual Studio Debugger | Windows | GUI |
| Delve | Go | CLI |

### 2.2 Extensions GDB

- **gdb-dashboard**: Interface moderne
- **pwndbg**: Pour reverse engineering
- **gef**: GDB Enhanced Features
- **Voltron**: Multi-pane debugger

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Systems Programmer**

GDB est essentiel pour:
- Debug de drivers
- Analyse de core dumps
- Debug kernel (KGDB)

**Metier : Security Researcher**

GDB pour:
- Reverse engineering
- Exploit development
- Analyse de malware

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -g -O0 -std=c17 debug_exercise.c -o debug_exercise
$ gdb ./debug_exercise
GNU gdb (GDB) 12.1
[...]
Reading symbols from ./debug_exercise...
(gdb) break factorial
Breakpoint 1 at 0x401156: file debug_exercise.c, line 8.
(gdb) run
Starting program: /home/user/debug_exercise
=== GDB Debug Exercise ===

Breakpoint 1, factorial (n=5) at debug_exercise.c:8
8           int result = 0;
(gdb) next
9           for (int i = 1; i <= n; i++)
(gdb) print result
$1 = 0
(gdb) next
11              result *= i;
(gdb) print i
$2 = 1
(gdb) next
9           for (int i = 1; i <= n; i++)
(gdb) print result
$3 = 0
(gdb) # Aha! result reste 0 car 0 * n = 0
(gdb) continue
Continuing.
Factorial(5) = 0 (expected 120)
[...]
(gdb) quit

# Apres correction:
$ ./debug_exercise
=== GDB Debug Exercise ===

Factorial(5) = 120 (expected 120)
Sum = 15 (expected 15)
Search 7: index 3 (expected 3)
Search 1: index 0 (expected 0)
Reversed: olleh (expected olleh)
Length of 'hello': 5
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Utiliser des fonctionnalites avancees de GDB.

```bash
# Remote debugging
gdbserver :1234 ./program
gdb -ex "target remote :1234" ./program

# Core dump analysis
ulimit -c unlimited
./crash_program
gdb ./crash_program core

# Scripting GDB
gdb -x commands.gdb ./program

# Python extension
(gdb) python
>>> gdb.execute("info registers")
>>> end
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Verification | Points |
|---------|-------------|--------------|--------|
| T01 | factorial correct | factorial(5) == 120 | 15 |
| T02 | array_sum correct | sum == 15 | 15 |
| T03 | binary_search correct | found at correct index | 15 |
| T04 | count_down terminates | no infinite loop | 15 |
| T05 | reverse_string correct | "olleh" | 15 |
| T06 | NULL check added | no crash on NULL | 10 |
| T07 | GDB session complete | All bugs documented | 15 |

### 4.2 Script de test

```bash
#!/bin/bash

pass=0
fail=0

# Compile
gcc -g -O0 -std=c17 debug_exercise.c -o debug_exercise 2>/dev/null
if [ $? -ne 0 ]; then
    echo "FAIL: Compilation failed"
    exit 1
fi

# Run and capture output
output=$(timeout 5 ./debug_exercise 2>&1)

# T01: factorial
if echo "$output" | grep -q "Factorial(5) = 120"; then
    echo "T01 PASS: factorial correct"
    ((pass++))
else
    echo "T01 FAIL: factorial incorrect"
    ((fail++))
fi

# T02: array_sum
if echo "$output" | grep -q "Sum = 15"; then
    echo "T02 PASS: array_sum correct"
    ((pass++))
else
    echo "T02 FAIL: array_sum incorrect"
    ((fail++))
fi

# T03: binary_search
if echo "$output" | grep -q "Search 7: index 3" && \
   echo "$output" | grep -q "Search 1: index 0"; then
    echo "T03 PASS: binary_search correct"
    ((pass++))
else
    echo "T03 FAIL: binary_search incorrect"
    ((fail++))
fi

# T04: count_down (check it doesn't hang)
# This is tested implicitly by the timeout

# T05: reverse_string
if echo "$output" | grep -q "Reversed: olleh"; then
    echo "T05 PASS: reverse_string correct"
    ((pass++))
else
    echo "T05 FAIL: reverse_string incorrect"
    ((fail++))
fi

# T06: NULL check (add test code)
cat >> test_null.c << 'EOF'
#include <stdio.h>
extern int string_length(char *str);
int main() {
    int len = string_length(NULL);
    printf("NULL length: %d\n", len);
    return 0;
}
EOF
gcc -g -std=c17 -c debug_exercise.c -o debug_exercise.o 2>/dev/null
gcc debug_exercise.o test_null.c -o test_null 2>/dev/null
if timeout 2 ./test_null >/dev/null 2>&1; then
    echo "T06 PASS: NULL check works"
    ((pass++))
else
    echo "T06 FAIL: crashes on NULL"
    ((fail++))
fi
rm -f test_null test_null.c debug_exercise.o

# T07: GDB session file
if [ -f "gdb_session.txt" ] && grep -q "BUG #" gdb_session.txt; then
    echo "T07 PASS: GDB session documented"
    ((pass++))
else
    echo "T07 FAIL: GDB session missing or incomplete"
    ((fail++))
fi

rm -f debug_exercise
echo ""
echo "Results: $pass passed, $fail failed"
exit $fail
```

### 4.3 Solution de reference (debug_exercise.c corrige)

```c
/*
 * debug_exercise.c (CORRECTED VERSION)
 * All logic bugs fixed using GDB
 * Exercice ex37_gdb_basics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: FIXED - result initialized to 1
int factorial(int n)
{
    if (n < 0)
        return -1;  // Error case

    int result = 1;  // FIXED: was 0
    for (int i = 1; i <= n; i++)
    {
        result *= i;
    }
    return result;
}

// Bug 2: FIXED - correct loop bound
int array_sum(int *arr, int size)
{
    if (arr == NULL || size <= 0)
        return 0;

    int sum = 0;
    for (int i = 0; i < size; i++)  // FIXED: was i <= size
    {
        sum += arr[i];
    }
    return sum;
}

// Bug 3: FIXED - correct while condition
int binary_search(int *arr, int size, int target)
{
    if (arr == NULL || size <= 0)
        return -1;

    int left = 0;
    int right = size - 1;

    while (left <= right)  // FIXED: was left < right
    {
        int mid = left + (right - left) / 2;
        if (arr[mid] == target)
            return mid;
        else if (arr[mid] < target)
            left = mid + 1;
        else
            right = mid - 1;
    }
    return -1;
}

// Bug 4: FIXED - decrement n
void count_down(int n)
{
    while (n > 0)
    {
        printf("%d ", n);
        n--;  // FIXED: was missing
    }
    printf("Blast off!\n");
}

// Bug 5: FIXED - correct end pointer
void reverse_string(char *str)
{
    if (str == NULL)
        return;

    int len = strlen(str);
    if (len <= 1)
        return;

    char *start = str;
    char *end = str + len - 1;  // FIXED: was str + len

    while (start < end)
    {
        char temp = *start;
        *start = *end;
        *end = temp;
        start++;
        end--;
    }
}

// Bug 6: FIXED - NULL check added
int string_length(char *str)
{
    if (str == NULL)  // FIXED: added NULL check
        return 0;

    int len = 0;
    while (str[len] != '\0')
    {
        len++;
    }
    return len;
}

int main(int argc, char *argv[])
{
    printf("=== GDB Debug Exercise (FIXED) ===\n\n");

    // Test factorial
    printf("Factorial(5) = %d (expected 120)\n", factorial(5));
    printf("Factorial(0) = %d (expected 1)\n", factorial(0));

    // Test array_sum
    int arr[] = {1, 2, 3, 4, 5};
    printf("Sum = %d (expected 15)\n", array_sum(arr, 5));

    // Test binary_search
    int sorted[] = {1, 3, 5, 7, 9, 11, 13};
    printf("Search 7: index %d (expected 3)\n", binary_search(sorted, 7, 7));
    printf("Search 1: index %d (expected 0)\n", binary_search(sorted, 7, 1));
    printf("Search 13: index %d (expected 6)\n", binary_search(sorted, 7, 13));
    printf("Search 100: index %d (expected -1)\n", binary_search(sorted, 7, 100));

    // Test count_down (now safe to run)
    printf("Countdown: ");
    count_down(5);

    // Test reverse_string
    char test[] = "hello";
    reverse_string(test);
    printf("Reversed: %s (expected olleh)\n", test);

    // Test string_length with NULL (now safe)
    printf("Length of 'hello': %d\n", string_length("hello"));
    printf("Length of NULL: %d\n", string_length(NULL));

    return 0;
}
```

### 4.4 Exemple de gdb_session.txt

```
GDB SESSION TRANSCRIPT
======================
File: debug_exercise.c
Date: 2024-01-15

---
BUG #1: factorial returns 0 for all inputs
=========================================

(gdb) break factorial
Breakpoint 1 at 0x401156: file debug_exercise.c, line 8.
(gdb) run
Starting program: ./debug_exercise
=== GDB Debug Exercise ===

Breakpoint 1, factorial (n=5) at debug_exercise.c:8
8           int result = 0;
(gdb) next
9           for (int i = 1; i <= n; i++)
(gdb) print result
$1 = 0
(gdb) next
11              result *= i;
(gdb) print i
$2 = 1
(gdb) print result
$3 = 0
(gdb) # result = 0 * 1 = 0, will always stay 0!
(gdb) continue
Continuing.
Factorial(5) = 0 (expected 120)

Analysis: result is initialized to 0. Since 0 * anything = 0,
the factorial calculation never produces correct result.

Fix: Change "int result = 0" to "int result = 1"

---
BUG #2: array_sum reads past end of array
=========================================

(gdb) break array_sum
Breakpoint 2 at 0x401189
(gdb) run
[...]
Breakpoint 2, array_sum (arr=0x7fffffffde30, size=5) at debug_exercise.c:18
18          int sum = 0;
(gdb) print size
$4 = 5
(gdb) next
19          for (int i = 0; i <= size; i++)
(gdb) # Notice: i <= size means i goes 0,1,2,3,4,5 (6 iterations!)
(gdb) # But array only has indices 0-4

Analysis: Loop condition "i <= size" iterates 6 times for size=5,
accessing arr[5] which is out of bounds.

Fix: Change "i <= size" to "i < size"

---
BUG #3: binary_search fails for edge elements
=============================================

(gdb) break binary_search
Breakpoint 3 at 0x4011c8
(gdb) run
[...]
(gdb) # Testing search for value 1 (first element)
(gdb) print left
$5 = 0
(gdb) print right
$6 = 6
(gdb) # Watch what happens when target is at left boundary
(gdb) next
[... stepping through ...]
(gdb) # When left == right, loop exits without checking that element!

Analysis: "while (left < right)" exits when left equals right,
missing the case where target is at that exact position.

Fix: Change "while (left < right)" to "while (left <= right)"

---
BUG #4: count_down infinite loop
================================

(gdb) break count_down
Breakpoint 4 at 0x401210
(gdb) run
[...]
(gdb) print n
$7 = 5
(gdb) next
45          printf("%d ", n);
(gdb) next
43      while (n > 0)
(gdb) print n
$8 = 5
(gdb) # n never changes! It stays 5 forever.

Analysis: The while loop decrements nothing. n stays at initial value,
creating an infinite loop.

Fix: Add "n--;" inside the while loop.

---
BUG #5: reverse_string overwrites wrong character
=================================================

(gdb) break reverse_string
Breakpoint 5 at 0x401240
(gdb) run
[...]
(gdb) print str
$9 = 0x7fffffffde40 "hello"
(gdb) print strlen(str)
$10 = 5
(gdb) print end
$11 = 0x7fffffffde45 ""
(gdb) # end points to '\0' (null terminator), not last char 'o'!
(gdb) print *end
$12 = 0 '\000'

Analysis: "end = str + len" points to the null terminator ('\0'),
not the last character. This corrupts the string.

Fix: Change "str + len" to "str + len - 1"

---
BUG #6: string_length crashes on NULL
=====================================

(gdb) break string_length
Breakpoint 6 at 0x401290
(gdb) run
[...]
(gdb) # Manually calling with NULL would crash
(gdb) call string_length(0)
Program received signal SIGSEGV, Segmentation fault.

Analysis: No NULL check before accessing str[len].
Dereferencing NULL causes segmentation fault.

Fix: Add "if (str == NULL) return 0;" at function start.

---
SUMMARY
=======
All 6 bugs identified and fixed using GDB:
1. factorial: result init 0 -> 1
2. array_sum: i <= size -> i < size
3. binary_search: left < right -> left <= right
4. count_down: added n--;
5. reverse_string: str + len -> str + len - 1
6. string_length: added NULL check
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.14-a",
  "name": "gdb_basics",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["debug_exercise.c", "gdb_session.txt"],
    "provided": ["debug_exercise_buggy.c"],
    "test": ["test_gdb.sh"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-g", "-O0", "-std=c17"]
  },
  "tests": {
    "type": "output_compare",
    "timeout": 5
  },
  "scoring": {
    "total": 100,
    "correct_output": 75,
    "gdb_session_quality": 25
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Off-by-one): Mauvaise correction factorial
int factorial(int n)
{
    int result = 1;
    for (int i = 0; i <= n; i++)  // Commence a 0!
        result *= i;  // 1 * 0 = 0!
    return result;
}
// Detection: Toujours 0

// MUTANT 2 (Boundary): array_sum encore faux
int array_sum(int *arr, int size)
{
    int sum = 0;
    for (int i = 1; i < size; i++)  // Commence a 1!
        sum += arr[i];
    return sum;
}
// Detection: Manque arr[0]

// MUTANT 3 (Logic): binary_search avec mauvais mid
int binary_search(...)
{
    int mid = (left + right) / 2;  // Overflow possible!
    // ...
}
// Detection: Mauvais resultat sur grands tableaux

// MUTANT 4 (Logic): count_down decremente avant print
void count_down(int n)
{
    while (n > 0)
    {
        n--;
        printf("%d ", n);  // Affiche 4,3,2,1,0 au lieu de 5,4,3,2,1
    }
}
// Detection: Mauvais output

// MUTANT 5 (Null): string_length retourne -1 pour NULL
int string_length(char *str)
{
    if (str == NULL)
        return -1;  // Devrait etre 0 ou erreur coherente
    // ...
}
// Detection: Comportement inconsistant
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux de GDB** :

1. **breakpoints** - Arreter l'execution
2. **step/next** - Execution pas a pas
3. **print** - Inspecter les variables
4. **backtrace** - Voir la pile d'appels

### 5.2 LDA - Traduction Litterale en Francais

```
PROCEDURE debugger_avec_gdb(programme, bug):
DEBUT
    charger_programme(programme)

    TANT QUE bug_non_trouve FAIRE
        poser_breakpoint(fonction_suspecte)
        lancer_programme()

        A chaque arret:
            afficher_variables_locales()
            verifier_valeurs_attendues()

            SI valeur_inattendue ALORS
                bug_trouve <- VRAI
                noter_ligne_et_cause()
            SINON
                executer_ligne_suivante()
            FIN SI
    FIN TANT QUE

    corriger_code()
    re-tester()
FIN
```

### 5.3 Visualisation ASCII

```
EXECUTION AVEC GDB
==================

Code source:
    1: int factorial(int n)
    2: {
    3:     int result = 0;    <-- Breakpoint ici
    4:     for (int i = 1; i <= n; i++)
    5:     {
    6:         result *= i;
    7:     }
    8:     return result;
    9: }

Session GDB:
+------------------------------------------+
| (gdb) break factorial                     |
| Breakpoint 1 at 0x401156: line 3         |
| (gdb) run                                 |
|                                           |
| Breakpoint 1, factorial (n=5) at line 3  |
| 3:     int result = 0;                   |
| (gdb) _                                   |
+------------------------------------------+

COMMANDES DE NAVIGATION:
========================

        start
          |
          v
    +-- break ---+
    |            |
    v            v
  [STOP]      [RUN]
    |            |
    +---+  +-----+
        |  |
        v  v
      next/step
          |
    +-----+-----+
    |           |
    v           v
  next        step
(same level) (into func)

PILE D'APPELS (backtrace):
==========================

(gdb) bt
#0  factorial (n=5) at debug.c:6
#1  0x00401567 in main () at debug.c:45
    ^                        ^
    |                        |
  Frame 0                 Frame 1
  (current)              (caller)
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier -g a la compilation
```bash
# FAUX - pas de symboles debug
gcc program.c -o program
gdb ./program
# -> Pas de numeros de ligne, pas de noms de variables

# CORRECT
gcc -g program.c -o program
gdb ./program
# -> Informations completes
```

#### Piege 2: Optimisations brouillent le debug
```bash
# FAUX - code optimise, execution non-lineaire
gcc -g -O2 program.c -o program

# CORRECT
gcc -g -O0 program.c -o program
```

### 5.5 Cours Complet

#### 5.5.1 Demarrer GDB

```bash
gdb ./program              # Charger programme
gdb -tui ./program         # Mode interface texte
gdb -q ./program           # Mode silencieux
```

#### 5.5.2 Breakpoints

```
break main              # Sur fonction
break file.c:42         # Sur ligne
break func if x > 10    # Conditionnel
tbreak func             # Temporaire (une fois)
watch var               # Sur modification
rwatch var              # Sur lecture
awatch var              # Sur acces
```

#### 5.5.3 Execution

| Commande | Description |
|----------|-------------|
| run | Demarrer |
| continue | Reprendre |
| next | Ligne suivante |
| step | Entrer dans fonction |
| finish | Finir fonction |
| until N | Jusqu'a ligne N |

#### 5.5.4 Inspection

```
print var               # Variable
print *ptr              # Dereference
print arr[0]@5          # 5 elements
print/x var             # Hexa
print/t var             # Binaire
x/10xw addr             # 10 words hexa
info locals             # Variables locales
info args               # Arguments
backtrace               # Pile d'appels
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| -g -O0 | Debug symbols | `gcc -g -O0` |
| Breakpoint strategique | Avant le bug | `break suspect_func` |
| Verifier hypotheses | print avant/apres | `print var` |
| Documenter | Reproduire le bug | Session log |

### 5.7 Simulation avec trace d'execution

```
Programme: factorial(5)
Bug: result = 0 au lieu de 1

(gdb) break factorial
(gdb) run

-> Execution atteint factorial(), s'arrete ligne 3

(gdb) next
-> Execute "int result = 0;"

(gdb) print result
$1 = 0           <- Valeur initiale

(gdb) next
-> Execute debut du for

(gdb) print i
$2 = 1

(gdb) next
-> Execute "result *= i;"

(gdb) print result
$3 = 0           <- 0 * 1 = 0, reste 0!

CONCLUSION: result doit etre initialise a 1
```

### 5.8 Mnemotechniques

**"RBCP" - Workflow debug**
- **R**un (demarrer)
- **B**reak (arreter)
- **C**heck (inspecter)
- **P**roceed (continuer)

**"NSF" - Navigation**
- **N**ext (meme niveau)
- **S**tep (descendre)
- **F**inish (remonter)

### 5.9 Applications pratiques

1. **Bug hunting**: Trouver bugs logiques
2. **Core dump**: Analyser crashes
3. **Reverse engineering**: Comprendre binaires
4. **Learning**: Comprendre execution

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de -g | Pas de symboles | Recompiler avec -g |
| Optimisation | Execution bizarre | Utiliser -O0 |
| Mauvais breakpoint | Jamais atteint | Verifier nom/ligne |
| Oublier continue | Programme bloque | c pour continuer |

---

## SECTION 7 : QCM

### Question 1
Quelle commande GDB execute la ligne suivante SANS entrer dans les fonctions ?

A) step
B) next
C) continue
D) finish
E) run

**Reponse correcte: B**

### Question 2
Que fait la commande "backtrace" (bt) ?

A) Revient en arriere dans l'execution
B) Affiche la pile d'appels de fonctions
C) Supprime les breakpoints
D) Charge un fichier
E) Termine le programme

**Reponse correcte: B**

### Question 3
Pourquoi compiler avec -O0 pour debugger ?

A) Pour accelerer l'execution
B) Pour reduire la taille du binaire
C) Pour que l'execution suive exactement le code source
D) C'est obligatoire
E) Pour activer les symboles debug

**Reponse correcte: C**

### Question 4
Quelle commande permet d'afficher la valeur d'une variable ?

A) show
B) display
C) print
D) info
E) watch

**Reponse correcte: C**

### Question 5
Comment poser un breakpoint conditionnel ?

A) break func && x > 10
B) break func if x > 10
C) break func when x > 10
D) breakif func x > 10
E) Ce n'est pas possible

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Commande | Raccourci | Description |
|----------|-----------|-------------|
| break | b | Poser breakpoint |
| run | r | Demarrer |
| continue | c | Continuer |
| next | n | Ligne suivante |
| step | s | Entrer fonction |
| print | p | Afficher variable |
| backtrace | bt | Pile d'appels |
| quit | q | Quitter |

| Flag compilation | Description |
|------------------|-------------|
| -g | Symboles debug |
| -O0 | Pas d'optimisation |
| -ggdb | Symboles GDB specifiques |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.14-a",
    "name": "gdb_basics",
    "module": "0.6.14",
    "phase": 0,
    "difficulty": 4,
    "xp": 250,
    "time_minutes": 150
  },
  "metadata": {
    "concepts": ["breakpoints", "step", "print", "backtrace"],
    "prerequisites": ["0.5", "command-line"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "debug_exercise.c",
    "session_template": "gdb_session.txt",
    "solution": "debug_exercise_fixed.c",
    "test": "test_gdb.sh"
  },
  "tools": {
    "required": ["gdb", "gcc"]
  },
  "grading": {
    "automated": true,
    "correct_output_weight": 75,
    "session_quality_weight": 25
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 5
  }
}
```
