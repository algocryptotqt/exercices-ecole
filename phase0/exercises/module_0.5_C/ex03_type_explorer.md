# Exercice 0.5.4-a : type_explorer

**Module :**
0.5.4 — Types Fondamentaux C

**Concept :**
a-g — char, short, int, long, float, double, void

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.3 (format_master)

**Domaines :**
Mem, CPU

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `type_explorer.c`

**Fonctions autorisees :**
- `printf()`, `sizeof`

**Headers autorises :**
- `<stdio.h>`, `<limits.h>`, `<float.h>`

### 1.2 Consigne

Creer un programme qui affiche les caracteristiques de chaque type fondamental C.

**Ta mission :**

Implementer les fonctions suivantes qui affichent pour chaque type:
- La taille en octets (sizeof)
- La valeur minimale
- La valeur maximale

**Prototypes :**
```c
void explore_char(void);
void explore_short(void);
void explore_int(void);
void explore_long(void);
void explore_float(void);
void explore_double(void);
void explain_void(void);
```

**Sortie attendue (systeme 64-bit) :**
```
=== char ===
Size: 1 byte
Min: -128
Max: 127

=== short ===
Size: 2 bytes
Min: -32768
Max: 32767

=== int ===
Size: 4 bytes
Min: -2147483648
Max: 2147483647

=== long ===
Size: 8 bytes
Min: -9223372036854775808
Max: 9223372036854775807

=== float ===
Size: 4 bytes
Min: 1.175494e-38
Max: 3.402823e+38

=== double ===
Size: 8 bytes
Min: 2.225074e-308
Max: 1.797693e+308

=== void ===
void represents absence of type
Used for: functions returning nothing, generic pointers (void*)
```

**Contraintes :**
- Utiliser les macros de `<limits.h>` (CHAR_MIN, INT_MAX, etc.)
- Utiliser les macros de `<float.h>` (FLT_MIN, DBL_MAX, etc.)
- Le mot "byte" au singulier pour 1, "bytes" pour >1

### 1.3 Prototype

```c
void explore_char(void);
void explore_short(void);
void explore_int(void);
void explore_long(void);
void explore_float(void);
void explore_double(void);
void explain_void(void);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

La taille des types en C n'est PAS fixe. Elle depend de l'architecture:
- Sur systeme 32-bit: `long` = 4 bytes
- Sur systeme 64-bit: `long` = 8 bytes (Linux) ou 4 bytes (Windows)

C'est pourquoi `<stdint.h>` existe: pour avoir des types a taille garantie.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Firmware Developer**

Connaitre les tailles exactes est crucial pour:
- Communication avec peripheriques (registres 8/16/32 bits)
- Protocoles reseau (tailles fixes dans headers)
- Optimisation memoire sur microcontroleurs

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o type_explorer type_explorer.c
$ ./type_explorer
=== char ===
Size: 1 byte
Min: -128
Max: 127

=== short ===
Size: 2 bytes
Min: -32768
Max: 32767
[...]
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Function | Check | Points |
|---------|----------|-------|--------|
| T01 | explore_char | sizeof == 1 | 10 |
| T02 | explore_char | Min/Max correct | 10 |
| T03 | explore_short | sizeof == 2 | 10 |
| T04 | explore_int | sizeof == 4 | 10 |
| T05 | explore_long | sizeof >= 4 | 10 |
| T06 | explore_float | sizeof == 4 | 10 |
| T07 | explore_double | sizeof == 8 | 10 |
| T08 | explain_void | Contains "void" | 10 |
| T09 | Format correct | All lines match | 10 |
| T10 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <limits.h>
#include <float.h>

void explore_char(void)
{
    printf("=== char ===\n");
    printf("Size: %zu byte\n", sizeof(char));
    printf("Min: %d\n", CHAR_MIN);
    printf("Max: %d\n", CHAR_MAX);
    printf("\n");
}

void explore_short(void)
{
    printf("=== short ===\n");
    printf("Size: %zu bytes\n", sizeof(short));
    printf("Min: %d\n", SHRT_MIN);
    printf("Max: %d\n", SHRT_MAX);
    printf("\n");
}

void explore_int(void)
{
    printf("=== int ===\n");
    printf("Size: %zu bytes\n", sizeof(int));
    printf("Min: %d\n", INT_MIN);
    printf("Max: %d\n", INT_MAX);
    printf("\n");
}

void explore_long(void)
{
    printf("=== long ===\n");
    printf("Size: %zu bytes\n", sizeof(long));
    printf("Min: %ld\n", LONG_MIN);
    printf("Max: %ld\n", LONG_MAX);
    printf("\n");
}

void explore_float(void)
{
    printf("=== float ===\n");
    printf("Size: %zu bytes\n", sizeof(float));
    printf("Min: %e\n", FLT_MIN);
    printf("Max: %e\n", FLT_MAX);
    printf("\n");
}

void explore_double(void)
{
    printf("=== double ===\n");
    printf("Size: %zu bytes\n", sizeof(double));
    printf("Min: %e\n", DBL_MIN);
    printf("Max: %e\n", DBL_MAX);
    printf("\n");
}

void explain_void(void)
{
    printf("=== void ===\n");
    printf("void represents absence of type\n");
    printf("Used for: functions returning nothing, generic pointers (void*)\n");
}

int main(void)
{
    explore_char();
    explore_short();
    explore_int();
    explore_long();
    explore_float();
    explore_double();
    explain_void();
    return 0;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Mauvais format pour sizeof
printf("Size: %d bytes\n", sizeof(int));  // %d au lieu de %zu

// MUTANT 2: Valeur hardcodee au lieu de macro
printf("Max: 127\n");  // Au lieu de CHAR_MAX

// MUTANT 3: Oubli du pluriel "bytes"
printf("Size: 4 byte\n");

// MUTANT 4: Mauvais format pour long
printf("Max: %d\n", LONG_MAX);  // %d au lieu de %ld

// MUTANT 5: Oubli du saut de ligne entre sections
// Pas de printf("\n") entre les fonctions
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **7 types fondamentaux** du C et leurs caracteristiques:
- `char` : 1 byte, caracteres et petits entiers
- `short` : 2 bytes minimum, petits entiers
- `int` : taille naturelle du processeur (souvent 4 bytes)
- `long` : au moins 4 bytes, entiers etendus
- `float` : 4 bytes, flottant simple precision
- `double` : 8 bytes, flottant double precision
- `void` : absence de type

### 5.3 Visualisation ASCII

```
Type        Bytes    Bits     Range (signed)
----        -----    ----     --------------
char          1        8      -128 to 127
short         2       16      -32768 to 32767
int           4       32      -2.1B to 2.1B
long        4/8    32/64      varies by system
float         4       32      ~1e-38 to ~3e38
double        8       64      ~2e-308 to ~2e308
```

### 5.5 Cours Complet

#### Macros de limits.h

| Macro | Type | Description |
|-------|------|-------------|
| CHAR_MIN | char | Minimum char |
| CHAR_MAX | char | Maximum char |
| SHRT_MIN | short | Minimum short |
| SHRT_MAX | short | Maximum short |
| INT_MIN | int | Minimum int (-2147483648) |
| INT_MAX | int | Maximum int (2147483647) |
| LONG_MIN | long | Minimum long |
| LONG_MAX | long | Maximum long |

#### Macros de float.h

| Macro | Type | Description |
|-------|------|-------------|
| FLT_MIN | float | Plus petit float positif |
| FLT_MAX | float | Plus grand float |
| DBL_MIN | double | Plus petit double positif |
| DBL_MAX | double | Plus grand double |

---

## SECTION 7 : QCM

### Question 1
Quelle macro donne la valeur maximale d'un int ?

A) MAX_INT
B) INT_MAX
C) INTEGER_MAX
D) MAXINT
E) int_max

**Reponse correcte: B**

### Question 2
Quel format printf utiliser avec sizeof() ?

A) %d
B) %u
C) %zu
D) %lu
E) %s

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.4-a",
  "name": "type_explorer",
  "language": "c",
  "language_version": "c17",
  "files": ["type_explorer.c"],
  "headers_required": ["limits.h", "float.h"],
  "tests": {"type": "output_comparison"}
}
```
