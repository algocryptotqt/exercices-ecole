# Exercice 0.5.3-a : format_master

**Module :**
0.5.3 — Formats printf

**Concept :**
a-j — %d, %u, %ld, %f, %c, %s, %p, %x, %%, \n

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.1 (first_program), 0.5.2 (compilation_flags)

**Domaines :**
Encodage

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `format_master.c`
- `format_master.h`

**Fonctions autorisees :**
- `printf()`

**Fonctions interdites :**
- Aucune autre fonction

### 1.2 Consigne

Implementer une fonction qui affiche tous les formats printf standards.

**Ta mission :**

Creer la fonction `display_all_formats` qui recoit differents types de valeurs et les affiche avec leur format correspondant.

**Entree :**
- `i` : entier signe (int)
- `u` : entier non signe (unsigned int)
- `l` : entier long (long)
- `d` : nombre flottant (double)
- `c` : caractere (char)
- `s` : chaine de caracteres (char *)
- `p` : pointeur (void *)

**Sortie :**
Affichage sur stdout avec le format exact suivant:
```
int: 42
unsigned: 4294967254
long: 9223372036854775807
double: 3.141593
char: A
string: Hello
pointer: 0x7fff5e8c3a40
hex: 2a
literal percent: %
```

**Contraintes :**
- Utiliser le bon format pour chaque type
- Afficher le pointeur en hexadecimal avec prefixe 0x
- Afficher l'entier en hexadecimal (minuscules)
- Afficher un signe % litteral
- Chaque ligne se termine par \n

### 1.3 Prototype

```c
// format_master.h
#ifndef FORMAT_MASTER_H
#define FORMAT_MASTER_H

void display_all_formats(int i, unsigned int u, long l, double d,
                         char c, char *s, void *p);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

La fonction `printf` date de 1972 et fut creee pour UNIX par Dennis Ritchie. Le "f" signifie "formatted" (formate).

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Embedded Developer**

Les developpeurs embarques utilisent printf pour:
- Debug sur port serie (UART)
- Logs systeme
- Affichage sur ecrans LCD

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -c format_master.c
$ gcc -Wall -Werror -std=c17 -o test_format test_main.c format_master.o
$ ./test_format
int: 42
unsigned: 4294967254
long: 9223372036854775807
double: 3.141593
char: A
string: Hello
pointer: 0x7fff5e8c3a40
hex: 2a
literal percent: %
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected Output | Points |
|---------|-------|-----------------|--------|
| T01 | i=42 | "int: 42" | 10 |
| T02 | u=4294967254 | "unsigned: 4294967254" | 10 |
| T03 | l=LONG_MAX | "long: 9223372036854775807" | 10 |
| T04 | d=3.141592653 | "double: 3.141593" | 10 |
| T05 | c='A' | "char: A" | 10 |
| T06 | s="Hello" | "string: Hello" | 10 |
| T07 | p=&var | "pointer: 0x..." | 10 |
| T08 | i=42 (hex) | "hex: 2a" | 10 |
| T09 | literal % | "literal percent: %" | 10 |
| T10 | Compilation clean | No warnings | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include "format_master.h"

void display_all_formats(int i, unsigned int u, long l, double d,
                         char c, char *s, void *p)
{
    printf("int: %d\n", i);
    printf("unsigned: %u\n", u);
    printf("long: %ld\n", l);
    printf("double: %f\n", d);
    printf("char: %c\n", c);
    printf("string: %s\n", s);
    printf("pointer: %p\n", p);
    printf("hex: %x\n", i);
    printf("literal percent: %%\n");
}
```

### 4.5 Solutions refusees

```c
// REFUSE: Mauvais format pour long
printf("long: %d\n", l);  // %d au lieu de %ld

// REFUSE: Oubli du newline
printf("int: %d", i);  // Pas de \n

// REFUSE: Mauvaise precision flottant
printf("double: %.2f\n", d);  // Precision imposee
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: %d pour unsigned (overflow possible)
printf("unsigned: %d\n", u);

// MUTANT 2: %X majuscule au lieu de %x
printf("hex: %X\n", i);

// MUTANT 3: Oubli du %% -> crash ou comportement indefini
printf("literal percent: %\n");

// MUTANT 4: %lld pour long (incorrect sur certains systemes)
printf("long: %lld\n", l);

// MUTANT 5: Pas d'espace apres les deux-points
printf("int:%d\n", i);
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **10 formats essentiels** de printf:
- `%d` - entier signe decimal
- `%u` - entier non signe decimal
- `%ld` - long decimal
- `%f` - flottant (6 decimales par defaut)
- `%c` - caractere
- `%s` - chaine de caracteres
- `%p` - pointeur (adresse)
- `%x` - hexadecimal minuscules
- `%%` - caractere % litteral
- `\n` - saut de ligne

### 5.3 Visualisation ASCII

```
Format     Type           Exemple
------     ----           -------
%d         int            42
%u         unsigned       4294967295
%ld        long           9223372036854775807
%f         double         3.141593
%c         char           A
%s         char*          Hello
%p         void*          0x7fff...
%x         int (hex)      2a
%%         literal        %
```

### 5.5 Cours Complet

#### Tableau des formats

| Format | Type attendu | Description |
|--------|--------------|-------------|
| %d, %i | int | Entier signe decimal |
| %u | unsigned int | Entier non signe decimal |
| %ld | long | Long signe |
| %lu | unsigned long | Long non signe |
| %lld | long long | Long long signe |
| %f | double | Flottant (defaut 6 decimales) |
| %e | double | Notation scientifique |
| %g | double | Plus court entre %f et %e |
| %c | char | Caractere unique |
| %s | char* | Chaine terminee par \0 |
| %p | void* | Adresse en hexadecimal |
| %x | unsigned int | Hexadecimal minuscules |
| %X | unsigned int | Hexadecimal majuscules |
| %o | unsigned int | Octal |
| %% | (rien) | Caractere % litteral |

---

## SECTION 7 : QCM

### Question 1
Quel format utiliser pour un `long` ?

A) %d
B) %ld
C) %l
D) %long
E) %L

**Reponse correcte: B**

### Question 2
Comment afficher un caractere % litteral ?

A) \%
B) %%
C) %c avec '%'
D) %s avec "%"
E) Impossible

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.3-a",
  "name": "format_master",
  "language": "c",
  "language_version": "c17",
  "files": ["format_master.c", "format_master.h"],
  "compilation": {"flags": ["-Wall", "-Werror", "-std=c17"]},
  "tests": {
    "type": "output_comparison",
    "cases": 10
  }
}
```
