# Exercice 0.5.19-a : string_basics

**Module :**
0.5.19 — Chaines de Caracteres

**Concept :**
a-e — char[], null terminator, strlen, strcpy, strcmp

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.14 (tableaux), 0.5.16 (pointeurs)

**Domaines :**
Algo, Encodage

**Duree estimee :**
180 min

**XP Base :**
220

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `string_basics.c`
- `string_basics.h`

### 1.2 Consigne

Implementer des fonctions de manipulation de chaines de caracteres.

**Ta mission :**

```c
// Calculer la longueur d'une chaine
size_t my_strlen(const char *s);

// Copier une chaine vers une destination
char *my_strcpy(char *dest, const char *src);

// Comparer deux chaines
int my_strcmp(const char *s1, const char *s2);

// Concatener deux chaines
char *my_strcat(char *dest, const char *src);

// Trouver un caractere dans une chaine
char *my_strchr(const char *s, int c);

// Compter les occurrences d'un caractere
int count_char(const char *s, char c);
```

**Comportement:**

1. `my_strlen("Hello")` -> 5
2. `my_strcpy(dest, "World")` -> dest = "World"
3. `my_strcmp("abc", "abd")` -> negatif
4. `my_strcat("Hello", " World")` -> "Hello World"
5. `my_strchr("Hello", 'l')` -> pointeur vers premier 'l'
6. `count_char("hello", 'l')` -> 2

**Exemples:**
```
my_strlen("")       -> 0
my_strlen("a")      -> 1
my_strlen("Hello")  -> 5

my_strcmp("abc", "abc") -> 0
my_strcmp("abc", "abd") -> < 0
my_strcmp("abd", "abc") -> > 0

my_strchr("hello", 'e') -> &"hello"[1]
my_strchr("hello", 'z') -> NULL
```

### 1.3 Prototype

```c
// string_basics.h
#ifndef STRING_BASICS_H
#define STRING_BASICS_H

#include <stddef.h>

size_t my_strlen(const char *s);
char *my_strcpy(char *dest, const char *src);
int my_strcmp(const char *s1, const char *s2);
char *my_strcat(char *dest, const char *src);
char *my_strchr(const char *s, int c);
int count_char(const char *s, char c);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | strlen("Hello") | 5 | 15 |
| T02 | strlen("") | 0 | 10 |
| T03 | strcpy | correct | 15 |
| T04 | strcmp equal | 0 | 15 |
| T05 | strcmp less | < 0 | 10 |
| T06 | strcat | correct | 15 |
| T07 | strchr found | correct ptr | 10 |
| T08 | count_char | correct | 10 |

### 4.3 Solution de reference

```c
#include <stddef.h>
#include "string_basics.h"

size_t my_strlen(const char *s)
{
    size_t len = 0;
    while (s[len] != '\0')
    {
        len++;
    }
    return len;
}

char *my_strcpy(char *dest, const char *src)
{
    char *original_dest = dest;
    while (*src != '\0')
    {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
    return original_dest;
}

int my_strcmp(const char *s1, const char *s2)
{
    while (*s1 != '\0' && *s2 != '\0' && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

char *my_strcat(char *dest, const char *src)
{
    char *original_dest = dest;

    // Aller a la fin de dest
    while (*dest != '\0')
        dest++;

    // Copier src
    while (*src != '\0')
    {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';

    return original_dest;
}

char *my_strchr(const char *s, int c)
{
    while (*s != '\0')
    {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    // Verifier si on cherche '\0'
    if (c == '\0')
        return (char *)s;
    return NULL;
}

int count_char(const char *s, char c)
{
    int count = 0;
    while (*s != '\0')
    {
        if (*s == c)
            count++;
        s++;
    }
    return count;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: strlen compte le '\0'
size_t my_strlen(const char *s)
{
    size_t len = 0;
    while (s[len] != '\0')
        len++;
    return len + 1;  // Compte le '\0' en trop
}

// MUTANT 2: strcpy oublie le terminateur
char *my_strcpy(char *dest, const char *src)
{
    char *original_dest = dest;
    while (*src != '\0')
    {
        *dest++ = *src++;
    }
    // Oublie: *dest = '\0';
    return original_dest;
}

// MUTANT 3: strcmp retourne 1 ou -1 au lieu de difference
int my_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    if (*s1 > *s2) return 1;
    if (*s1 < *s2) return -1;
    return 0;
    // Techniquement acceptable mais moins standard
}

// MUTANT 4: strcat ecrase le debut de dest
char *my_strcat(char *dest, const char *src)
{
    // Oublie d'aller a la fin de dest
    while (*src != '\0')
    {
        *dest++ = *src++;
    }
    *dest = '\0';
    return dest;  // Aussi retourne la mauvaise adresse
}

// MUTANT 5: strchr ne gere pas la recherche de '\0'
char *my_strchr(const char *s, int c)
{
    while (*s != '\0')
    {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    return NULL;  // Oublie le cas c == '\0'
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **chaines de caracteres** en C:

1. **char[]** - Tableau de caracteres
2. **'\0'** - Terminateur null (fin de chaine)
3. **Pas de type string** - C n'a pas de type string natif
4. **Fonctions string.h** - Bibliotheque standard pour manipuler les chaines

### 5.3 Visualisation ASCII

```
char str[] = "Hello";

Memoire:
+-----+-----+-----+-----+-----+-----+
| 'H' | 'e' | 'l' | 'l' | 'o' | '\0'|
+-----+-----+-----+-----+-----+-----+
  72    101   108   108   111    0   (valeurs ASCII)
  ^
  str

strlen("Hello") = 5 (ne compte PAS le '\0')
sizeof("Hello") = 6 (compte le '\0')
```

### 5.5 Difference char[] vs char*

```c
char arr[] = "Hello";  // Tableau modifiable
char *ptr = "Hello";   // Pointeur vers literal (NON modifiable!)

arr[0] = 'J';  // OK: arr est modifiable
ptr[0] = 'J';  // CRASH: literal en memoire read-only
```

---

## SECTION 7 : QCM

### Question 1
Que vaut strlen("") ?

A) 1
B) 0
C) -1
D) NULL
E) Erreur

**Reponse correcte: B**

### Question 2
Quel caractere termine une chaine en C ?

A) '\n'
B) ' '
C) '\0'
D) EOF
E) Aucun

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.19-a",
  "name": "string_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["string_basics.c", "string_basics.h"],
  "tests": {
    "strlen": ["", "a", "Hello", "Hello World"],
    "strcmp": [["abc","abc"], ["abc","abd"], ["", ""]],
    "strchr": "string_search_tests"
  }
}
```
