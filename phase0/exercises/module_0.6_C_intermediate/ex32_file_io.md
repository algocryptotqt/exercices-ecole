# Exercice 0.6.9-a : file_io

**Module :**
0.6.9 — Entrees/Sorties Fichiers

**Concept :**
a-d — fopen, fread, fwrite, fclose

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5 (bases C), pointeurs, strings

**Domaines :**
IO, Fichiers, Systeme

**Duree estimee :**
180 min

**XP Base :**
300

**Complexite :**
T1 O(n) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `file_io.c`
- `file_io.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stddef.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `fopen()`, `fclose()`, `fread()`, `fwrite()`, `fgets()`, `fputs()`
- `fprintf()`, `fscanf()`, `fseek()`, `ftell()`, `rewind()`
- `malloc()`, `free()`, `strlen()`, `memcpy()`

### 1.2 Consigne

Implementer des fonctions utilitaires pour la manipulation de fichiers en C.

**Ta mission :**

Creer un ensemble de fonctions qui encapsulent les operations courantes sur les fichiers avec gestion d'erreurs robuste.

**Prototypes :**
```c
// Lit tout le contenu d'un fichier et retourne une string allouee
// Retourne NULL si erreur, sinon string terminee par '\0'
char *file_read_all(const char *filename);

// Ecrit une string dans un fichier (ecrase si existe)
// Retourne true si succes, false sinon
bool file_write_all(const char *filename, const char *content);

// Ajoute une string a la fin d'un fichier
bool file_append(const char *filename, const char *content);

// Copie un fichier source vers destination
bool file_copy(const char *src, const char *dest);

// Retourne la taille d'un fichier en octets (-1 si erreur)
long file_size(const char *filename);

// Lit un fichier ligne par ligne (retourne tableau de strings)
// lines_count recoit le nombre de lignes
char **file_read_lines(const char *filename, size_t *lines_count);

// Libere le tableau de lignes
void file_free_lines(char **lines, size_t count);

// Ecrit un fichier binaire
bool file_write_binary(const char *filename, const void *data, size_t size);

// Lit un fichier binaire (retourne buffer alloue, size recoit la taille)
void *file_read_binary(const char *filename, size_t *size);
```

**Comportement :**
- Toutes les fonctions retournent NULL/false/-1 en cas d'erreur
- `file_read_all` alloue la memoire necessaire (appelant doit free)
- `file_read_lines` alloue un tableau de strings (appelant doit free avec file_free_lines)
- Les fichiers doivent etre fermes meme en cas d'erreur
- Gerer les fichiers vides correctement

**Exemples :**
```
file_read_all("test.txt")           -> "Hello\nWorld\n"
file_write_all("out.txt", "Test")   -> true (fichier cree)
file_append("out.txt", "!")         -> true (fichier: "Test!")
file_copy("out.txt", "copy.txt")    -> true
file_size("out.txt")                -> 5
file_read_lines("test.txt", &count) -> ["Hello", "World"], count=2
```

**Contraintes :**
- Toujours fermer les fichiers (meme en cas d'erreur)
- Verifier tous les retours de fopen, fread, fwrite
- Utiliser les modes corrects ("r", "w", "a", "rb", "wb")
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// file_io.h
#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>
#include <stdbool.h>

char *file_read_all(const char *filename);
bool file_write_all(const char *filename, const char *content);
bool file_append(const char *filename, const char *content);
bool file_copy(const char *src, const char *dest);
long file_size(const char *filename);
char **file_read_lines(const char *filename, size_t *lines_count);
void file_free_lines(char **lines, size_t count);
bool file_write_binary(const char *filename, const void *data, size_t size);
void *file_read_binary(const char *filename, size_t *size);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Modes d'ouverture

| Mode | Description | Fichier existe | Fichier n'existe pas |
|------|-------------|----------------|---------------------|
| "r" | Lecture | Ouvre | Erreur |
| "w" | Ecriture | Ecrase | Cree |
| "a" | Ajout | Ajoute | Cree |
| "r+" | Lecture/Ecriture | Ouvre | Erreur |
| "w+" | Lecture/Ecriture | Ecrase | Cree |
| "rb" | Lecture binaire | Ouvre | Erreur |
| "wb" | Ecriture binaire | Ecrase | Cree |

### 2.2 Buffering

Par defaut, stdio utilise un buffer:
- **Full buffering**: Fichiers (buffer ~4KB)
- **Line buffering**: Terminal stdout
- **No buffering**: stderr

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Backend Developer**

Les operations fichiers sont essentielles pour:
- Logs applicatifs
- Configuration (JSON, YAML, INI)
- Cache sur disque
- Import/Export de donnees

**Metier : Systems Programmer**

Cas d'utilisation avances:
- Memory-mapped files (mmap)
- Fichiers temporaires
- Locks (flock)
- Fichiers sparse

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_io test_main.c file_io.c
$ echo "Hello World" > test.txt
$ ./test_io
Testing file_read_all...
  Content: "Hello World\n" - OK

Testing file_write_all...
  file_write_all("output.txt", "Test content"): OK
  Verification: "Test content" - OK

Testing file_append...
  file_append("output.txt", " + more"): OK
  Content: "Test content + more" - OK

Testing file_copy...
  file_copy("output.txt", "copy.txt"): OK
  Copy matches original: OK

Testing file_size...
  file_size("output.txt"): 19 bytes - OK

Testing file_read_lines...
  Line 0: "Hello World" - OK
  Total lines: 1 - OK

Testing binary operations...
  file_write_binary: OK
  file_read_binary: OK
  Data integrity: OK

Cleaning up test files...
All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer des fonctions avancees de manipulation de fichiers.

```c
// Lit une ligne specifique (1-indexed)
char *file_read_line(const char *filename, size_t line_num);

// Remplace une ligne specifique
bool file_replace_line(const char *filename, size_t line_num, const char *content);

// Compte le nombre de lignes
size_t file_count_lines(const char *filename);

// Verifie si un fichier existe
bool file_exists(const char *filename);

// Cree un fichier temporaire avec prefixe
char *file_create_temp(const char *prefix);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | file_read_all valide | fichier texte | contenu complet | 15 |
| T02 | file_read_all inexistant | "no_file.txt" | NULL | 5 |
| T03 | file_write_all cree | nouveau fichier | true, fichier cree | 15 |
| T04 | file_append ajoute | fichier existant | contenu ajoute | 10 |
| T05 | file_copy identique | src, dest | copies identiques | 15 |
| T06 | file_size correct | fichier connu | taille exacte | 10 |
| T07 | file_read_lines correct | fichier multi-lignes | tableau correct | 15 |
| T08 | binary read/write | donnees binaires | donnees preservees | 15 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_io.h"

int main(void)
{
    int pass = 0, fail = 0;

    // Setup: create test file
    FILE *f = fopen("test_input.txt", "w");
    fprintf(f, "Line 1\nLine 2\nLine 3\n");
    fclose(f);

    // T01: file_read_all valide
    char *content = file_read_all("test_input.txt");
    if (content != NULL && strstr(content, "Line 1") != NULL) {
        printf("T01 PASS: file_read_all works\n");
        pass++;
        free(content);
    } else {
        printf("T01 FAIL: file_read_all failed\n");
        fail++;
    }

    // T02: file_read_all inexistant
    content = file_read_all("nonexistent_file.txt");
    if (content == NULL) {
        printf("T02 PASS: file_read_all returns NULL for missing file\n");
        pass++;
    } else {
        printf("T02 FAIL: should return NULL\n");
        free(content);
        fail++;
    }

    // T03: file_write_all
    if (file_write_all("test_output.txt", "Hello World")) {
        content = file_read_all("test_output.txt");
        if (content && strcmp(content, "Hello World") == 0) {
            printf("T03 PASS: file_write_all works\n");
            pass++;
        } else {
            printf("T03 FAIL: content mismatch\n");
            fail++;
        }
        free(content);
    } else {
        printf("T03 FAIL: file_write_all returned false\n");
        fail++;
    }

    // T04: file_append
    if (file_append("test_output.txt", "!")) {
        content = file_read_all("test_output.txt");
        if (content && strcmp(content, "Hello World!") == 0) {
            printf("T04 PASS: file_append works\n");
            pass++;
        } else {
            printf("T04 FAIL: append content wrong\n");
            fail++;
        }
        free(content);
    } else {
        printf("T04 FAIL: file_append returned false\n");
        fail++;
    }

    // T05: file_copy
    if (file_copy("test_output.txt", "test_copy.txt")) {
        char *orig = file_read_all("test_output.txt");
        char *copy = file_read_all("test_copy.txt");
        if (orig && copy && strcmp(orig, copy) == 0) {
            printf("T05 PASS: file_copy works\n");
            pass++;
        } else {
            printf("T05 FAIL: copy differs\n");
            fail++;
        }
        free(orig);
        free(copy);
    } else {
        printf("T05 FAIL: file_copy returned false\n");
        fail++;
    }

    // T06: file_size
    long size = file_size("test_output.txt");
    if (size == 12) {  // "Hello World!"
        printf("T06 PASS: file_size works\n");
        pass++;
    } else {
        printf("T06 FAIL: size=%ld, expected 12\n", size);
        fail++;
    }

    // T07: file_read_lines
    size_t count = 0;
    char **lines = file_read_lines("test_input.txt", &count);
    if (lines != NULL && count == 3) {
        printf("T07 PASS: file_read_lines works (%zu lines)\n", count);
        pass++;
        file_free_lines(lines, count);
    } else {
        printf("T07 FAIL: lines=%p, count=%zu\n", (void*)lines, count);
        if (lines) file_free_lines(lines, count);
        fail++;
    }

    // T08: binary operations
    int data[] = {1, 2, 3, 4, 5};
    if (file_write_binary("test.bin", data, sizeof(data))) {
        size_t read_size;
        int *read_data = file_read_binary("test.bin", &read_size);
        if (read_data && read_size == sizeof(data) &&
            memcmp(data, read_data, sizeof(data)) == 0) {
            printf("T08 PASS: binary operations work\n");
            pass++;
        } else {
            printf("T08 FAIL: binary data mismatch\n");
            fail++;
        }
        free(read_data);
    } else {
        printf("T08 FAIL: file_write_binary failed\n");
        fail++;
    }

    // Cleanup
    remove("test_input.txt");
    remove("test_output.txt");
    remove("test_copy.txt");
    remove("test.bin");

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * file_io.c
 * Fonctions utilitaires pour manipulation de fichiers
 * Exercice ex32_file_io
 */

#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *file_read_all(const char *filename)
{
    if (filename == NULL)
    {
        return NULL;
    }

    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        return NULL;
    }

    // Obtenir la taille du fichier
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    if (size < 0)
    {
        fclose(f);
        return NULL;
    }

    // Allouer le buffer (+1 pour '\0')
    char *content = malloc(size + 1);
    if (content == NULL)
    {
        fclose(f);
        return NULL;
    }

    // Lire le contenu
    size_t read = fread(content, 1, size, f);
    content[read] = '\0';

    fclose(f);
    return content;
}

bool file_write_all(const char *filename, const char *content)
{
    if (filename == NULL || content == NULL)
    {
        return false;
    }

    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        return false;
    }

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);

    fclose(f);
    return written == len;
}

bool file_append(const char *filename, const char *content)
{
    if (filename == NULL || content == NULL)
    {
        return false;
    }

    FILE *f = fopen(filename, "a");
    if (f == NULL)
    {
        return false;
    }

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);

    fclose(f);
    return written == len;
}

bool file_copy(const char *src, const char *dest)
{
    if (src == NULL || dest == NULL)
    {
        return false;
    }

    FILE *fsrc = fopen(src, "rb");
    if (fsrc == NULL)
    {
        return false;
    }

    FILE *fdest = fopen(dest, "wb");
    if (fdest == NULL)
    {
        fclose(fsrc);
        return false;
    }

    char buffer[4096];
    size_t bytes;
    bool success = true;

    while ((bytes = fread(buffer, 1, sizeof(buffer), fsrc)) > 0)
    {
        if (fwrite(buffer, 1, bytes, fdest) != bytes)
        {
            success = false;
            break;
        }
    }

    fclose(fsrc);
    fclose(fdest);
    return success;
}

long file_size(const char *filename)
{
    if (filename == NULL)
    {
        return -1;
    }

    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);

    fclose(f);
    return size;
}

char **file_read_lines(const char *filename, size_t *lines_count)
{
    if (filename == NULL || lines_count == NULL)
    {
        return NULL;
    }

    *lines_count = 0;

    // Lire tout le contenu
    char *content = file_read_all(filename);
    if (content == NULL)
    {
        return NULL;
    }

    // Compter les lignes
    size_t count = 0;
    for (char *p = content; *p; p++)
    {
        if (*p == '\n')
        {
            count++;
        }
    }
    // Ajouter 1 si derniere ligne sans \n
    if (strlen(content) > 0 && content[strlen(content) - 1] != '\n')
    {
        count++;
    }

    if (count == 0)
    {
        free(content);
        return NULL;
    }

    // Allouer le tableau de lignes
    char **lines = malloc(count * sizeof(*lines));
    if (lines == NULL)
    {
        free(content);
        return NULL;
    }

    // Parser les lignes
    size_t idx = 0;
    char *line = content;
    char *newline;

    while ((newline = strchr(line, '\n')) != NULL && idx < count)
    {
        *newline = '\0';
        lines[idx] = malloc(strlen(line) + 1);
        if (lines[idx] == NULL)
        {
            // Cleanup en cas d'erreur
            for (size_t i = 0; i < idx; i++)
            {
                free(lines[i]);
            }
            free(lines);
            free(content);
            return NULL;
        }
        strcpy(lines[idx], line);
        idx++;
        line = newline + 1;
    }

    // Derniere ligne sans \n
    if (*line && idx < count)
    {
        lines[idx] = malloc(strlen(line) + 1);
        if (lines[idx] != NULL)
        {
            strcpy(lines[idx], line);
            idx++;
        }
    }

    free(content);
    *lines_count = idx;
    return lines;
}

void file_free_lines(char **lines, size_t count)
{
    if (lines == NULL)
    {
        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        free(lines[i]);
    }
    free(lines);
}

bool file_write_binary(const char *filename, const void *data, size_t size)
{
    if (filename == NULL || data == NULL || size == 0)
    {
        return false;
    }

    FILE *f = fopen(filename, "wb");
    if (f == NULL)
    {
        return false;
    }

    size_t written = fwrite(data, 1, size, f);

    fclose(f);
    return written == size;
}

void *file_read_binary(const char *filename, size_t *size)
{
    if (filename == NULL || size == NULL)
    {
        return NULL;
    }

    *size = 0;

    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        return NULL;
    }

    // Obtenir la taille
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (file_size <= 0)
    {
        fclose(f);
        return NULL;
    }

    // Allouer et lire
    void *data = malloc(file_size);
    if (data == NULL)
    {
        fclose(f);
        return NULL;
    }

    size_t read = fread(data, 1, file_size, f);
    fclose(f);

    if (read != (size_t)file_size)
    {
        free(data);
        return NULL;
    }

    *size = read;
    return data;
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: file_read_all avec getc
char *file_read_all_getc(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    size_t capacity = 256;
    size_t len = 0;
    char *content = malloc(capacity);
    if (!content) { fclose(f); return NULL; }

    int c;
    while ((c = getc(f)) != EOF)
    {
        if (len + 1 >= capacity)
        {
            capacity *= 2;
            char *new = realloc(content, capacity);
            if (!new) { free(content); fclose(f); return NULL; }
            content = new;
        }
        content[len++] = c;
    }
    content[len] = '\0';

    fclose(f);
    return content;
}

// Alternative 2: file_copy avec mmap (bonus)
// Necessite #include <sys/mman.h> et <fcntl.h>
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Ne ferme pas le fichier en cas d'erreur
char *file_read_all(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) return NULL;

    char *content = malloc(1000);
    if (content == NULL)
        return NULL;  // f n'est pas ferme!
    // ...
}
// Raison: File descriptor leak

// REFUSE 2: Buffer overflow potentiel
char *file_read_all(const char *filename)
{
    char buffer[1024];  // Taille fixe!
    FILE *f = fopen(filename, "r");
    fread(buffer, 1, 10000, f);  // Debordement!
}
// Raison: Buffer de taille fixe pour fichier de taille inconnue

// REFUSE 3: Mode incorrect pour binaire
bool file_copy(const char *src, const char *dest)
{
    FILE *fsrc = fopen(src, "r");   // Devrait etre "rb"
    FILE *fdest = fopen(dest, "w"); // Devrait etre "wb"
    // Sur Windows, \r\n sera modifie!
}
// Raison: Corruption de donnees binaires sur certains OS
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.9-a",
  "name": "file_io",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["file_io.c", "file_io.h"],
    "test": ["test_file_io.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_io"
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
// MUTANT 1 (Resource): Fichier non ferme
char *file_read_all(const char *filename)
{
    FILE *f = fopen(filename, "r");
    // ... lecture ...
    // Manque fclose(f)!
    return content;
}
// Detection: Valgrind file descriptor leak, ulimit atteint

// MUTANT 2 (Memory): Pas de +1 pour '\0'
char *file_read_all(const char *filename)
{
    char *content = malloc(size);  // Manque +1!
    fread(content, 1, size, f);
    content[size] = '\0';  // Buffer overflow!
}
// Detection: Valgrind invalid write

// MUTANT 3 (Logic): Mode "w" au lieu de "a" pour append
bool file_append(const char *filename, const char *content)
{
    FILE *f = fopen(filename, "w");  // Ecrase au lieu d'ajouter!
    // ...
}
// Detection: Contenu original perdu

// MUTANT 4 (Logic): Mode texte pour binaire
bool file_copy(const char *src, const char *dest)
{
    FILE *fsrc = fopen(src, "r");  // Pas "rb"
    // Sur Windows: corruption des \r\n
}
// Detection: Fichier copie different de l'original

// MUTANT 5 (Boundary): Off-by-one dans read_lines
char **file_read_lines(const char *filename, size_t *lines_count)
{
    // ...
    char **lines = malloc((count - 1) * sizeof(*lines));  // -1 erreur!
    // ...
}
// Detection: Buffer overflow ou derniere ligne perdue
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des E/S fichiers** en C:

1. **fopen** - Ouvrir un fichier avec le bon mode
2. **fread/fwrite** - Lecture/ecriture binaire
3. **fclose** - Toujours fermer les fichiers
4. **Gestion d'erreurs** - Verifier chaque operation

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION lire_fichier_entier(nom_fichier):
DEBUT
    fichier <- ouvrir(nom_fichier, "lecture")
    SI fichier EST NULL ALORS
        RETOURNER NULL
    FIN SI

    aller_a_fin(fichier)
    taille <- position_actuelle(fichier)
    retour_debut(fichier)

    contenu <- allouer(taille + 1)
    SI contenu EST NULL ALORS
        fermer(fichier)
        RETOURNER NULL
    FIN SI

    octets_lus <- lire(fichier, contenu, taille)
    contenu[octets_lus] <- '\0'

    fermer(fichier)
    RETOURNER contenu
FIN
```

### 5.3 Visualisation ASCII

```
FLUX D'UN FICHIER EN C
======================

Programme          Buffer stdio           Disque
    |                   |                    |
    | fwrite(data)      |                    |
    |------------------>|                    |
    |                   | [buffer 4KB]       |
    |                   |                    |
    |                   | fflush() ou        |
    |                   | buffer plein       |
    |                   |------------------->|
    |                   |    write syscall   |
    |                   |                    |
    | fread(buf, n)     |                    |
    |------------------>|                    |
    |                   | Si buffer vide:    |
    |                   |<-------------------|
    |                   |    read syscall    |
    |<------------------|                    |
    | data              | [buffer rempli]    |

MODES D'OUVERTURE:
==================
"r"  : [EXIST] ---> [READ]     erreur si n'existe pas
"w"  : [CREATE/TRUNCATE] ---> [WRITE]
"a"  : [CREATE/APPEND] ---> [WRITE at end]
"r+" : [EXIST] ---> [READ+WRITE]
"w+" : [CREATE/TRUNCATE] ---> [READ+WRITE]
"a+" : [CREATE/APPEND] ---> [READ+WRITE at end]

+b   : Mode binaire (important sur Windows)

POSITIONNEMENT:
===============
fseek(f, 0, SEEK_SET)  -> |XXXXXXXXXXXXXX|
                          ^debut
fseek(f, 0, SEEK_END)  -> |XXXXXXXXXXXXXX|
                                         ^fin
fseek(f, 5, SEEK_CUR)  -> |XXXXX|XXXXXXXXX|
                               ^+5 depuis position actuelle
```

### 5.4 Les pieges en detail

#### Piege 1: Ne pas fermer le fichier
```c
// FAUX - File descriptor leak
char *file_read_all(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) return NULL;

    char *content = malloc(size);
    if (content == NULL)
        return NULL;  // f reste ouvert!
    // ...
}

// CORRECT
char *file_read_all(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) return NULL;

    char *content = malloc(size);
    if (content == NULL)
    {
        fclose(f);  // Toujours fermer!
        return NULL;
    }
    // ...
}
```

#### Piege 2: Mode texte vs binaire
```c
// PROBLEMATIQUE sur Windows
FILE *f = fopen("image.png", "r");  // Mode texte!
// \r\n sera converti en \n -> corruption

// CORRECT pour fichiers binaires
FILE *f = fopen("image.png", "rb");  // Mode binaire
```

### 5.5 Cours Complet

#### 5.5.1 fopen - Ouvrir un fichier

```c
FILE *fopen(const char *filename, const char *mode);
```

Retourne NULL si erreur. Toujours verifier!

#### 5.5.2 fread/fwrite - E/S binaires

```c
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
```

- `size`: taille d'un element
- `nmemb`: nombre d'elements
- Retourne le nombre d'elements lus/ecrits

#### 5.5.3 fseek/ftell/rewind - Positionnement

```c
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
void rewind(FILE *stream);  // Equivalent a fseek(f, 0, SEEK_SET)
```

`whence`: SEEK_SET (debut), SEEK_CUR (courant), SEEK_END (fin)

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Toujours fclose | Evite file descriptor leak | `fclose(f);` en sortie |
| Verifier fopen | Peut echouer (permissions, etc.) | `if (f == NULL)` |
| Mode binaire pour binaire | Evite corruption sur Windows | `"rb"`, `"wb"` |
| Buffer +1 pour '\0' | Espace pour terminateur | `malloc(size + 1)` |

### 5.7 Simulation avec trace d'execution

```
Programme: file_read_all("test.txt")
Fichier test.txt contient: "Hello\n" (6 octets)

1. fopen("test.txt", "r") -> FILE* a 0x7f00001000
2. fseek(f, 0, SEEK_END) -> positionne a la fin
3. ftell(f) -> retourne 6 (taille)
4. rewind(f) -> retourne au debut
5. malloc(6 + 1) -> alloue 7 octets a 0x5500002000
6. fread(content, 1, 6, f) -> lit 6 octets: "Hello\n"
7. content[6] = '\0' -> termine la string
8. fclose(f) -> libere le FILE*
9. return content -> "Hello\n"
```

### 5.8 Mnemotechniques

**"OVLF" - Sequence des operations**
- **O**uvrir (fopen)
- **V**erifier (NULL check)
- **L**ire/ecrire (fread/fwrite)
- **F**ermer (fclose)

**"TBR" - Modes de base**
- **T**exte: r, w, a
- **B**inaire: rb, wb, ab
- **R**ead+write: r+, w+, a+

### 5.9 Applications pratiques

1. **Configuration**: Lecture de fichiers .ini, .json, .yaml
2. **Logs**: Ecriture de journaux d'evenements
3. **Serialisation**: Sauvegarde/chargement d'etat
4. **Import/Export**: Traitement de donnees CSV, etc.

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Fichier non ferme | FD leak, limite atteinte | `fclose()` toujours |
| Mode texte pour binaire | Corruption donnees | Utiliser "rb"/"wb" |
| Pas de NULL check | Segfault | Verifier fopen retour |
| Buffer trop petit | Overflow | Calculer taille exacte |
| Oubli '\0' | String non terminee | `content[len] = '\0'` |

---

## SECTION 7 : QCM

### Question 1
Quel mode fopen utiliser pour ajouter du contenu a un fichier existant ?

A) "r"
B) "w"
C) "a"
D) "r+"
E) "w+"

**Reponse correcte: C**

### Question 2
Que retourne fopen si le fichier n'existe pas avec le mode "r" ?

A) Un FILE* vide
B) NULL
C) Un FILE* vers un fichier vide
D) -1
E) Une exception

**Reponse correcte: B**

### Question 3
Pourquoi utiliser "rb" plutot que "r" pour lire un fichier binaire ?

A) C'est plus rapide
B) Ca utilise moins de memoire
C) Pour eviter la conversion \r\n sur Windows
D) C'est obligatoire en C17
E) Il n'y a pas de difference

**Reponse correcte: C**

### Question 4
Que fait fseek(f, 0, SEEK_END) ?

A) Ferme le fichier
B) Positionne au debut du fichier
C) Positionne a la fin du fichier
D) Efface le contenu
E) Retourne la taille du fichier

**Reponse correcte: C**

### Question 5
Que se passe-t-il si on oublie de fermer un fichier ?

A) Le fichier est corrompu
B) Fuite de file descriptor
C) Le programme crash
D) Les donnees ne sont pas ecrites
E) Rien de grave

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Fonction | Description | Retour erreur |
|----------|-------------|---------------|
| fopen | Ouvre fichier | NULL |
| fclose | Ferme fichier | EOF |
| fread | Lecture binaire | < nmemb |
| fwrite | Ecriture binaire | < nmemb |
| fseek | Positionnement | non-zero |
| ftell | Position actuelle | -1L |

| Mode | Lecture | Ecriture | Cree | Tronque |
|------|---------|----------|------|---------|
| r | oui | non | non | non |
| w | non | oui | oui | oui |
| a | non | oui | oui | non |
| r+ | oui | oui | non | non |
| w+ | oui | oui | oui | oui |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.9-a",
    "name": "file_io",
    "module": "0.6.9",
    "phase": 0,
    "difficulty": 4,
    "xp": 300,
    "time_minutes": 180
  },
  "metadata": {
    "concepts": ["fopen", "fread", "fwrite", "fclose"],
    "prerequisites": ["0.5", "pointers", "strings"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "file_io.c",
    "header": "file_io.h",
    "solution": "file_io_solution.c",
    "test": "test_file_io.c"
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
    "difficulty": 5
  }
}
```
