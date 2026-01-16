# Exercice 0.6.10-a : error_handling

**Module :**
0.6.10 — Gestion des Erreurs

**Concept :**
a-c — errno, perror, return codes

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5 (bases C), 0.6.9 (file_io)

**Domaines :**
Systeme, Debug, Robustesse

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
- `error_handling.c`
- `error_handling.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<errno.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `perror()`, `strerror()`, `fprintf()`, `printf()`
- `malloc()`, `free()`, `fopen()`, `fclose()`

### 1.2 Consigne

Implementer un systeme de gestion d'erreurs robuste en C avec codes de retour et messages explicites.

**Ta mission :**

Creer un framework leger pour la gestion d'erreurs incluant des codes d'erreur personnalises, des messages explicatifs et des utilitaires de diagnostic.

**Prototypes :**
```c
// Codes d'erreur personnalises
typedef enum {
    ERR_OK = 0,           // Pas d'erreur
    ERR_NULL_PTR,         // Pointeur NULL inattendu
    ERR_INVALID_ARG,      // Argument invalide
    ERR_OUT_OF_MEMORY,    // Echec allocation memoire
    ERR_FILE_NOT_FOUND,   // Fichier non trouve
    ERR_FILE_READ,        // Erreur lecture fichier
    ERR_FILE_WRITE,       // Erreur ecriture fichier
    ERR_BUFFER_OVERFLOW,  // Depassement de buffer
    ERR_UNKNOWN           // Erreur inconnue
} error_code_t;

// Retourne le message associe a un code d'erreur
const char *error_get_message(error_code_t code);

// Affiche une erreur sur stderr avec contexte
void error_print(error_code_t code, const char *context);

// Affiche l'erreur errno avec contexte (wrapper perror)
void error_print_errno(const char *context);

// Definit l'erreur courante (thread-local idealement)
void error_set(error_code_t code);

// Retourne la derniere erreur definie
error_code_t error_get(void);

// Efface la derniere erreur
void error_clear(void);

// Verifie si une erreur est survenue
bool error_occurred(void);

// Fonction safe_malloc avec gestion d'erreur integree
void *safe_malloc(size_t size);

// Fonction safe_fopen avec gestion d'erreur integree
FILE *safe_fopen(const char *filename, const char *mode);

// Fonction pour logger une erreur dans un fichier
bool error_log(const char *logfile, error_code_t code, const char *message);
```

**Comportement :**
- `error_get_message` retourne une string statique (pas de malloc)
- `error_print` affiche: "[ERROR] context: message"
- `error_print_errno` utilise errno et strerror/perror
- `safe_malloc` definit ERR_OUT_OF_MEMORY si echec
- `safe_fopen` definit ERR_FILE_NOT_FOUND si echec
- `error_log` ajoute timestamp et erreur au fichier

**Exemples :**
```
error_get_message(ERR_NULL_PTR)    -> "Null pointer"
error_set(ERR_INVALID_ARG);
error_get()                        -> ERR_INVALID_ARG
error_occurred()                   -> true
error_clear();
error_occurred()                   -> false
safe_malloc(0)                     -> NULL, errno set
error_print(ERR_FILE_NOT_FOUND, "config.txt")
  -> "[ERROR] config.txt: File not found"
```

**Contraintes :**
- Ne pas utiliser de variables globales (utiliser static)
- Messages d'erreur en anglais
- Timestamps au format ISO 8601 pour le log
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// error_handling.h
#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    ERR_OK = 0,
    ERR_NULL_PTR,
    ERR_INVALID_ARG,
    ERR_OUT_OF_MEMORY,
    ERR_FILE_NOT_FOUND,
    ERR_FILE_READ,
    ERR_FILE_WRITE,
    ERR_BUFFER_OVERFLOW,
    ERR_UNKNOWN
} error_code_t;

const char *error_get_message(error_code_t code);
void error_print(error_code_t code, const char *context);
void error_print_errno(const char *context);
void error_set(error_code_t code);
error_code_t error_get(void);
void error_clear(void);
bool error_occurred(void);
void *safe_malloc(size_t size);
FILE *safe_fopen(const char *filename, const char *mode);
bool error_log(const char *logfile, error_code_t code, const char *message);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 La variable errno

`errno` est une variable globale (macro en realite) definie dans `<errno.h>`:
- Mise a jour par les appels systeme et certaines fonctions de la libc
- Doit etre verifiee **immediatement** apres l'appel
- Valeur 0 = pas d'erreur
- Valeurs communes: ENOENT (2), ENOMEM (12), EACCES (13)

### 2.2 perror vs strerror

```c
perror("fopen");         // Affiche sur stderr: "fopen: No such file or directory"
char *msg = strerror(errno);  // Retourne: "No such file or directory"
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Systems Programmer**

La gestion d'erreurs est critique pour:
- Serveurs haute disponibilite (uptime 99.99%)
- Systemes embarques (pas de crash tolere)
- Drivers et code noyau

**Metier : DevOps / SRE**

Les logs d'erreurs sont essentiels pour:
- Monitoring et alerting
- Post-mortem analysis
- Capacity planning

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_err test_main.c error_handling.c
$ ./test_err
Testing error codes...
  error_get_message(ERR_OK): "Success" - OK
  error_get_message(ERR_NULL_PTR): "Null pointer" - OK
  error_get_message(ERR_OUT_OF_MEMORY): "Out of memory" - OK

Testing error state...
  error_set(ERR_INVALID_ARG)
  error_get(): ERR_INVALID_ARG - OK
  error_occurred(): true - OK
  error_clear()
  error_occurred(): false - OK

Testing error_print...
  [ERROR] test_function: Invalid argument
  OK

Testing error_print_errno...
  Simulating file open error...
  [ERROR] nonexistent.txt: No such file or directory
  OK

Testing safe_malloc...
  safe_malloc(100): 0x55a4c8f012a0 - OK
  safe_malloc(0): NULL - OK
  error_get(): ERR_INVALID_ARG - OK

Testing safe_fopen...
  safe_fopen("nonexistent.txt", "r"): NULL - OK
  error_get(): ERR_FILE_NOT_FOUND - OK

Testing error_log...
  error_log("errors.log", ERR_NULL_PTR, "test message"): true
  Log file content:
  2024-01-15T10:30:45 [ERR_NULL_PTR] test message
  OK

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

Implementer un systeme de gestion d'erreurs avec stack trace et contexte etendu.

```c
// Structure d'erreur etendue
typedef struct {
    error_code_t code;
    char message[256];
    const char *file;
    int line;
    const char *function;
} error_context_t;

// Macro pour capturer le contexte
#define ERROR_SET(code, msg) \
    error_set_context(code, msg, __FILE__, __LINE__, __func__)

// Definit une erreur avec contexte complet
void error_set_context(error_code_t code, const char *msg,
                       const char *file, int line, const char *func);

// Retourne le contexte complet
const error_context_t *error_get_context(void);

// Affiche le contexte complet
void error_print_context(void);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | error_get_message valid | ERR_NULL_PTR | "Null pointer" | 10 |
| T02 | error_get_message unknown | 999 | "Unknown error" | 5 |
| T03 | error_set/get cycle | ERR_INVALID_ARG | correct code | 15 |
| T04 | error_clear | apres set | ERR_OK | 10 |
| T05 | error_occurred | apres set | true | 10 |
| T06 | safe_malloc valid | 100 | non-NULL | 15 |
| T07 | safe_malloc zero | 0 | NULL + error | 10 |
| T08 | safe_fopen missing | "no_file" | NULL + error | 15 |
| T09 | error_log write | valid args | true + file | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "error_handling.h"

int main(void)
{
    int pass = 0, fail = 0;

    // T01: error_get_message valid
    const char *msg = error_get_message(ERR_NULL_PTR);
    if (msg != NULL && strstr(msg, "Null") != NULL) {
        printf("T01 PASS: error_get_message(ERR_NULL_PTR)\n");
        pass++;
    } else {
        printf("T01 FAIL: got '%s'\n", msg);
        fail++;
    }

    // T02: error_get_message unknown
    msg = error_get_message(999);
    if (msg != NULL && strstr(msg, "Unknown") != NULL) {
        printf("T02 PASS: error_get_message(999) returns unknown\n");
        pass++;
    } else {
        printf("T02 FAIL: got '%s'\n", msg);
        fail++;
    }

    // T03: error_set/get cycle
    error_clear();
    error_set(ERR_INVALID_ARG);
    if (error_get() == ERR_INVALID_ARG) {
        printf("T03 PASS: error_set/get works\n");
        pass++;
    } else {
        printf("T03 FAIL: error_get() returned %d\n", error_get());
        fail++;
    }

    // T04: error_clear
    error_clear();
    if (error_get() == ERR_OK) {
        printf("T04 PASS: error_clear works\n");
        pass++;
    } else {
        printf("T04 FAIL: error_get() after clear = %d\n", error_get());
        fail++;
    }

    // T05: error_occurred
    error_set(ERR_BUFFER_OVERFLOW);
    if (error_occurred()) {
        printf("T05 PASS: error_occurred returns true\n");
        pass++;
    } else {
        printf("T05 FAIL: error_occurred should be true\n");
        fail++;
    }
    error_clear();

    // T06: safe_malloc valid
    void *ptr = safe_malloc(100);
    if (ptr != NULL) {
        printf("T06 PASS: safe_malloc(100) works\n");
        pass++;
        free(ptr);
    } else {
        printf("T06 FAIL: safe_malloc(100) returned NULL\n");
        fail++;
    }

    // T07: safe_malloc zero
    error_clear();
    ptr = safe_malloc(0);
    if (ptr == NULL && error_occurred()) {
        printf("T07 PASS: safe_malloc(0) returns NULL with error\n");
        pass++;
    } else {
        printf("T07 FAIL: safe_malloc(0) should fail\n");
        if (ptr) free(ptr);
        fail++;
    }

    // T08: safe_fopen missing
    error_clear();
    FILE *f = safe_fopen("nonexistent_file_12345.txt", "r");
    if (f == NULL && error_get() == ERR_FILE_NOT_FOUND) {
        printf("T08 PASS: safe_fopen missing file works\n");
        pass++;
    } else {
        printf("T08 FAIL: error = %d\n", error_get());
        if (f) fclose(f);
        fail++;
    }

    // T09: error_log write
    remove("test_error.log");
    if (error_log("test_error.log", ERR_NULL_PTR, "test message")) {
        FILE *log = fopen("test_error.log", "r");
        if (log) {
            char buf[256];
            if (fgets(buf, sizeof(buf), log) && strstr(buf, "ERR_NULL_PTR")) {
                printf("T09 PASS: error_log works\n");
                pass++;
            } else {
                printf("T09 FAIL: log content wrong\n");
                fail++;
            }
            fclose(log);
        } else {
            printf("T09 FAIL: log file not created\n");
            fail++;
        }
    } else {
        printf("T09 FAIL: error_log returned false\n");
        fail++;
    }
    remove("test_error.log");

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * error_handling.c
 * Systeme de gestion d'erreurs en C
 * Exercice ex33_error_handling
 */

#include "error_handling.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// Variable statique pour l'erreur courante
static error_code_t g_last_error = ERR_OK;

// Messages d'erreur
static const char *error_messages[] = {
    [ERR_OK] = "Success",
    [ERR_NULL_PTR] = "Null pointer",
    [ERR_INVALID_ARG] = "Invalid argument",
    [ERR_OUT_OF_MEMORY] = "Out of memory",
    [ERR_FILE_NOT_FOUND] = "File not found",
    [ERR_FILE_READ] = "File read error",
    [ERR_FILE_WRITE] = "File write error",
    [ERR_BUFFER_OVERFLOW] = "Buffer overflow",
    [ERR_UNKNOWN] = "Unknown error"
};

const char *error_get_message(error_code_t code)
{
    if (code >= 0 && code <= ERR_UNKNOWN)
    {
        return error_messages[code];
    }
    return error_messages[ERR_UNKNOWN];
}

void error_print(error_code_t code, const char *context)
{
    const char *msg = error_get_message(code);
    if (context != NULL)
    {
        fprintf(stderr, "[ERROR] %s: %s\n", context, msg);
    }
    else
    {
        fprintf(stderr, "[ERROR] %s\n", msg);
    }
}

void error_print_errno(const char *context)
{
    if (context != NULL)
    {
        fprintf(stderr, "[ERROR] %s: %s\n", context, strerror(errno));
    }
    else
    {
        fprintf(stderr, "[ERROR] %s\n", strerror(errno));
    }
}

void error_set(error_code_t code)
{
    g_last_error = code;
}

error_code_t error_get(void)
{
    return g_last_error;
}

void error_clear(void)
{
    g_last_error = ERR_OK;
}

bool error_occurred(void)
{
    return g_last_error != ERR_OK;
}

void *safe_malloc(size_t size)
{
    if (size == 0)
    {
        error_set(ERR_INVALID_ARG);
        return NULL;
    }

    void *ptr = malloc(size);
    if (ptr == NULL)
    {
        error_set(ERR_OUT_OF_MEMORY);
    }

    return ptr;
}

FILE *safe_fopen(const char *filename, const char *mode)
{
    if (filename == NULL || mode == NULL)
    {
        error_set(ERR_NULL_PTR);
        return NULL;
    }

    FILE *f = fopen(filename, mode);
    if (f == NULL)
    {
        if (errno == ENOENT)
        {
            error_set(ERR_FILE_NOT_FOUND);
        }
        else if (errno == EACCES)
        {
            error_set(ERR_FILE_READ);
        }
        else
        {
            error_set(ERR_UNKNOWN);
        }
    }

    return f;
}

// Helper pour obtenir le nom du code d'erreur
static const char *error_code_name(error_code_t code)
{
    static const char *names[] = {
        [ERR_OK] = "ERR_OK",
        [ERR_NULL_PTR] = "ERR_NULL_PTR",
        [ERR_INVALID_ARG] = "ERR_INVALID_ARG",
        [ERR_OUT_OF_MEMORY] = "ERR_OUT_OF_MEMORY",
        [ERR_FILE_NOT_FOUND] = "ERR_FILE_NOT_FOUND",
        [ERR_FILE_READ] = "ERR_FILE_READ",
        [ERR_FILE_WRITE] = "ERR_FILE_WRITE",
        [ERR_BUFFER_OVERFLOW] = "ERR_BUFFER_OVERFLOW",
        [ERR_UNKNOWN] = "ERR_UNKNOWN"
    };

    if (code >= 0 && code <= ERR_UNKNOWN)
    {
        return names[code];
    }
    return "ERR_UNKNOWN";
}

bool error_log(const char *logfile, error_code_t code, const char *message)
{
    if (logfile == NULL)
    {
        error_set(ERR_NULL_PTR);
        return false;
    }

    FILE *f = fopen(logfile, "a");
    if (f == NULL)
    {
        error_set(ERR_FILE_WRITE);
        return false;
    }

    // Obtenir le timestamp ISO 8601
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);

    // Ecrire l'entree de log
    int written = fprintf(f, "%s [%s] %s\n",
                         timestamp,
                         error_code_name(code),
                         message ? message : "");

    fclose(f);

    if (written < 0)
    {
        error_set(ERR_FILE_WRITE);
        return false;
    }

    return true;
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: Utiliser perror directement
void error_print_errno(const char *context)
{
    perror(context);  // Plus simple mais format different
}

// Alternative 2: Thread-local storage pour g_last_error
#include <threads.h>
static _Thread_local error_code_t g_last_error = ERR_OK;
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Variable globale non-static
error_code_t g_last_error = ERR_OK;  // Visible hors du fichier!
// Raison: Pollution de namespace, pas d'encapsulation

// REFUSE 2: Message alloue dynamiquement
const char *error_get_message(error_code_t code)
{
    char *msg = malloc(100);
    sprintf(msg, "Error %d", code);
    return msg;  // Qui va free?
}
// Raison: Memory leak

// REFUSE 3: Pas de validation des arguments
FILE *safe_fopen(const char *filename, const char *mode)
{
    return fopen(filename, mode);  // Crash si NULL!
}
// Raison: Pas "safe" du tout
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.10-a",
  "name": "error_handling",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["error_handling.c", "error_handling.h"],
    "test": ["test_error_handling.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_err"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "leak_check": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 75,
    "memory_safety": 15
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Logic): Mauvais index dans messages
const char *error_get_message(error_code_t code)
{
    return error_messages[code + 1];  // Off by one!
}
// Detection: Mauvais message retourne

// MUTANT 2 (State): error_clear ne reset pas
void error_clear(void)
{
    // g_last_error = ERR_OK;  // Oublie!
}
// Detection: error_get() != ERR_OK apres clear

// MUTANT 3 (Logic): error_occurred inverse
bool error_occurred(void)
{
    return g_last_error == ERR_OK;  // Inverse!
}
// Detection: Retourne true quand pas d'erreur

// MUTANT 4 (Resource): Log file non ferme
bool error_log(const char *logfile, error_code_t code, const char *message)
{
    FILE *f = fopen(logfile, "a");
    fprintf(f, "...");
    // Manque fclose(f)!
    return true;
}
// Detection: File descriptor leak

// MUTANT 5 (Safety): safe_malloc accepte 0
void *safe_malloc(size_t size)
{
    // Manque check size == 0
    void *ptr = malloc(size);
    return ptr;
}
// Detection: malloc(0) comportement indefini
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux de la gestion d'erreurs** en C:

1. **errno** - Variable globale d'erreur systeme
2. **perror** - Affichage d'erreur formatee
3. **return codes** - Codes de retour personnalises

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION ouverture_securisee(nom_fichier, mode):
DEBUT
    SI nom_fichier EST NULL OU mode EST NULL ALORS
        definir_erreur(ERR_NULL_PTR)
        RETOURNER NULL
    FIN SI

    fichier <- ouvrir_fichier(nom_fichier, mode)

    SI fichier EST NULL ALORS
        SI errno EGALE ENOENT ALORS
            definir_erreur(ERR_FILE_NOT_FOUND)
        SINON SI errno EGALE EACCES ALORS
            definir_erreur(ERR_FILE_READ)
        SINON
            definir_erreur(ERR_UNKNOWN)
        FIN SI
    FIN SI

    RETOURNER fichier
FIN
```

### 5.3 Visualisation ASCII

```
FLUX DE GESTION D'ERREURS
=========================

     Appel fonction
          |
          v
    +------------+
    | Execution  |
    +------------+
          |
    +-----+-----+
    |           |
    v           v
 Succes      Echec
    |           |
    v           v
 return 0   errno = code
    |       error_set(code)
    |       return -1/NULL
    |           |
    +-----+-----+
          |
          v
    Appelant verifie
    retour + errno
          |
    +-----+-----+
    |           |
    v           v
 Continue   Gere erreur
             - error_print()
             - error_log()
             - propagate

CODES ERRNO COMMUNS:
====================
+-------+--------+---------------------------+
| Code  | Nom    | Description               |
+-------+--------+---------------------------+
|   2   | ENOENT | No such file or directory |
|  12   | ENOMEM | Out of memory             |
|  13   | EACCES | Permission denied         |
|  17   | EEXIST | File exists               |
|  22   | EINVAL | Invalid argument          |
+-------+--------+---------------------------+

PATTERN D'UTILISATION:
======================
errno = 0;              // Reset avant l'appel
FILE *f = fopen(...);
if (f == NULL) {
    if (errno == ENOENT)
        // Fichier n'existe pas
    else if (errno == EACCES)
        // Permission refusee
    perror("fopen");    // Affiche message
}
```

### 5.4 Les pieges en detail

#### Piege 1: Ne pas verifier errno immediatement
```c
// FAUX - errno peut etre modifie entre temps
FILE *f = fopen("test.txt", "r");
printf("Tentative d'ouverture...\n");  // Peut modifier errno!
if (f == NULL)
    perror("fopen");  // Mauvais errno!

// CORRECT
FILE *f = fopen("test.txt", "r");
if (f == NULL)
{
    perror("fopen");  // Immediatement apres
}
```

#### Piege 2: Oublier de reset errno
```c
// FAUX - errno garde l'ancienne valeur
errno = 0;  // IMPORTANT: reset
long val = strtol(str, &end, 10);
if (errno != 0)  // Maintenant fiable
    // Erreur de conversion
```

### 5.5 Cours Complet

#### 5.5.1 La variable errno

```c
#include <errno.h>

// errno est defini comme:
// extern int errno;  // Simplification
// En realite: #define errno (*__errno_location())  // Thread-safe
```

#### 5.5.2 perror et strerror

```c
void perror(const char *s);
// Affiche: "s: message_erreur\n" sur stderr

char *strerror(int errnum);
// Retourne la string du message (ne pas free!)
```

#### 5.5.3 Pattern de gestion d'erreur

```c
// Pattern standard
int function_that_can_fail(params)
{
    if (invalid_params)
    {
        errno = EINVAL;
        return -1;
    }

    result = do_operation();
    if (result == error)
    {
        // errno deja defini par l'operation
        return -1;
    }

    return 0;  // Succes
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Verifier immediatement | errno volatile | `if (ret == -1) perror()` |
| Reset avant appel | Ancienne valeur | `errno = 0; strtol()` |
| Messages statiques | Pas de leak | `return "Error msg";` |
| Codes explicites | Debug facile | `enum { ERR_... }` |

### 5.7 Simulation avec trace d'execution

```
Programme: safe_fopen("missing.txt", "r")

1. Verifie filename != NULL -> OK
2. Verifie mode != NULL -> OK
3. Appelle fopen("missing.txt", "r")
4. fopen retourne NULL, errno = 2 (ENOENT)
5. Verifie f == NULL -> true
6. errno == ENOENT -> error_set(ERR_FILE_NOT_FOUND)
7. Retourne NULL

Etat apres:
- g_last_error = ERR_FILE_NOT_FOUND
- errno = 2 (ENOENT)
- Retour = NULL

Appelant:
FILE *f = safe_fopen("missing.txt", "r");
if (f == NULL) {
    // error_get() == ERR_FILE_NOT_FOUND
    error_print(error_get(), "missing.txt");
    // -> "[ERROR] missing.txt: File not found"
}
```

### 5.8 Mnemotechniques

**"RVG" - Sequence d'erreur**
- **R**eset errno avant l'appel
- **V**erifier le retour immediatement
- **G**erer ou propager l'erreur

**"PERC" - Actions possibles**
- **P**rint (perror, error_print)
- **E**xit (si fatal)
- **R**etry (si transitoire)
- **C**leanup (liberer ressources)

### 5.9 Applications pratiques

1. **Serveurs**: Logging centralise des erreurs
2. **CLI**: Messages d'erreur user-friendly
3. **Libraries**: Codes de retour documentees
4. **Debug**: Traces d'erreur avec contexte

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| errno pas immediatement | Mauvais message | Verifier tout de suite |
| errno pas reset | Faux positif | `errno = 0` avant appel |
| Message dynamique | Memory leak | Strings statiques |
| Pas de validation | Crash | Check NULL, bounds |
| Erreur ignoree | Bug silencieux | Toujours verifier retour |

---

## SECTION 7 : QCM

### Question 1
Quand faut-il verifier errno apres un appel systeme ?

A) Avant l'appel
B) Immediatement apres
C) A la fin de la fonction
D) Jamais
E) Quand on a le temps

**Reponse correcte: B**

### Question 2
Que fait perror("open") ?

A) Ouvre un fichier
B) Affiche "open: message_erreur" sur stderr
C) Retourne le code d'erreur
D) Reset errno
E) Leve une exception

**Reponse correcte: B**

### Question 3
Pourquoi utiliser des codes d'erreur personnalises plutot que errno ?

A) C'est plus rapide
B) errno n'existe pas en C17
C) Pour des erreurs specifiques a l'application
D) errno est deprecie
E) Il n'y a pas de raison

**Reponse correcte: C**

### Question 4
Que vaut errno si aucune erreur n'est survenue ?

A) -1
B) 0
C) NULL
D) Indefini
E) ERR_OK

**Reponse correcte: B**

### Question 5
Quelle est la meilleure pratique pour les messages d'erreur retournes ?

A) Les allouer avec malloc
B) Les stocker dans des variables globales modifiables
C) Utiliser des strings statiques constantes
D) Les calculer a chaque appel
E) Les lire depuis un fichier

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Fonction | Description | Header |
|----------|-------------|--------|
| errno | Variable d'erreur globale | <errno.h> |
| perror(s) | Affiche erreur sur stderr | <stdio.h> |
| strerror(n) | Message pour code n | <string.h> |

| Code errno | Valeur | Description |
|------------|--------|-------------|
| ENOENT | 2 | File not found |
| ENOMEM | 12 | Out of memory |
| EACCES | 13 | Permission denied |
| EINVAL | 22 | Invalid argument |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.10-a",
    "name": "error_handling",
    "module": "0.6.10",
    "phase": 0,
    "difficulty": 4,
    "xp": 250,
    "time_minutes": 150
  },
  "metadata": {
    "concepts": ["errno", "perror", "return codes"],
    "prerequisites": ["0.5", "0.6.9"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "error_handling.c",
    "header": "error_handling.h",
    "solution": "error_handling_solution.c",
    "test": "test_error_handling.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 75,
    "memory_weight": 15
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 5
  }
}
```
