# Exercice 0.9.43 : environment_manager

**Module :**
0.9 — Systems Programming

**Concept :**
getenv(), setenv(), putenv(), environ, environment variables

**Difficulte :**
4/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
C (c17)

**Prerequis :**
- Syntaxe C de base
- Pointeurs et tableaux
- Allocation memoire

**Domaines :**
Unix, Sys, Process

**Duree estimee :**
45 min

**XP Base :**
125

**Complexite :**
T2 O(n) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `environment_manager.c`, `environment_manager.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `getenv`, `setenv`, `unsetenv`, `putenv`, `clearenv`, `malloc`, `free`, `strdup`, `strlen`, `strchr`, `strcmp`, `strncmp`, `printf`, `environ` (variable globale) |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `system`, commandes shell (env, export) |

---

### 1.2 Consigne

#### Section Culture : "Westworld - Variables de Controle"

**WESTWORLD - "These violent delights have violent environment variables"**

Dans Westworld, les hosts (robots) sont controles par des parametres internes : leur "boucle" (routine quotidienne), leurs souvenirs, leur niveau de conscience. Ces parametres sont comme des variables d'environnement qui definissent leur comportement.

*"The environment shapes who we are. PATH determines where we search for commands, just as cornerstone memories determine who the hosts believe they are."*

Dr. Ford t'explique :
- **Boucles narratives** = PATH - ou chercher les executables/comportements
- **Souvenirs de base** = HOME - point de depart, identite
- **Niveau de conscience** = DEBUG - combien de details on voit
- **Directives secretes** = Variables cachees qui controlent tout

*"Some people choose to see the ugliness in this world. The disarray. I choose to see the beauty. The environment variables."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un gestionnaire de variables d'environnement :

1. **env_get** : Recupere une variable
2. **env_set** : Definit/modifie une variable
3. **env_unset** : Supprime une variable
4. **env_list** : Liste toutes les variables
5. **env_expand** : Expanse les variables dans une chaine

**Entree (C) :**

```c
#ifndef ENVIRONMENT_MANAGER_H
# define ENVIRONMENT_MANAGER_H

# include <stddef.h>

// Structure pour stocker une paire cle=valeur
typedef struct s_env_var {
    char    *key;
    char    *value;
} t_env_var;

// Structure pour un environnement complet
typedef struct s_env {
    t_env_var   **vars;     // Tableau de pointeurs vers les variables
    int         count;      // Nombre de variables
    int         capacity;   // Capacite du tableau
} t_env;

// === BASIC FUNCTIONS ===

// Recupere la valeur d'une variable d'environnement
// Retourne NULL si la variable n'existe pas
char    *env_get(const char *name);

// Definit ou modifie une variable d'environnement
// overwrite: 1 = remplace si existe, 0 = ne remplace pas
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     env_set(const char *name, const char *value, int overwrite);

// Supprime une variable d'environnement
// Retourne 0 en cas de succes, -1 si n'existe pas
int     env_unset(const char *name);

// Definit une variable au format "NAME=value"
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     env_put(const char *string);

// === LISTING FUNCTIONS ===

// Retourne le nombre de variables d'environnement
int     env_count(void);

// Retourne une copie du tableau environ (doit etre liberee)
char    **env_copy(void);

// Libere une copie d'environnement
void    env_free_copy(char **copy);

// Affiche toutes les variables (format NAME=value)
void    env_print_all(void);

// === EXPANSION FUNCTIONS ===

// Expanse les variables dans une chaine
// $VAR ou ${VAR} sont remplaces par leur valeur
// Retourne une nouvelle chaine (doit etre liberee)
char    *env_expand(const char *str);

// Expanse les variables avec un environnement personnalise
char    *env_expand_with(const char *str, char **custom_env);

// === CUSTOM ENVIRONMENT ===

// Cree un nouvel environnement vide
t_env   *env_create(void);

// Cree un environnement a partir de environ
t_env   *env_from_environ(void);

// Ajoute/modifie une variable dans un environnement personnalise
int     env_custom_set(t_env *env, const char *name, const char *value);

// Recupere une variable dans un environnement personnalise
char    *env_custom_get(t_env *env, const char *name);

// Supprime une variable dans un environnement personnalise
int     env_custom_unset(t_env *env, const char *name);

// Convertit en tableau char** pour execve
char    **env_to_array(t_env *env);

// Libere un environnement personnalise
void    env_destroy(t_env *env);

// === UTILITY FUNCTIONS ===

// Verifie si un nom de variable est valide
// (commence par lettre ou _, contient lettres, chiffres, _)
int     env_valid_name(const char *name);

// Cherche une variable et retourne son index dans environ
// Retourne -1 si non trouvee
int     env_find_index(const char *name);

// Separe "NAME=value" en name et value
// Retourne 0 si succes, -1 si format invalide
int     env_parse(const char *string, char **name, char **value);

#endif
```

**Sortie :**
- `env_get` : valeur ou NULL
- `env_set` : 0 succes, -1 erreur
- `env_expand` : chaine expansee (malloc'd)
- `env_valid_name` : 1 valide, 0 invalide

**Contraintes :**
- Ne pas modifier directement `environ` sauf via setenv/putenv
- Gerer les noms de variables invalides
- Liberer la memoire correctement
- Supporter l'expansion recursive (limiter la profondeur)

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `env_get("HOME")` | - | "/home/user" | Variable standard |
| `env_set("MY_VAR", "hello", 1)` | - | 0 | Nouvelle variable |
| `env_expand("$HOME/bin")` | - | "/home/user/bin" | Expansion |
| `env_expand("${USER:-default}")` | - | "user" ou "default" | Avec defaut |

---

### 1.3 Prototype

**C :**
```c
#include <stdlib.h>

char    *env_get(const char *name);
int     env_set(const char *name, const char *value, int overwrite);
int     env_unset(const char *name);
int     env_put(const char *string);
int     env_count(void);
char    **env_copy(void);
void    env_free_copy(char **copy);
void    env_print_all(void);
char    *env_expand(const char *str);
t_env   *env_create(void);
t_env   *env_from_environ(void);
int     env_custom_set(t_env *env, const char *name, const char *value);
char    *env_custom_get(t_env *env, const char *name);
int     env_custom_unset(t_env *env, const char *name);
char    **env_to_array(t_env *env);
void    env_destroy(t_env *env);
int     env_valid_name(const char *name);
int     env_find_index(const char *name);
int     env_parse(const char *string, char **name, char **value);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**environ vs envp**

Il y a deux facons d'acceder aux variables d'environnement :
- `extern char **environ` : variable globale
- `int main(int argc, char **argv, char **envp)` : troisieme argument de main

Attention : `envp` est une copie au moment du lancement, `environ` est dynamique !

**PATH est puissant**

La variable PATH controle ou le shell cherche les executables. Un PATH mal configure est une faille de securite classique (PATH injection).

**setenv vs putenv**

- `setenv("NAME", "value", 1)` : copie les chaines
- `putenv("NAME=value")` : utilise la chaine directement (danger!)

Avec putenv, si vous modifiez la chaine apres, l'environnement change aussi !

**Les variables speciales**

- `$?` : code de retour de la derniere commande
- `$$` : PID du shell
- `$!` : PID du dernier processus en arriere-plan
- `$0` : nom du script

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps Engineer** | Configuration d'applications (12-factor) |
| **Backend Developer** | Secrets, API keys, configuration |
| **Shell Developer** | Implementation de bash, zsh |
| **Security Engineer** | Audit de variables sensibles |
| **Container Engineer** | Docker env vars, Kubernetes secrets |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "environment_manager.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Test basic operations
    printf("=== Basic Operations ===\n");
    printf("HOME = %s\n", env_get("HOME"));
    printf("PATH = %s\n", env_get("PATH"));

    // Set a new variable
    env_set("MY_TEST_VAR", "hello world", 1);
    printf("MY_TEST_VAR = %s\n", env_get("MY_TEST_VAR"));

    // Modify existing variable
    env_set("MY_TEST_VAR", "modified", 1);
    printf("MY_TEST_VAR (modified) = %s\n", env_get("MY_TEST_VAR"));

    // Try to set without overwrite
    env_set("MY_TEST_VAR", "not this", 0);
    printf("MY_TEST_VAR (no overwrite) = %s\n", env_get("MY_TEST_VAR"));

    // Unset
    env_unset("MY_TEST_VAR");
    printf("MY_TEST_VAR (after unset) = %s\n",
           env_get("MY_TEST_VAR") ? env_get("MY_TEST_VAR") : "(null)");

    // Count variables
    printf("\n=== Environment Stats ===\n");
    printf("Total variables: %d\n", env_count());

    // Test expansion
    printf("\n=== Expansion ===\n");
    char *expanded = env_expand("My home is $HOME and user is ${USER}");
    printf("Expanded: %s\n", expanded);
    free(expanded);

    expanded = env_expand("Path: $PATH");
    printf("Path expansion: %s\n", expanded);
    free(expanded);

    // Invalid variable name
    printf("\n=== Validation ===\n");
    printf("'VALID_NAME' is %s\n",
           env_valid_name("VALID_NAME") ? "valid" : "invalid");
    printf("'123invalid' is %s\n",
           env_valid_name("123invalid") ? "valid" : "invalid");
    printf("'has-dash' is %s\n",
           env_valid_name("has-dash") ? "valid" : "invalid");

    // Custom environment
    printf("\n=== Custom Environment ===\n");
    t_env *custom = env_create();
    env_custom_set(custom, "CUSTOM_VAR", "custom_value");
    env_custom_set(custom, "ANOTHER", "another_value");
    printf("CUSTOM_VAR = %s\n", env_custom_get(custom, "CUSTOM_VAR"));

    char **arr = env_to_array(custom);
    printf("As array:\n");
    for (int i = 0; arr[i]; i++) {
        printf("  %s\n", arr[i]);
    }
    env_free_copy(arr);
    env_destroy(custom);

    return 0;
}

$ gcc -Wall -Wextra environment_manager.c main.c -o env_test
$ ./env_test
=== Basic Operations ===
HOME = /home/user
PATH = /usr/local/bin:/usr/bin:/bin
MY_TEST_VAR = hello world
MY_TEST_VAR (modified) = modified
MY_TEST_VAR (no overwrite) = modified
MY_TEST_VAR (after unset) = (null)

=== Environment Stats ===
Total variables: 42

=== Expansion ===
Expanded: My home is /home/user and user is user
Path expansion: Path: /usr/local/bin:/usr/bin:/bin

=== Validation ===
'VALID_NAME' is valid
'123invalid' is invalid
'has-dash' is invalid

=== Custom Environment ===
CUSTOM_VAR = custom_value
As array:
  CUSTOM_VAR=custom_value
  ANOTHER=another_value
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
6/10

**Recompense :**
XP x1.5

**Consigne Bonus :**

Implementer l'expansion avancee comme bash :

```c
// Expansion avec valeur par defaut si non definie
// ${VAR:-default} -> valeur de VAR ou "default"
char *env_expand_default(const char *str);

// Expansion avec affectation si non definie
// ${VAR:=default} -> affecte et retourne "default" si VAR non definie
char *env_expand_assign(const char *str);

// Expansion avec erreur si non definie
// ${VAR:?error} -> erreur si VAR non definie
char *env_expand_error(const char *str);

// Expansion avec valeur alternative si definie
// ${VAR:+alternative} -> "alternative" si VAR est definie
char *env_expand_alternate(const char *str);

// Expansion avec substring
// ${VAR:offset:length} -> sous-chaine
char *env_expand_substring(const char *str);

// Expansion avec remplacement de pattern
// ${VAR/pattern/replacement}
char *env_expand_replace(const char *str);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | env_get_exists | env_get("PATH") | non-NULL | 10 | Basic |
| 2 | env_get_missing | env_get("NONEXISTENT") | NULL | 5 | Basic |
| 3 | env_set_new | env_set("NEW", "val", 1) | 0, accessible | 10 | Set |
| 4 | env_set_overwrite | overwrite=1 | updated | 10 | Set |
| 5 | env_set_no_overwrite | overwrite=0 | unchanged | 10 | Set |
| 6 | env_unset | env_unset("VAR") | removed | 10 | Unset |
| 7 | env_expand_simple | "$HOME" | expanded | 15 | Expand |
| 8 | env_expand_braces | "${USER}" | expanded | 10 | Expand |
| 9 | env_valid_name | various | correct | 10 | Validate |
| 10 | custom_env | create, set, get | works | 10 | Custom |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "environment_manager.h"

void test_env_get(void) {
    // PATH should always exist
    assert(env_get("PATH") != NULL);

    // Non-existent variable
    assert(env_get("DEFINITELY_NOT_A_REAL_VAR_12345") == NULL);

    printf("Test env_get: OK\n");
}

void test_env_set(void) {
    // Set new variable
    assert(env_set("TEST_VAR_SET", "test_value", 1) == 0);
    assert(strcmp(env_get("TEST_VAR_SET"), "test_value") == 0);

    // Overwrite
    assert(env_set("TEST_VAR_SET", "new_value", 1) == 0);
    assert(strcmp(env_get("TEST_VAR_SET"), "new_value") == 0);

    // No overwrite
    assert(env_set("TEST_VAR_SET", "ignored", 0) == 0);
    assert(strcmp(env_get("TEST_VAR_SET"), "new_value") == 0);

    // Cleanup
    env_unset("TEST_VAR_SET");
    printf("Test env_set: OK\n");
}

void test_env_unset(void) {
    env_set("TO_BE_DELETED", "value", 1);
    assert(env_get("TO_BE_DELETED") != NULL);

    assert(env_unset("TO_BE_DELETED") == 0);
    assert(env_get("TO_BE_DELETED") == NULL);

    printf("Test env_unset: OK\n");
}

void test_env_expand(void) {
    env_set("EXPAND_TEST", "hello", 1);

    char *result = env_expand("$EXPAND_TEST world");
    assert(result != NULL);
    assert(strcmp(result, "hello world") == 0);
    free(result);

    result = env_expand("${EXPAND_TEST}!");
    assert(result != NULL);
    assert(strcmp(result, "hello!") == 0);
    free(result);

    // Non-existent variable
    result = env_expand("$NONEXISTENT_VAR");
    assert(result != NULL);
    assert(strcmp(result, "") == 0);
    free(result);

    env_unset("EXPAND_TEST");
    printf("Test env_expand: OK\n");
}

void test_env_valid_name(void) {
    assert(env_valid_name("VALID") == 1);
    assert(env_valid_name("_also_valid") == 1);
    assert(env_valid_name("with_123") == 1);
    assert(env_valid_name("123invalid") == 0);
    assert(env_valid_name("has-dash") == 0);
    assert(env_valid_name("has space") == 0);
    assert(env_valid_name("") == 0);
    assert(env_valid_name(NULL) == 0);

    printf("Test env_valid_name: OK\n");
}

void test_env_count(void) {
    int initial = env_count();
    env_set("COUNT_TEST", "value", 1);
    assert(env_count() == initial + 1);
    env_unset("COUNT_TEST");
    assert(env_count() == initial);

    printf("Test env_count: OK\n");
}

void test_custom_env(void) {
    t_env *env = env_create();
    assert(env != NULL);

    env_custom_set(env, "VAR1", "value1");
    env_custom_set(env, "VAR2", "value2");

    assert(strcmp(env_custom_get(env, "VAR1"), "value1") == 0);
    assert(strcmp(env_custom_get(env, "VAR2"), "value2") == 0);
    assert(env_custom_get(env, "VAR3") == NULL);

    char **arr = env_to_array(env);
    assert(arr != NULL);
    int count = 0;
    while (arr[count]) count++;
    assert(count == 2);
    env_free_copy(arr);

    env_destroy(env);
    printf("Test custom_env: OK\n");
}

int main(void) {
    test_env_get();
    test_env_set();
    test_env_unset();
    test_env_expand();
    test_env_valid_name();
    test_env_count();
    test_custom_env();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "environment_manager.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

extern char **environ;

char *env_get(const char *name) {
    if (!name)
        return NULL;
    return getenv(name);
}

int env_set(const char *name, const char *value, int overwrite) {
    if (!name || !env_valid_name(name))
        return -1;
    return setenv(name, value ? value : "", overwrite);
}

int env_unset(const char *name) {
    if (!name || !env_valid_name(name))
        return -1;
    return unsetenv(name);
}

int env_put(const char *string) {
    if (!string || !strchr(string, '='))
        return -1;
    return putenv((char*)string);
}

int env_count(void) {
    int count = 0;
    if (environ) {
        while (environ[count])
            count++;
    }
    return count;
}

char **env_copy(void) {
    int count = env_count();
    char **copy = malloc(sizeof(char*) * (count + 1));
    if (!copy)
        return NULL;

    for (int i = 0; i < count; i++) {
        copy[i] = strdup(environ[i]);
        if (!copy[i]) {
            env_free_copy(copy);
            return NULL;
        }
    }
    copy[count] = NULL;
    return copy;
}

void env_free_copy(char **copy) {
    if (!copy)
        return;
    for (int i = 0; copy[i]; i++)
        free(copy[i]);
    free(copy);
}

void env_print_all(void) {
    if (!environ)
        return;
    for (int i = 0; environ[i]; i++)
        printf("%s\n", environ[i]);
}

static char *expand_variable(const char *name) {
    char *value = env_get(name);
    return value ? strdup(value) : strdup("");
}

char *env_expand(const char *str) {
    if (!str)
        return NULL;

    size_t capacity = strlen(str) * 2 + 1;
    char *result = malloc(capacity);
    if (!result)
        return NULL;

    size_t pos = 0;
    const char *p = str;

    while (*p) {
        if (*p == '$' && (isalpha(p[1]) || p[1] == '_' || p[1] == '{')) {
            p++;
            int braces = (*p == '{');
            if (braces) p++;

            const char *start = p;
            while (*p && (isalnum(*p) || *p == '_'))
                p++;

            size_t name_len = p - start;
            char *name = strndup(start, name_len);

            if (braces && *p == '}')
                p++;

            char *value = expand_variable(name);
            size_t value_len = strlen(value);
            free(name);

            // Resize if needed
            while (pos + value_len + 1 > capacity) {
                capacity *= 2;
                char *new_result = realloc(result, capacity);
                if (!new_result) {
                    free(result);
                    free(value);
                    return NULL;
                }
                result = new_result;
            }

            memcpy(result + pos, value, value_len);
            pos += value_len;
            free(value);
        } else {
            if (pos + 2 > capacity) {
                capacity *= 2;
                result = realloc(result, capacity);
            }
            result[pos++] = *p++;
        }
    }

    result[pos] = '\0';
    return result;
}

char *env_expand_with(const char *str, char **custom_env) {
    // Save current environ
    char **saved = environ;
    environ = custom_env;

    char *result = env_expand(str);

    // Restore environ
    environ = saved;
    return result;
}

t_env *env_create(void) {
    t_env *env = malloc(sizeof(t_env));
    if (!env)
        return NULL;

    env->capacity = 16;
    env->count = 0;
    env->vars = malloc(sizeof(t_env_var*) * env->capacity);
    if (!env->vars) {
        free(env);
        return NULL;
    }

    return env;
}

t_env *env_from_environ(void) {
    t_env *env = env_create();
    if (!env || !environ)
        return env;

    for (int i = 0; environ[i]; i++) {
        char *name, *value;
        if (env_parse(environ[i], &name, &value) == 0) {
            env_custom_set(env, name, value);
            free(name);
            free(value);
        }
    }

    return env;
}

int env_custom_set(t_env *env, const char *name, const char *value) {
    if (!env || !name || !env_valid_name(name))
        return -1;

    // Check if exists
    for (int i = 0; i < env->count; i++) {
        if (strcmp(env->vars[i]->key, name) == 0) {
            free(env->vars[i]->value);
            env->vars[i]->value = strdup(value ? value : "");
            return 0;
        }
    }

    // Resize if needed
    if (env->count >= env->capacity) {
        env->capacity *= 2;
        env->vars = realloc(env->vars, sizeof(t_env_var*) * env->capacity);
        if (!env->vars)
            return -1;
    }

    // Add new
    t_env_var *var = malloc(sizeof(t_env_var));
    if (!var)
        return -1;

    var->key = strdup(name);
    var->value = strdup(value ? value : "");
    env->vars[env->count++] = var;

    return 0;
}

char *env_custom_get(t_env *env, const char *name) {
    if (!env || !name)
        return NULL;

    for (int i = 0; i < env->count; i++) {
        if (strcmp(env->vars[i]->key, name) == 0)
            return env->vars[i]->value;
    }

    return NULL;
}

int env_custom_unset(t_env *env, const char *name) {
    if (!env || !name)
        return -1;

    for (int i = 0; i < env->count; i++) {
        if (strcmp(env->vars[i]->key, name) == 0) {
            free(env->vars[i]->key);
            free(env->vars[i]->value);
            free(env->vars[i]);

            // Shift remaining
            for (int j = i; j < env->count - 1; j++)
                env->vars[j] = env->vars[j + 1];

            env->count--;
            return 0;
        }
    }

    return -1;
}

char **env_to_array(t_env *env) {
    if (!env)
        return NULL;

    char **arr = malloc(sizeof(char*) * (env->count + 1));
    if (!arr)
        return NULL;

    for (int i = 0; i < env->count; i++) {
        size_t len = strlen(env->vars[i]->key) +
                     strlen(env->vars[i]->value) + 2;
        arr[i] = malloc(len);
        if (!arr[i]) {
            for (int j = 0; j < i; j++)
                free(arr[j]);
            free(arr);
            return NULL;
        }
        sprintf(arr[i], "%s=%s", env->vars[i]->key, env->vars[i]->value);
    }
    arr[env->count] = NULL;

    return arr;
}

void env_destroy(t_env *env) {
    if (!env)
        return;

    for (int i = 0; i < env->count; i++) {
        free(env->vars[i]->key);
        free(env->vars[i]->value);
        free(env->vars[i]);
    }
    free(env->vars);
    free(env);
}

int env_valid_name(const char *name) {
    if (!name || !*name)
        return 0;

    // First char must be letter or underscore
    if (!isalpha(*name) && *name != '_')
        return 0;

    // Rest must be alphanumeric or underscore
    for (const char *p = name + 1; *p; p++) {
        if (!isalnum(*p) && *p != '_')
            return 0;
    }

    return 1;
}

int env_find_index(const char *name) {
    if (!name || !environ)
        return -1;

    size_t name_len = strlen(name);
    for (int i = 0; environ[i]; i++) {
        if (strncmp(environ[i], name, name_len) == 0 &&
            environ[i][name_len] == '=')
            return i;
    }

    return -1;
}

int env_parse(const char *string, char **name, char **value) {
    if (!string || !name || !value)
        return -1;

    const char *eq = strchr(string, '=');
    if (!eq)
        return -1;

    *name = strndup(string, eq - string);
    *value = strdup(eq + 1);

    if (!*name || !*value) {
        free(*name);
        free(*value);
        return -1;
    }

    return 0;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de verification name vide**

```c
/* Mutant A : Crash sur nom vide */
int env_set(const char *name, const char *value, int overwrite) {
    return setenv(name, value, overwrite);
    // ERREUR: setenv(NULL, ...) ou setenv("", ...) = comportement indefini !
}
// Pourquoi c'est faux: Pas de validation du nom
```

**Mutant B (Safety) : putenv avec stack variable**

```c
/* Mutant B : Corruption memoire */
int env_put(const char *string) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s", string);
    return putenv(buffer);
    // ERREUR: buffer est sur la stack et sera detruit !
    // L'environnement pointera vers de la memoire invalide
}
// Pourquoi c'est faux: putenv ne copie pas, utilise le pointeur directement
```

**Mutant C (Resource) : Memory leak dans expand**

```c
/* Mutant C : Fuite memoire */
char *env_expand(const char *str) {
    char *result = malloc(1024);
    // ...
    if (error_condition) {
        return NULL;  // ERREUR: result n'est pas libere !
    }
    // ...
}
// Pourquoi c'est faux: Fuite de memoire sur les chemins d'erreur
```

**Mutant D (Logic) : Expansion sans verification '}'**

```c
/* Mutant D : Parse incorrect */
char *env_expand(const char *str) {
    // ...
    if (*p == '$' && p[1] == '{') {
        p += 2;
        const char *start = p;
        while (*p && *p != '}') p++;
        // ERREUR: si pas de '}', on lit jusqu'a la fin !
        // "${VAR" sans } -> lit trop de caracteres
    }
}
// Pourquoi c'est faux: Pas de gestion des accolades non fermees
```

**Mutant E (Return) : env_get retourne pointeur interne modifiable**

```c
/* Mutant E : Modification accidentelle */
// getenv() retourne un pointeur vers la vraie valeur
// Si l'utilisateur la modifie, l'environnement est corrompu !
char *value = env_get("PATH");
value[0] = 'X';  // DANGER: modifie l'environnement !
```
---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| getenv() | Lecture de variables | Fondamental |
| setenv() | Modification de variables | Essentiel |
| environ | Acces direct a l'environnement | Important |
| Expansion | Substitution de variables | Shell |

---

### 5.2 LDA - Traduction litterale

```
FONCTION env_expand QUI PREND str
DEBUT FONCTION
    CREER UN BUFFER RESULTAT

    POUR CHAQUE CARACTERE c DE str FAIRE
        SI c == '$' ALORS
            SI caractere suivant EST '{' ALORS
                LIRE LE NOM JUSQU'A '}'
            SINON
                LIRE LE NOM (lettres, chiffres, _)
            FIN SI

            RECUPERER LA VALEUR AVEC getenv
            AJOUTER LA VALEUR AU RESULTAT
        SINON
            AJOUTER c AU RESULTAT
        FIN SI
    FIN POUR

    RETOURNER LE RESULTAT
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
STRUCTURE DE L'ENVIRONNEMENT
============================

extern char **environ;

environ (char**)
    |
    v
+--------+     +----------------------+
|   [0] -+---->| "PATH=/usr/bin:/bin" |
+--------+     +----------------------+
|   [1] -+---->| "HOME=/home/user"    |
+--------+     +----------------------+
|   [2] -+---->| "USER=user"          |
+--------+     +----------------------+
|   [3] -+---->| "SHELL=/bin/bash"    |
+--------+     +----------------------+
|  NULL  |
+--------+


SETENV vs PUTENV
================

setenv("VAR", "value", 1):
    1. Alloue une nouvelle chaine "VAR=value"
    2. Ajoute le pointeur a environ
    3. La chaine originale n'est PAS utilisee

putenv("VAR=value"):
    1. Utilise DIRECTEMENT le pointeur passe
    2. Pas de copie !
    3. DANGER si la chaine est sur la stack

Exemple dangereux:
    void bad_function() {
        char str[32] = "VAR=temp";
        putenv(str);
    }  // str est detruit, environ pointe vers garbage!


EXPANSION DE VARIABLES
======================

Input: "Hello $USER, your home is ${HOME}!"

Parsing:
    "Hello "     -> copie directe
    "$USER"      -> lookup USER -> "john"
    ", your home is "  -> copie directe
    "${HOME}"    -> lookup HOME -> "/home/john"
    "!"          -> copie directe

Output: "Hello john, your home is /home/john!"


SYNTAXE D'EXPANSION BASH (BONUS)
================================

${VAR}          -> Valeur de VAR
${VAR:-default} -> VAR si definie, sinon "default"
${VAR:=default} -> Comme :- mais assigne aussi VAR
${VAR:?error}   -> VAR si definie, sinon erreur
${VAR:+alt}     -> "alt" si VAR definie, sinon rien
${VAR:offset}   -> Substring depuis offset
${VAR:off:len}  -> Substring de off a len
${#VAR}         -> Longueur de VAR
${VAR#pattern}  -> Retire prefix
${VAR%pattern}  -> Retire suffix


HERITAGE DE L'ENVIRONNEMENT
===========================

Parent Process
    |
    +-- environ: PATH, HOME, USER
    |
    +-- fork()
         |
         v
    Child Process
         |
         +-- environ: (copie) PATH, HOME, USER
         |
         +-- execve(prog, argv, envp)
              |
              v
         New Program
              |
              +-- environ: envp (passe explicitement)


SECURITE
========

Variables sensibles (ne jamais logger !):
    - AWS_SECRET_ACCESS_KEY
    - DATABASE_PASSWORD
    - API_TOKEN
    - JWT_SECRET

Variables de securite:
    - PATH (injection de commandes)
    - LD_LIBRARY_PATH (injection de bibliotheques)
    - LD_PRELOAD (hooking)
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 3 getenv` - Documentation getenv
- `man 3 setenv` - Documentation setenv
- `man 7 environ` - Vue d'ensemble de l'environnement
- Bash Reference Manual - Parameter Expansion

### 6.2 Commandes utiles

```bash
# Afficher toutes les variables
env
printenv

# Afficher une variable specifique
echo $HOME
printenv HOME

# Definir une variable pour une commande
VAR=value command

# Exporter une variable
export MY_VAR="value"

# Supprimer une variable
unset MY_VAR

# Voir les variables exportees
export -p
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Manipuler** les variables d'environnement en C
2. **Comprendre** la difference entre setenv et putenv
3. **Implementer** l'expansion de variables
4. **Creer** des environnements personnalises pour execve
5. **Eviter** les pieges de securite lies aux variables

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.34 fork_exec | Passage d'environnement a execve |
| 0.9.45 daemon | Configuration par variables |
| Shell (minishell) | Expansion de variables |
| DevOps | Configuration d'applications |
