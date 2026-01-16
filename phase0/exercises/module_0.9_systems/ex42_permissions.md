# Exercice 0.9.42 : permission_manager

**Module :**
0.9 — Systems Programming

**Concept :**
chmod(), chown(), umask(), file permissions, access control

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
- Notions de systeme de fichiers
- Exercice ex41_filesystem
- Comprendre les utilisateurs/groupes Unix

**Domaines :**
Security, Unix, Sys, Filesystem

**Duree estimee :**
45 min

**XP Base :**
125

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `permission_manager.c`, `permission_manager.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `chmod`, `fchmod`, `chown`, `fchown`, `lchown`, `access`, `umask`, `stat`, `lstat`, `getuid`, `geteuid`, `getgid`, `getegid`, `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`, `perror`, `printf`, `malloc`, `free` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `system`, commandes shell (chmod, chown en ligne de commande) |

---

### 1.2 Consigne

#### Section Culture : "Mission Impossible - Acces Refuse"

**MISSION IMPOSSIBLE - "Your mission, should you choose to accept it..."**

Dans Mission Impossible, Ethan Hunt doit souvent contourner des systemes de securite sophistiques. Les permissions Unix sont comme ces lasers de securite : READ te permet de voir, WRITE de modifier, EXECUTE de traverser.

*"The IMF has three clearance levels: Read access lets you view classified files. Write access lets you modify mission parameters. Execute access lets you run field operations."*

Le directeur Hunley t'explique :
- **Niveau OWNER** = Agent principal (rwx) - acces total
- **Niveau GROUP** = Equipe IMF (r-x) - lecture et execution
- **Niveau OTHER** = Gouvernement (r--) - lecture seule
- **SUID/SGID** = Acces temporaire aux privileges superieurs
- **Sticky bit** = Dossier partage securise (/tmp)

*"This message will self-destruct in 5 seconds... unless you chmod 000 it first."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un gestionnaire de permissions Unix :

1. **set_permissions** : Modifie les permissions d'un fichier
2. **set_owner** : Change le proprietaire/groupe
3. **check_access** : Verifie les droits d'acces
4. **get_umask** / **set_umask** : Gere le masque de creation
5. **parse_mode** : Parse une chaine de permissions (rwxr-xr-x ou 755)

**Entree (C) :**

```c
#ifndef PERMISSION_MANAGER_H
# define PERMISSION_MANAGER_H

# include <sys/types.h>
# include <sys/stat.h>

typedef enum e_perm_who {
    PERM_OWNER = 0,     // u
    PERM_GROUP = 1,     // g
    PERM_OTHER = 2,     // o
    PERM_ALL   = 3      // a
} t_perm_who;

typedef enum e_perm_what {
    PERM_READ    = 4,   // r
    PERM_WRITE   = 2,   // w
    PERM_EXEC    = 1,   // x
    PERM_SETUID  = 04000,
    PERM_SETGID  = 02000,
    PERM_STICKY  = 01000
} t_perm_what;

typedef enum e_perm_op {
    PERM_SET = 0,       // =
    PERM_ADD = 1,       // +
    PERM_REMOVE = 2     // -
} t_perm_op;

// Structure pour representer une modification de permission
typedef struct s_perm_change {
    t_perm_who  who;        // u, g, o, a
    t_perm_op   op;         // +, -, =
    int         perms;      // Combinaison de rwx
} t_perm_change;

// === PERMISSION FUNCTIONS ===

// Modifie les permissions d'un fichier (comme chmod)
// mode peut etre numerique (0755) ou symbolique (u+x)
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     set_permissions(const char *path, mode_t mode);

// Modifie les permissions avec une chaine symbolique (u+x, go-w, etc.)
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     set_permissions_symbolic(const char *path, const char *mode_str);

// Recupere les permissions actuelles
mode_t  get_permissions(const char *path);

// Convertit un mode en chaine "rwxr-xr-x" (10 chars avec type)
void    mode_to_string(mode_t mode, char *str);

// Convertit une chaine en mode numerique
// Accepte "755", "rwxr-xr-x", "u=rwx,g=rx,o=rx"
// Retourne -1 si la chaine est invalide
int     parse_mode_string(const char *str, mode_t *mode);

// === OWNERSHIP FUNCTIONS ===

// Change le proprietaire d'un fichier
// owner peut etre un nom ou UID en string
int     set_owner(const char *path, const char *owner);

// Change le groupe d'un fichier
int     set_group(const char *path, const char *group);

// Change proprietaire et groupe en une fois
int     set_owner_group(const char *path, const char *owner, const char *group);

// Recupere le nom du proprietaire (malloc'd)
char    *get_owner_name(const char *path);

// Recupere le nom du groupe (malloc'd)
char    *get_group_name(const char *path);

// === ACCESS CHECK FUNCTIONS ===

// Verifie si le processus courant a l'acces specifie
// mode: R_OK, W_OK, X_OK, F_OK
int     check_access(const char *path, int mode);

// Verifie si un utilisateur specifique aurait l'acces
int     check_access_for_user(const char *path, uid_t uid, gid_t gid, int mode);

// === UMASK FUNCTIONS ===

// Recupere le umask actuel
mode_t  get_current_umask(void);

// Definit un nouveau umask
// Retourne l'ancien umask
mode_t  set_new_umask(mode_t mask);

// Calcule les permissions effectives apres umask
mode_t  apply_umask(mode_t requested, mode_t umask);

// === UTILITY FUNCTIONS ===

// Verifie si le processus a les privileges root
int     is_root(void);

// Verifie si le fichier a le bit SUID
int     has_suid(const char *path);

// Verifie si le fichier a le bit SGID
int     has_sgid(const char *path);

// Verifie si le fichier a le sticky bit
int     has_sticky(const char *path);

#endif
```

**Sortie :**
- `set_permissions` : 0 succes, -1 erreur
- `get_permissions` : mode_t ou (mode_t)-1 en erreur
- `check_access` : 0 si acces OK, -1 sinon
- `parse_mode_string` : 0 succes avec mode rempli, -1 erreur

**Contraintes :**
- Gerer les erreurs de permission (EPERM, EACCES)
- Supporter les formats numeriques (0755) et symboliques (u+x)
- Ne pas modifier les permissions sans verification

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `set_permissions("f.txt", 0644)` | - | 0 | rw-r--r-- |
| `set_permissions_symbolic("f.txt", "u+x")` | - | 0 | Ajoute exec owner |
| `parse_mode_string("755", &m)` | - | 0, m=0755 | Parse octal |
| `check_access("f.txt", R_OK)` | - | 0 | Readable |

---

### 1.3 Prototype

**C :**
```c
#include <sys/stat.h>
#include <unistd.h>

int     set_permissions(const char *path, mode_t mode);
int     set_permissions_symbolic(const char *path, const char *mode_str);
mode_t  get_permissions(const char *path);
void    mode_to_string(mode_t mode, char *str);
int     parse_mode_string(const char *str, mode_t *mode);
int     set_owner(const char *path, const char *owner);
int     set_group(const char *path, const char *group);
int     set_owner_group(const char *path, const char *owner, const char *group);
char    *get_owner_name(const char *path);
char    *get_group_name(const char *path);
int     check_access(const char *path, int mode);
mode_t  get_current_umask(void);
mode_t  set_new_umask(mode_t mask);
mode_t  apply_umask(mode_t requested, mode_t umask);
int     is_root(void);
int     has_suid(const char *path);
int     has_sgid(const char *path);
int     has_sticky(const char *path);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi 777 est dangereux**

`chmod 777` donne tous les droits a tout le monde. Sur un serveur web, cela permet a n'importe qui de modifier vos fichiers. C'est la premiere chose que les hackers recherchent !

**Le fameux umask 022**

Par defaut, Unix utilise umask 022. Cela signifie que les fichiers sont crees avec 644 (666 - 022) et les repertoires avec 755 (777 - 022).

**SUID root = danger**

Un fichier avec SUID root s'execute avec les privileges root, meme si lance par un utilisateur normal. C'est ainsi que `passwd` peut modifier `/etc/shadow`. Mais un bug dans un programme SUID = privilege escalation !

**Le sticky bit /tmp**

Sans le sticky bit, n'importe qui pourrait supprimer les fichiers des autres dans /tmp. Avec le sticky bit, seul le proprietaire peut supprimer ses fichiers.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **SysAdmin** | Securisation des serveurs |
| **DevOps** | Deployment scripts, containers |
| **Security Engineer** | Audit de permissions, hardening |
| **Web Developer** | Upload de fichiers, securite |
| **Pentester** | Recherche de mauvaises permissions |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "permission_manager.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *file = argc > 1 ? argv[1] : "test.txt";

    // Create test file
    FILE *f = fopen(file, "w");
    if (f) {
        fputs("Test content\n", f);
        fclose(f);
    }

    // Get current permissions
    mode_t mode = get_permissions(file);
    char mode_str[11];
    mode_to_string(mode, mode_str);
    printf("Current: %s (0%o)\n", mode_str, mode & 0777);

    // Set new permissions
    printf("\nSetting permissions to 0644...\n");
    set_permissions(file, 0644);
    mode = get_permissions(file);
    mode_to_string(mode, mode_str);
    printf("After set_permissions: %s\n", mode_str);

    // Symbolic modification
    printf("\nAdding execute for owner (u+x)...\n");
    set_permissions_symbolic(file, "u+x");
    mode = get_permissions(file);
    mode_to_string(mode, mode_str);
    printf("After u+x: %s\n", mode_str);

    // Parse mode string
    mode_t parsed;
    parse_mode_string("rwxr-xr--", &parsed);
    printf("\nParsed 'rwxr-xr--' = 0%o\n", parsed);

    parse_mode_string("750", &parsed);
    printf("Parsed '750' = 0%o\n", parsed);

    // Check access
    printf("\nAccess checks:\n");
    printf("  Read: %s\n", check_access(file, R_OK) == 0 ? "yes" : "no");
    printf("  Write: %s\n", check_access(file, W_OK) == 0 ? "yes" : "no");
    printf("  Execute: %s\n", check_access(file, X_OK) == 0 ? "yes" : "no");

    // Owner info
    char *owner = get_owner_name(file);
    char *group = get_group_name(file);
    printf("\nOwner: %s, Group: %s\n", owner, group);
    free(owner);
    free(group);

    // Umask
    mode_t old_umask = get_current_umask();
    printf("\nCurrent umask: 0%o\n", old_umask);
    printf("Effective permissions for 0666: 0%o\n", apply_umask(0666, old_umask));

    // Cleanup
    unlink(file);
    return 0;
}

$ gcc -Wall -Wextra permission_manager.c main.c -o perm_test
$ ./perm_test myfile.txt
Current: -rw-r--r-- (0644)

Setting permissions to 0644...
After set_permissions: -rw-r--r--

Adding execute for owner (u+x)...
After u+x: -rwxr--r--

Parsed 'rwxr-xr--' = 0754
Parsed '750' = 0750

Access checks:
  Read: yes
  Write: yes
  Execute: yes

Owner: user, Group: user

Current umask: 022
Effective permissions for 0666: 0644
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
6/10

**Recompense :**
XP x1.5

**Consigne Bonus :**

Implementer un mini-`chmod` avec support complet :

```c
// Parse les arguments style chmod
// Exemples: "755 file", "u+x file", "a=rx file", "-R 755 dir"
typedef struct s_chmod_args {
    char    *mode_str;
    char    **files;
    int     file_count;
    int     recursive;      // -R
    int     verbose;        // -v
    int     changes;        // -c
    int     silent;         // -f
} t_chmod_args;

// Parse les arguments
int parse_chmod_args(int argc, char **argv, t_chmod_args *args);

// Execute chmod avec les arguments
int execute_chmod(const t_chmod_args *args);

// Support des modes symboliques complets
// u+rwx, g=rx, o-w, a+x, u=rwx,g=rx,o=r
int apply_symbolic_mode(const char *mode_str, mode_t current, mode_t *result);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | set_perms_octal | set_permissions(f, 0755) | mode=0755 | 10 | Basic |
| 2 | set_perms_symbolic | "u+x" | owner exec | 10 | Symbolic |
| 3 | parse_octal | "644" | 0644 | 10 | Parse |
| 4 | parse_symbolic | "rwxr-xr-x" | 0755 | 10 | Parse |
| 5 | mode_to_string | 0755 | "rwxr-xr-x" | 10 | Convert |
| 6 | check_access | R_OK | 0 | 10 | Access |
| 7 | get_owner | - | correct name | 10 | Owner |
| 8 | umask_apply | 0666, 022 | 0644 | 10 | Umask |
| 9 | suid_sgid_sticky | special bits | detected | 10 | Special |
| 10 | error_handling | invalid path | -1 | 10 | Error |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include "permission_manager.h"

#define TEST_FILE "/tmp/perm_test_file"

void setup(void) {
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}

void cleanup(void) {
    unlink(TEST_FILE);
}

void test_set_permissions_octal(void) {
    setup();
    assert(set_permissions(TEST_FILE, 0755) == 0);
    assert((get_permissions(TEST_FILE) & 0777) == 0755);

    assert(set_permissions(TEST_FILE, 0600) == 0);
    assert((get_permissions(TEST_FILE) & 0777) == 0600);

    cleanup();
    printf("Test set_permissions_octal: OK\n");
}

void test_set_permissions_symbolic(void) {
    setup();
    set_permissions(TEST_FILE, 0644);

    assert(set_permissions_symbolic(TEST_FILE, "u+x") == 0);
    assert((get_permissions(TEST_FILE) & 0100) == 0100);

    assert(set_permissions_symbolic(TEST_FILE, "g+w") == 0);
    assert((get_permissions(TEST_FILE) & 0020) == 0020);

    assert(set_permissions_symbolic(TEST_FILE, "o-r") == 0);
    assert((get_permissions(TEST_FILE) & 0004) == 0);

    cleanup();
    printf("Test set_permissions_symbolic: OK\n");
}

void test_parse_mode_string(void) {
    mode_t mode;

    assert(parse_mode_string("755", &mode) == 0);
    assert(mode == 0755);

    assert(parse_mode_string("644", &mode) == 0);
    assert(mode == 0644);

    assert(parse_mode_string("rwxr-xr-x", &mode) == 0);
    assert(mode == 0755);

    assert(parse_mode_string("rw-r--r--", &mode) == 0);
    assert(mode == 0644);

    printf("Test parse_mode_string: OK\n");
}

void test_mode_to_string(void) {
    char str[11];

    mode_to_string(0755 | S_IFREG, str);
    assert(strcmp(str, "-rwxr-xr-x") == 0);

    mode_to_string(0644 | S_IFREG, str);
    assert(strcmp(str, "-rw-r--r--") == 0);

    mode_to_string(0755 | S_IFDIR, str);
    assert(strcmp(str, "drwxr-xr-x") == 0);

    printf("Test mode_to_string: OK\n");
}

void test_check_access(void) {
    setup();
    set_permissions(TEST_FILE, 0644);

    assert(check_access(TEST_FILE, F_OK) == 0);
    assert(check_access(TEST_FILE, R_OK) == 0);
    assert(check_access(TEST_FILE, W_OK) == 0);

    set_permissions(TEST_FILE, 0000);
    // Note: root can still access, so this test may vary
    if (!is_root()) {
        assert(check_access(TEST_FILE, R_OK) == -1);
    }

    cleanup();
    printf("Test check_access: OK\n");
}

void test_umask_functions(void) {
    mode_t old = get_current_umask();

    mode_t new_mask = set_new_umask(0077);
    assert(get_current_umask() == 0077);

    set_new_umask(old); // Restore

    assert(apply_umask(0666, 0022) == 0644);
    assert(apply_umask(0777, 0022) == 0755);
    assert(apply_umask(0777, 0077) == 0700);

    printf("Test umask_functions: OK\n");
}

void test_owner_functions(void) {
    setup();

    char *owner = get_owner_name(TEST_FILE);
    assert(owner != NULL);
    assert(strlen(owner) > 0);
    free(owner);

    char *group = get_group_name(TEST_FILE);
    assert(group != NULL);
    assert(strlen(group) > 0);
    free(group);

    cleanup();
    printf("Test owner_functions: OK\n");
}

int main(void) {
    test_set_permissions_octal();
    test_set_permissions_symbolic();
    test_parse_mode_string();
    test_mode_to_string();
    test_check_access();
    test_umask_functions();
    test_owner_functions();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "permission_manager.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

int set_permissions(const char *path, mode_t mode) {
    if (!path)
        return -1;
    return chmod(path, mode);
}

int set_permissions_symbolic(const char *path, const char *mode_str) {
    if (!path || !mode_str)
        return -1;

    mode_t current = get_permissions(path);
    if (current == (mode_t)-1)
        return -1;

    // Parse symbolic mode (simplified: handles u+x, g-w, o=r, a+x)
    const char *p = mode_str;
    int who_mask = 0;
    t_perm_op op = PERM_SET;
    int perms = 0;

    // Parse who (u, g, o, a)
    while (*p && strchr("ugoa", *p)) {
        switch (*p) {
            case 'u': who_mask |= 0700; break;
            case 'g': who_mask |= 0070; break;
            case 'o': who_mask |= 0007; break;
            case 'a': who_mask |= 0777; break;
        }
        p++;
    }
    if (who_mask == 0)
        who_mask = 0777; // Default to all

    // Parse operator
    if (*p == '+') op = PERM_ADD;
    else if (*p == '-') op = PERM_REMOVE;
    else if (*p == '=') op = PERM_SET;
    else return -1;
    p++;

    // Parse permissions (r, w, x)
    while (*p && strchr("rwx", *p)) {
        switch (*p) {
            case 'r': perms |= 0444; break;
            case 'w': perms |= 0222; break;
            case 'x': perms |= 0111; break;
        }
        p++;
    }

    perms &= who_mask;

    mode_t new_mode = current;
    switch (op) {
        case PERM_ADD:
            new_mode |= perms;
            break;
        case PERM_REMOVE:
            new_mode &= ~perms;
            break;
        case PERM_SET:
            new_mode = (current & ~who_mask) | perms;
            break;
    }

    return chmod(path, new_mode);
}

mode_t get_permissions(const char *path) {
    struct stat st;
    if (!path || stat(path, &st) == -1)
        return (mode_t)-1;
    return st.st_mode;
}

void mode_to_string(mode_t mode, char *str) {
    if (!str)
        return;

    // File type
    if (S_ISREG(mode))       str[0] = '-';
    else if (S_ISDIR(mode))  str[0] = 'd';
    else if (S_ISLNK(mode))  str[0] = 'l';
    else if (S_ISBLK(mode))  str[0] = 'b';
    else if (S_ISCHR(mode))  str[0] = 'c';
    else if (S_ISFIFO(mode)) str[0] = 'p';
    else if (S_ISSOCK(mode)) str[0] = 's';
    else                     str[0] = '?';

    // Owner
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? ((mode & S_ISUID) ? 's' : 'x') :
                                ((mode & S_ISUID) ? 'S' : '-');

    // Group
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? ((mode & S_ISGID) ? 's' : 'x') :
                                ((mode & S_ISGID) ? 'S' : '-');

    // Other
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? ((mode & S_ISVTX) ? 't' : 'x') :
                                ((mode & S_ISVTX) ? 'T' : '-');

    str[10] = '\0';
}

int parse_mode_string(const char *str, mode_t *mode) {
    if (!str || !mode)
        return -1;

    // Try octal first
    if (isdigit(str[0])) {
        char *end;
        long val = strtol(str, &end, 8);
        if (*end == '\0' && val >= 0 && val <= 07777) {
            *mode = (mode_t)val;
            return 0;
        }
    }

    // Try symbolic (rwxr-xr-x format)
    if (strlen(str) == 9) {
        mode_t m = 0;
        if (str[0] == 'r') m |= S_IRUSR;
        if (str[1] == 'w') m |= S_IWUSR;
        if (str[2] == 'x' || str[2] == 's') m |= S_IXUSR;
        if (str[2] == 's' || str[2] == 'S') m |= S_ISUID;

        if (str[3] == 'r') m |= S_IRGRP;
        if (str[4] == 'w') m |= S_IWGRP;
        if (str[5] == 'x' || str[5] == 's') m |= S_IXGRP;
        if (str[5] == 's' || str[5] == 'S') m |= S_ISGID;

        if (str[6] == 'r') m |= S_IROTH;
        if (str[7] == 'w') m |= S_IWOTH;
        if (str[8] == 'x' || str[8] == 't') m |= S_IXOTH;
        if (str[8] == 't' || str[8] == 'T') m |= S_ISVTX;

        *mode = m;
        return 0;
    }

    return -1;
}

int set_owner(const char *path, const char *owner) {
    if (!path || !owner)
        return -1;

    struct passwd *pw = getpwnam(owner);
    if (!pw) {
        // Try as UID
        char *end;
        long uid = strtol(owner, &end, 10);
        if (*end != '\0')
            return -1;
        return chown(path, uid, -1);
    }

    return chown(path, pw->pw_uid, -1);
}

int set_group(const char *path, const char *group) {
    if (!path || !group)
        return -1;

    struct group *gr = getgrnam(group);
    if (!gr) {
        char *end;
        long gid = strtol(group, &end, 10);
        if (*end != '\0')
            return -1;
        return chown(path, -1, gid);
    }

    return chown(path, -1, gr->gr_gid);
}

int set_owner_group(const char *path, const char *owner, const char *group) {
    if (!path)
        return -1;

    uid_t uid = -1;
    gid_t gid = -1;

    if (owner) {
        struct passwd *pw = getpwnam(owner);
        uid = pw ? pw->pw_uid : atoi(owner);
    }

    if (group) {
        struct group *gr = getgrnam(group);
        gid = gr ? gr->gr_gid : atoi(group);
    }

    return chown(path, uid, gid);
}

char *get_owner_name(const char *path) {
    struct stat st;
    if (!path || stat(path, &st) == -1)
        return NULL;

    struct passwd *pw = getpwuid(st.st_uid);
    if (pw)
        return strdup(pw->pw_name);

    char buf[32];
    snprintf(buf, sizeof(buf), "%d", st.st_uid);
    return strdup(buf);
}

char *get_group_name(const char *path) {
    struct stat st;
    if (!path || stat(path, &st) == -1)
        return NULL;

    struct group *gr = getgrgid(st.st_gid);
    if (gr)
        return strdup(gr->gr_name);

    char buf[32];
    snprintf(buf, sizeof(buf), "%d", st.st_gid);
    return strdup(buf);
}

int check_access(const char *path, int mode) {
    if (!path)
        return -1;
    return access(path, mode);
}

mode_t get_current_umask(void) {
    mode_t mask = umask(0);
    umask(mask);
    return mask;
}

mode_t set_new_umask(mode_t mask) {
    return umask(mask);
}

mode_t apply_umask(mode_t requested, mode_t mask) {
    return requested & ~mask;
}

int is_root(void) {
    return geteuid() == 0;
}

int has_suid(const char *path) {
    mode_t mode = get_permissions(path);
    return (mode != (mode_t)-1) && (mode & S_ISUID);
}

int has_sgid(const char *path) {
    mode_t mode = get_permissions(path);
    return (mode != (mode_t)-1) && (mode & S_ISGID);
}

int has_sticky(const char *path) {
    mode_t mode = get_permissions(path);
    return (mode != (mode_t)-1) && (mode & S_ISVTX);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de masque octal**

```c
/* Mutant A : Mode incorrect */
int parse_mode_string(const char *str, mode_t *mode) {
    *mode = atoi(str);  // ERREUR: atoi parse en decimal !
    // "755" devient 755 decimal, pas 0755 octal !
    return 0;
}
// Pourquoi c'est faux: 755 decimal = 01363 octal
```

**Mutant B (Safety) : chown sans verification root**

```c
/* Mutant B : Permission denied */
int set_owner(const char *path, const char *owner) {
    struct passwd *pw = getpwnam(owner);
    return chown(path, pw->pw_uid, -1);
    // ERREUR: Seul root peut changer le proprietaire !
    // Pas de gestion de l'erreur EPERM
}
// Pourquoi c'est faux: Echec silencieux pour non-root
```

**Mutant C (Resource) : Memory leak getpwnam**

```c
/* Mutant C : Pas exactement un leak mais... */
char *get_owner_name(const char *path) {
    struct stat st;
    stat(path, &st);
    struct passwd *pw = getpwuid(st.st_uid);
    return pw->pw_name;  // ERREUR: retourne un pointeur static !
}
// Pourquoi c'est faux: pw_name peut etre ecrase par le prochain appel
```

**Mutant D (Logic) : umask inverse**

```c
/* Mutant D : Permissions trop permissives */
mode_t apply_umask(mode_t requested, mode_t mask) {
    return requested | mask;  // ERREUR: OR au lieu de AND NOT !
    // Ajoute des permissions au lieu d'en retirer
}
// Pourquoi c'est faux: umask 022 + 0666 donnerait 0666 au lieu de 0644
```

**Mutant E (Return) : Pas de verification NULL getpwnam**

```c
/* Mutant E : Segfault */
int set_owner(const char *path, const char *owner) {
    struct passwd *pw = getpwnam(owner);
    // ERREUR: pas de check si pw == NULL !
    return chown(path, pw->pw_uid, -1);  // SEGFAULT si user inexistant
}
// Pourquoi c'est faux: getpwnam retourne NULL si l'utilisateur n'existe pas
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| chmod() | Modification des permissions | Fondamental |
| chown() | Changement de proprietaire | Essentiel |
| umask | Masque de creation | Important |
| SUID/SGID | Privileges temporaires | Securite |

---

### 5.2 LDA - Traduction litterale

```
FONCTION set_permissions_symbolic QUI PREND path, mode_str
DEBUT FONCTION
    OBTENIR LES PERMISSIONS ACTUELLES AVEC stat()

    PARSER mode_str POUR EXTRAIRE:
        - who: u (owner), g (group), o (other), a (all)
        - op: + (add), - (remove), = (set)
        - perms: r, w, x

    CALCULER LE NOUVEAU MODE:
        SI op EST '+' ALORS
            new_mode = current | perms
        SINON SI op EST '-' ALORS
            new_mode = current & ~perms
        SINON SI op EST '=' ALORS
            new_mode = (current & ~who_mask) | perms
        FIN SI

    APPELER chmod(path, new_mode)
    RETOURNER LE RESULTAT
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
STRUCTURE DES PERMISSIONS UNIX
==============================

mode_t (16 bits typiquement):
+----+----+----+----+----+----+----+----+----+----+----+----+
|Type| ?? |SUID|SGID|Stky| Ur | Uw | Ux | Gr | Gw | Gx | Or | Ow | Ox |
+----+----+----+----+----+----+----+----+----+----+----+----+
|    file type   |special|   owner   |   group   |   other   |
     (4 bits)    (3 bits)   (3 bits)    (3 bits)    (3 bits)


EXEMPLE: 0755 (rwxr-xr-x)
==========================

     7        5        5
   111      101      101
   rwx      r-x      r-x
  owner    group    other


CHAINE DE PERMISSION ls -l
==========================

-rwxr-xr-x  1  user  group  4096  Jan 1 00:00  file
|_________/
     |
     +-- Type + Permissions

Type:
  - = regular file
  d = directory
  l = symbolic link
  b = block device
  c = character device
  p = named pipe (FIFO)
  s = socket


BITS SPECIAUX
=============

SUID (Set User ID) - 4000:
    Execution avec UID du proprietaire
    Affiche: rws------ (s au lieu de x)
             rwS------ (S si pas de x)

SGID (Set Group ID) - 2000:
    Execution avec GID du groupe
    Sur repertoire: nouveaux fichiers heritent du groupe
    Affiche: ---rws--- ou ---rwS---

Sticky Bit - 1000:
    Sur repertoire: seul owner peut supprimer ses fichiers
    Exemple: /tmp
    Affiche: -------rwt ou -------rwT


UMASK : Masque de creation
==========================

   Demande    umask      Resultat
   ========   =====      ========
   0666       0022       0644
   (rw-rw-rw) (----w--w) (rw-r--r--)

   666 - 022 = 644? Non!
   666 AND NOT(022) = 644

   0666 = 110 110 110
   0022 = 000 010 010
   NOT  = 111 101 101
   AND  = 110 100 100 = 0644


HIERARCHIE DES ACCES
====================

         +-------+
         | root  |  <- Peut tout faire
         +-------+
             |
    +--------+--------+
    |                 |
+-------+         +-------+
| owner |  <---   | group |
+-------+    |    +-------+
    |        |        |
    +--------+--------+
             |
         +-------+
         | other |
         +-------+

Verification d'acces:
1. Si root (UID 0) -> ACCES
2. Si owner du fichier -> Check owner bits
3. Si membre du groupe -> Check group bits
4. Sinon -> Check other bits
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 2 chmod` - Documentation chmod()
- `man 2 chown` - Documentation chown()
- `man 2 access` - Documentation access()
- `man 2 umask` - Documentation umask()

### 6.2 Commandes utiles

```bash
# Voir les permissions
ls -la fichier

# Changer les permissions
chmod 755 fichier
chmod u+x fichier
chmod go-w fichier

# Changer le proprietaire
sudo chown user:group fichier

# Voir le umask
umask

# Trouver les fichiers SUID
find / -perm -4000 2>/dev/null

# Voir les ACL (si disponibles)
getfacl fichier
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Comprendre** le systeme de permissions Unix
2. **Utiliser** chmod() et chown() en C
3. **Parser** les notations octale et symbolique
4. **Gerer** umask pour les creations de fichiers
5. **Auditer** les permissions pour la securite

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.41 filesystem | stat() pour lire les permissions |
| 0.9.45 daemon | Permissions des fichiers de log |
| Security | Audit de permissions, hardening |
