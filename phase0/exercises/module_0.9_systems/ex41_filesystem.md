# Exercice 0.9.41 : filesystem_explorer

**Module :**
0.9 — Systems Programming

**Concept :**
stat(), opendir(), readdir(), directory traversal, file metadata

**Difficulte :**
5/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
C (c17)

**Prerequis :**
- Syntaxe C de base
- Structures et pointeurs
- Notions de systeme de fichiers Unix

**Domaines :**
Filesystem, Unix, Sys

**Duree estimee :**
60 min

**XP Base :**
150

**Complexite :**
T2 O(n) x S2 O(d) (d = profondeur)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `filesystem_explorer.c`, `filesystem_explorer.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `stat`, `lstat`, `fstat`, `opendir`, `readdir`, `closedir`, `open`, `close`, `getcwd`, `chdir`, `mkdir`, `rmdir`, `unlink`, `rename`, `realpath`, `readlink`, `perror`, `printf`, `malloc`, `free`, `strdup` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `system`, `popen`, `nftw`, `ftw` (tu dois implementer le parcours!) |

---

### 1.2 Consigne

#### Section Culture : "Indiana Jones - L'Explorateur de Fichiers"

**INDIANA JONES - "It belongs in a filesystem!"**

Indiana Jones explore des temples anciens a la recherche de reliques. Chaque couloir (directory) mene a d'autres salles ou a des tresors (files). Mais attention aux pieges (permissions) et aux faux chemins (symlinks)!

*"stat() before you leap! Always check if that path is a regular file, a directory, or a deadly trap (dangling symlink)."*

Dr. Jones t'enseigne :
- **La carte** = `readdir()` - liste le contenu d'une salle
- **Le journal** = `stat()` - informations detaillees sur un artefact
- **Le fouet** = parcours recursif - explorer toutes les salles
- **Le chapeau** = `getcwd()` - savoir ou on est
- **Le graal** = le fichier recherche

*"Directories. Why did it have to be directories?"*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un explorateur de systeme de fichiers avec :

1. **get_file_info** : Recupere les metadonnees d'un fichier
2. **list_directory** : Liste le contenu d'un repertoire
3. **walk_directory** : Parcourt recursivement un repertoire
4. **find_files** : Recherche des fichiers par pattern
5. **get_total_size** : Calcule la taille totale d'un repertoire

**Entree (C) :**

```c
#ifndef FILESYSTEM_EXPLORER_H
# define FILESYSTEM_EXPLORER_H

# include <sys/stat.h>
# include <sys/types.h>
# include <dirent.h>
# include <stddef.h>

typedef enum e_file_type {
    FILE_REGULAR,
    FILE_DIRECTORY,
    FILE_SYMLINK,
    FILE_BLOCK,
    FILE_CHAR,
    FILE_FIFO,
    FILE_SOCKET,
    FILE_UNKNOWN
} t_file_type;

typedef struct s_file_info {
    char            *path;          // Chemin complet
    char            *name;          // Nom du fichier
    t_file_type     type;           // Type de fichier
    off_t           size;           // Taille en bytes
    mode_t          mode;           // Permissions (rwxrwxrwx)
    uid_t           uid;            // User ID
    gid_t           gid;            // Group ID
    time_t          atime;          // Dernier acces
    time_t          mtime;          // Derniere modification
    time_t          ctime;          // Dernier changement status
    nlink_t         nlink;          // Nombre de liens
    dev_t           dev;            // Device
    ino_t           inode;          // Numero d'inode
    char            *link_target;   // Cible si symlink
} t_file_info;

typedef struct s_dir_entry {
    t_file_info         info;
    struct s_dir_entry  *next;
} t_dir_entry;

// Callback pour walk_directory
typedef void (*walk_callback)(const char *path, const t_file_info *info, void *data);

// Callback pour find_files (retourne 1 si match, 0 sinon)
typedef int (*match_callback)(const t_file_info *info, void *pattern);

// === FILE INFO FUNCTIONS ===

// Recupere les informations sur un fichier
// follow_symlinks: 1 = stat(), 0 = lstat()
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     get_file_info(const char *path, t_file_info *info, int follow_symlinks);

// Libere la memoire d'une structure file_info
void    free_file_info(t_file_info *info);

// Convertit le type en chaine ("file", "dir", "link", etc.)
const char *file_type_str(t_file_type type);

// Convertit les permissions en chaine "rwxrwxrwx"
void    mode_to_str(mode_t mode, char *str);

// === DIRECTORY FUNCTIONS ===

// Liste le contenu d'un repertoire
// Retourne une liste chainee ou NULL
t_dir_entry *list_directory(const char *path, int include_hidden);

// Libere la liste de dir_entry
void    free_dir_entries(t_dir_entry *entries);

// Compte le nombre d'entrees dans un repertoire
int     count_entries(const char *path, int include_hidden);

// === TRAVERSAL FUNCTIONS ===

// Parcourt un repertoire recursivement
// callback est appele pour chaque fichier/repertoire
// max_depth: -1 = infini, 0 = ce niveau seulement
int     walk_directory(const char *path, walk_callback callback,
                       void *user_data, int max_depth);

// Recherche des fichiers matchant le pattern
// Retourne une liste chainee des fichiers trouves
t_dir_entry *find_files(const char *path, match_callback match,
                        void *pattern, int max_depth);

// === UTILITY FUNCTIONS ===

// Calcule la taille totale d'un repertoire (recursif)
off_t   get_total_size(const char *path);

// Verifie si un chemin existe
int     path_exists(const char *path);

// Verifie si c'est un repertoire
int     is_directory(const char *path);

// Verifie si c'est un fichier regulier
int     is_regular_file(const char *path);

// Retourne le repertoire courant (malloc'd)
char    *get_current_dir(void);

#endif
```

**Sortie :**
- `get_file_info` : 0 succes, -1 erreur
- `list_directory` : liste chainee ou NULL
- `walk_directory` : 0 succes, -1 erreur
- `find_files` : liste chainee ou NULL
- `get_total_size` : taille en bytes ou -1

**Contraintes :**
- Gerer les symlinks (eviter les boucles infinies)
- Ne pas suivre ".." pour eviter de sortir du repertoire racine
- Gerer les erreurs de permission (EACCES)
- Liberer toute la memoire allouee

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `get_file_info("/etc/passwd", &info, 1)` | - | 0 | Info fichier |
| `list_directory("/tmp", 0)` | - | entries* | Sans fichiers caches |
| `walk_directory(".", cb, NULL, -1)` | - | 0 | Parcours recursif complet |
| `get_total_size("/home/user")` | - | 1048576 | Taille en bytes |

---

### 1.3 Prototype

**C :**
```c
#include <sys/stat.h>
#include <dirent.h>

int     get_file_info(const char *path, t_file_info *info, int follow_symlinks);
void    free_file_info(t_file_info *info);
const char *file_type_str(t_file_type type);
void    mode_to_str(mode_t mode, char *str);
t_dir_entry *list_directory(const char *path, int include_hidden);
void    free_dir_entries(t_dir_entry *entries);
int     count_entries(const char *path, int include_hidden);
int     walk_directory(const char *path, walk_callback callback,
                       void *user_data, int max_depth);
t_dir_entry *find_files(const char *path, match_callback match,
                        void *pattern, int max_depth);
off_t   get_total_size(const char *path);
int     path_exists(const char *path);
int     is_directory(const char *path);
int     is_regular_file(const char *path);
char    *get_current_dir(void);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Tout est fichier !**

En Unix, presque tout est represente comme un fichier :
- `/dev/null` - le trou noir
- `/dev/random` - generateur aleatoire
- `/proc/cpuinfo` - informations CPU (pas un vrai fichier!)

**Les inodes**

Chaque fichier a un numero d'inode unique. Le "nom" n'est qu'un lien vers cet inode. C'est pourquoi on peut avoir plusieurs noms pour le meme fichier (hard links).

**stat() vs lstat()**

- `stat()` suit les liens symboliques
- `lstat()` ne les suit pas (donne les infos du lien lui-meme)

Oublier cette difference peut causer des boucles infinies ou des bugs de securite!

**Le point et double-point**

"." et ".." ne sont pas des conventions, ce sont de vrais hard links dans chaque repertoire. C'est pourquoi `rmdir` ne peut pas supprimer un repertoire non vide.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps Engineer** | Scripts de deploiement, nettoyage |
| **Security Analyst** | Audit de fichiers, detection d'intrusion |
| **Backup Developer** | Logiciels de sauvegarde (rsync, tar) |
| **File Manager Dev** | Nautilus, Finder, Explorer |
| **Antivirus Dev** | Scan de fichiers |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "filesystem_explorer.h"
#include <stdio.h>
#include <string.h>

void print_file(const char *path, const t_file_info *info, void *data) {
    (void)data;
    char mode_str[10];
    mode_to_str(info->mode, mode_str);

    printf("%s %8ld %s %s\n",
           mode_str,
           (long)info->size,
           file_type_str(info->type),
           path);
}

int match_c_files(const t_file_info *info, void *pattern) {
    (void)pattern;
    const char *ext = strrchr(info->name, '.');
    return ext && strcmp(ext, ".c") == 0;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : ".";

    printf("=== File Info ===\n");
    t_file_info info;
    if (get_file_info(path, &info, 1) == 0) {
        char mode_str[10];
        mode_to_str(info.mode, mode_str);
        printf("Path: %s\n", info.path);
        printf("Type: %s\n", file_type_str(info.type));
        printf("Size: %ld bytes\n", (long)info.size);
        printf("Mode: %s\n", mode_str);
        printf("Inode: %lu\n", (unsigned long)info.inode);
        free_file_info(&info);
    }

    printf("\n=== Directory Listing ===\n");
    t_dir_entry *entries = list_directory(path, 0);
    for (t_dir_entry *e = entries; e; e = e->next) {
        printf("  %s (%s)\n", e->info.name, file_type_str(e->info.type));
    }
    free_dir_entries(entries);

    printf("\n=== Recursive Walk ===\n");
    walk_directory(path, print_file, NULL, 2);

    printf("\n=== Find .c files ===\n");
    t_dir_entry *c_files = find_files(path, match_c_files, NULL, -1);
    for (t_dir_entry *e = c_files; e; e = e->next) {
        printf("  Found: %s\n", e->info.path);
    }
    free_dir_entries(c_files);

    printf("\n=== Total Size ===\n");
    off_t total = get_total_size(path);
    printf("Total: %ld bytes\n", (long)total);

    return 0;
}

$ gcc -Wall -Wextra filesystem_explorer.c main.c -o explorer
$ ./explorer /home/user/project
=== File Info ===
Path: /home/user/project
Type: dir
Size: 4096 bytes
Mode: rwxr-xr-x
Inode: 12345

=== Directory Listing ===
  src (dir)
  Makefile (file)
  README.md (file)

=== Recursive Walk ===
rwxr-xr-x     4096 dir  /home/user/project
rwxr-xr-x     4096 dir  /home/user/project/src
rw-r--r--     2048 file /home/user/project/src/main.c
rw-r--r--      512 file /home/user/project/Makefile
rw-r--r--     1024 file /home/user/project/README.md

=== Find .c files ===
  Found: /home/user/project/src/main.c

=== Total Size ===
Total: 7680 bytes
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un mini-`find` avec options avancees :

```c
typedef struct s_find_options {
    char        *name_pattern;      // -name "*.c"
    t_file_type type;               // -type f/d/l
    off_t       min_size;           // -size +100k
    off_t       max_size;           // -size -1M
    time_t      newer_than;         // -newer file
    time_t      older_than;         // -mtime +7
    uid_t       owner;              // -user
    gid_t       group;              // -group
    int         max_depth;          // -maxdepth
    int         min_depth;          // -mindepth
} t_find_options;

// Recherche avancee
t_dir_entry *advanced_find(const char *path, const t_find_options *opts);

// Exemple: trouver les fichiers .c de plus de 1KB modifies dans les 7 jours
t_find_options opts = {
    .name_pattern = "*.c",
    .type = FILE_REGULAR,
    .min_size = 1024,
    .older_than = time(NULL) - 7*24*3600
};
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | get_file_info | regular file | correct info | 10 | Basic |
| 2 | get_dir_info | directory | type=DIR | 10 | Basic |
| 3 | symlink_stat | lstat symlink | type=LINK | 10 | Symlink |
| 4 | list_directory | /tmp | entries | 10 | List |
| 5 | hidden_files | include_hidden=1 | .* files | 5 | List |
| 6 | walk_recursive | depth=2 | all visited | 15 | Walk |
| 7 | find_files | *.c pattern | matches | 10 | Find |
| 8 | total_size | calculate | correct | 10 | Size |
| 9 | permission_error | no access | handle EACCES | 10 | Error |
| 10 | memory_cleanup | all ops | no leaks | 10 | Memory |

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
#include "filesystem_explorer.h"

void test_get_file_info(void) {
    t_file_info info;

    // Test regular file
    int fd = open("/tmp/test_fs_explorer.txt", O_CREAT | O_WRONLY, 0644);
    write(fd, "Hello", 5);
    close(fd);

    assert(get_file_info("/tmp/test_fs_explorer.txt", &info, 1) == 0);
    assert(info.type == FILE_REGULAR);
    assert(info.size == 5);
    assert((info.mode & 0777) == 0644);
    free_file_info(&info);

    unlink("/tmp/test_fs_explorer.txt");
    printf("Test get_file_info: OK\n");
}

void test_get_dir_info(void) {
    t_file_info info;

    assert(get_file_info("/tmp", &info, 1) == 0);
    assert(info.type == FILE_DIRECTORY);
    free_file_info(&info);

    printf("Test get_dir_info: OK\n");
}

void test_symlink(void) {
    // Create symlink
    symlink("/etc/passwd", "/tmp/test_link");

    t_file_info info;

    // lstat should see the link
    assert(get_file_info("/tmp/test_link", &info, 0) == 0);
    assert(info.type == FILE_SYMLINK);
    assert(info.link_target != NULL);
    free_file_info(&info);

    // stat should see the target
    assert(get_file_info("/tmp/test_link", &info, 1) == 0);
    assert(info.type == FILE_REGULAR);
    free_file_info(&info);

    unlink("/tmp/test_link");
    printf("Test symlink: OK\n");
}

void test_list_directory(void) {
    t_dir_entry *entries = list_directory("/tmp", 0);
    assert(entries != NULL || count_entries("/tmp", 0) == 0);

    int count = 0;
    for (t_dir_entry *e = entries; e; e = e->next)
        count++;

    assert(count == count_entries("/tmp", 0));
    free_dir_entries(entries);

    printf("Test list_directory: OK\n");
}

void test_mode_to_str(void) {
    char str[10];

    mode_to_str(0755, str);
    assert(strcmp(str, "rwxr-xr-x") == 0);

    mode_to_str(0644, str);
    assert(strcmp(str, "rw-r--r--") == 0);

    mode_to_str(0000, str);
    assert(strcmp(str, "---------") == 0);

    printf("Test mode_to_str: OK\n");
}

void test_path_exists(void) {
    assert(path_exists("/tmp") == 1);
    assert(path_exists("/nonexistent_path_12345") == 0);
    assert(is_directory("/tmp") == 1);
    assert(is_directory("/etc/passwd") == 0);

    printf("Test path_exists: OK\n");
}

int main(void) {
    test_get_file_info();
    test_get_dir_info();
    test_symlink();
    test_list_directory();
    test_mode_to_str();
    test_path_exists();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "filesystem_explorer.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static t_file_type get_type_from_mode(mode_t mode) {
    if (S_ISREG(mode))  return FILE_REGULAR;
    if (S_ISDIR(mode))  return FILE_DIRECTORY;
    if (S_ISLNK(mode))  return FILE_SYMLINK;
    if (S_ISBLK(mode))  return FILE_BLOCK;
    if (S_ISCHR(mode))  return FILE_CHAR;
    if (S_ISFIFO(mode)) return FILE_FIFO;
    if (S_ISSOCK(mode)) return FILE_SOCKET;
    return FILE_UNKNOWN;
}

int get_file_info(const char *path, t_file_info *info, int follow_symlinks) {
    if (!path || !info)
        return -1;

    memset(info, 0, sizeof(t_file_info));

    struct stat st;
    int ret = follow_symlinks ? stat(path, &st) : lstat(path, &st);
    if (ret == -1)
        return -1;

    info->path = realpath(path, NULL);
    if (!info->path)
        info->path = strdup(path);

    const char *slash = strrchr(path, '/');
    info->name = strdup(slash ? slash + 1 : path);

    info->type = get_type_from_mode(st.st_mode);
    info->size = st.st_size;
    info->mode = st.st_mode & 0777;
    info->uid = st.st_uid;
    info->gid = st.st_gid;
    info->atime = st.st_atime;
    info->mtime = st.st_mtime;
    info->ctime = st.st_ctime;
    info->nlink = st.st_nlink;
    info->dev = st.st_dev;
    info->inode = st.st_ino;

    // Get symlink target if applicable
    if (info->type == FILE_SYMLINK || (!follow_symlinks && S_ISLNK(st.st_mode))) {
        char target[PATH_MAX];
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            info->link_target = strdup(target);
        }
    }

    return 0;
}

void free_file_info(t_file_info *info) {
    if (!info)
        return;
    free(info->path);
    free(info->name);
    free(info->link_target);
    memset(info, 0, sizeof(t_file_info));
}

const char *file_type_str(t_file_type type) {
    static const char *types[] = {
        "file", "dir", "link", "block", "char", "fifo", "socket", "unknown"
    };
    return types[type < FILE_UNKNOWN ? type : FILE_UNKNOWN];
}

void mode_to_str(mode_t mode, char *str) {
    str[0] = (mode & S_IRUSR) ? 'r' : '-';
    str[1] = (mode & S_IWUSR) ? 'w' : '-';
    str[2] = (mode & S_IXUSR) ? 'x' : '-';
    str[3] = (mode & S_IRGRP) ? 'r' : '-';
    str[4] = (mode & S_IWGRP) ? 'w' : '-';
    str[5] = (mode & S_IXGRP) ? 'x' : '-';
    str[6] = (mode & S_IROTH) ? 'r' : '-';
    str[7] = (mode & S_IWOTH) ? 'w' : '-';
    str[8] = (mode & S_IXOTH) ? 'x' : '-';
    str[9] = '\0';
}

t_dir_entry *list_directory(const char *path, int include_hidden) {
    DIR *dir = opendir(path);
    if (!dir)
        return NULL;

    t_dir_entry *head = NULL;
    t_dir_entry *tail = NULL;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Skip hidden files if not requested
        if (!include_hidden && entry->d_name[0] == '.')
            continue;

        t_dir_entry *node = malloc(sizeof(t_dir_entry));
        if (!node)
            continue;

        // Build full path
        size_t path_len = strlen(path) + strlen(entry->d_name) + 2;
        char *full_path = malloc(path_len);
        if (full_path) {
            snprintf(full_path, path_len, "%s/%s", path, entry->d_name);
            get_file_info(full_path, &node->info, 1);
            free(full_path);
        }

        node->next = NULL;

        if (!head) {
            head = tail = node;
        } else {
            tail->next = node;
            tail = node;
        }
    }

    closedir(dir);
    return head;
}

void free_dir_entries(t_dir_entry *entries) {
    while (entries) {
        t_dir_entry *next = entries->next;
        free_file_info(&entries->info);
        free(entries);
        entries = next;
    }
}

int count_entries(const char *path, int include_hidden) {
    DIR *dir = opendir(path);
    if (!dir)
        return -1;

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!include_hidden && entry->d_name[0] == '.')
            continue;
        count++;
    }

    closedir(dir);
    return count;
}

static int walk_recursive(const char *path, walk_callback callback,
                         void *user_data, int max_depth, int current_depth) {
    t_file_info info;
    if (get_file_info(path, &info, 0) == -1)
        return -1;

    callback(path, &info, user_data);

    if (info.type == FILE_DIRECTORY && (max_depth < 0 || current_depth < max_depth)) {
        DIR *dir = opendir(path);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0)
                    continue;

                size_t len = strlen(path) + strlen(entry->d_name) + 2;
                char *child_path = malloc(len);
                if (child_path) {
                    snprintf(child_path, len, "%s/%s", path, entry->d_name);
                    walk_recursive(child_path, callback, user_data,
                                  max_depth, current_depth + 1);
                    free(child_path);
                }
            }
            closedir(dir);
        }
    }

    free_file_info(&info);
    return 0;
}

int walk_directory(const char *path, walk_callback callback,
                   void *user_data, int max_depth) {
    if (!path || !callback)
        return -1;
    return walk_recursive(path, callback, user_data, max_depth, 0);
}

// Helper for find_files
typedef struct {
    match_callback match;
    void *pattern;
    t_dir_entry **head;
    t_dir_entry **tail;
} find_context;

static void find_callback(const char *path, const t_file_info *info, void *data) {
    find_context *ctx = data;

    if (ctx->match(info, ctx->pattern)) {
        t_dir_entry *node = malloc(sizeof(t_dir_entry));
        if (!node)
            return;

        get_file_info(path, &node->info, 1);
        node->next = NULL;

        if (!*ctx->head) {
            *ctx->head = *ctx->tail = node;
        } else {
            (*ctx->tail)->next = node;
            *ctx->tail = node;
        }
    }
}

t_dir_entry *find_files(const char *path, match_callback match,
                        void *pattern, int max_depth) {
    if (!path || !match)
        return NULL;

    t_dir_entry *head = NULL;
    t_dir_entry *tail = NULL;

    find_context ctx = { match, pattern, &head, &tail };
    walk_directory(path, find_callback, &ctx, max_depth);

    return head;
}

// Helper for get_total_size
static void size_callback(const char *path, const t_file_info *info, void *data) {
    (void)path;
    if (info->type == FILE_REGULAR) {
        *(off_t*)data += info->size;
    }
}

off_t get_total_size(const char *path) {
    off_t total = 0;
    walk_directory(path, size_callback, &total, -1);
    return total;
}

int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int is_regular_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

char *get_current_dir(void) {
    char *buf = malloc(PATH_MAX);
    if (!buf)
        return NULL;
    if (!getcwd(buf, PATH_MAX)) {
        free(buf);
        return NULL;
    }
    return buf;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de skip . et ..**

```c
/* Mutant A : Boucle infinie */
t_dir_entry *list_directory(const char *path, int include_hidden) {
    DIR *dir = opendir(path);
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        // ERREUR: pas de skip "." et ".." !
        // walk_recursive sur "." cree une boucle infinie
        add_entry(entry->d_name);
    }
    ...
}
// Pourquoi c'est faux: "." pointe vers le repertoire courant = recursion infinie
```

**Mutant B (Safety) : stat au lieu de lstat pour symlinks**

```c
/* Mutant B : Symlink loop */
int walk_recursive(...) {
    struct stat st;
    stat(path, &st);  // ERREUR: suit les symlinks !

    if (S_ISDIR(st.st_mode)) {
        // Si path est un symlink vers "..", boucle infinie !
        // Si symlink vers lui-meme, crash
        walk_recursive(path, ...);
    }
}
// Pourquoi c'est faux: Les symlinks peuvent creer des boucles
```

**Mutant C (Resource) : Memory leak**

```c
/* Mutant C : Fuite memoire */
t_dir_entry *list_directory(const char *path, int include_hidden) {
    t_dir_entry *head = NULL;

    while ((entry = readdir(dir)) != NULL) {
        t_dir_entry *node = malloc(sizeof(t_dir_entry));
        node->info.path = strdup(path);  // Jamais libere !
        node->info.name = strdup(entry->d_name);  // Jamais libere !
        ...
    }
    return head;
}
// Pourquoi c'est faux: Chaque chaine dupliquee fuit en memoire
```

**Mutant D (Logic) : Pas de closedir**

```c
/* Mutant D : File descriptor leak */
int walk_recursive(const char *path, ...) {
    DIR *dir = opendir(path);

    while ((entry = readdir(dir)) != NULL) {
        if (S_ISDIR(...)) {
            walk_recursive(child_path, ...);  // Recursion
            // ERREUR: closedir jamais appele si recursion !
        }
    }
    // closedir(dir);  // Jamais atteint si return early
}
// Pourquoi c'est faux: Limite de FD ouverts atteinte rapidement
```

**Mutant E (Return) : Ignore les erreurs opendir**

```c
/* Mutant E : Segfault */
t_dir_entry *list_directory(const char *path, int include_hidden) {
    DIR *dir = opendir(path);
    // ERREUR: pas de check NULL !

    while ((entry = readdir(dir)) != NULL) {  // SEGFAULT si dir==NULL !
        ...
    }
}
// Pourquoi c'est faux: opendir peut echouer (permission, inexistant)
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| stat() | Metadonnees de fichiers | Fondamental |
| opendir/readdir | Parcours de repertoires | Essentiel |
| lstat() | Gestion des symlinks | Important |
| Recursion | Parcours d'arbres | Classique |

---

### 5.2 LDA - Traduction litterale

```
FONCTION walk_directory QUI PREND path, callback, data, max_depth
DEBUT FONCTION
    OBTENIR LES INFOS DU FICHIER AVEC lstat (pas stat!)
    APPELER callback(path, info, data)

    SI LE FICHIER EST UN REPERTOIRE ET profondeur OK ALORS
        OUVRIR LE REPERTOIRE AVEC opendir
        POUR CHAQUE ENTREE FAIRE
            SI entree EST "." OU ".." ALORS
                CONTINUER
            FIN SI

            CONSTRUIRE LE CHEMIN COMPLET (path + "/" + nom)
            APPELER walk_directory RECURSIVEMENT AVEC profondeur + 1
        FIN POUR
        FERMER LE REPERTOIRE AVEC closedir
    FIN SI

    LIBERER LA MEMOIRE
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
STRUCTURE DU SYSTEME DE FICHIERS
================================

Filesystem:
    /
    +-- home/
    |   +-- user/
    |       +-- .bashrc          (hidden file)
    |       +-- Documents/
    |       |   +-- report.pdf
    |       |   +-- notes.txt
    |       +-- link -> /tmp     (symlink)
    +-- tmp/
        +-- temp.txt

Inodes:
+--------+     +--------+     +--------+
| inode 1|     | inode 2|     | inode 3|
|  /     |---->| home   |---->| user   |
+--------+     +--------+     +--------+
                                  |
                                  v
                              +--------+
                              |Documents|
                              +--------+


STRUCTURE STAT
==============

struct stat {
    dev_t     st_dev;     // Device
    ino_t     st_ino;     // Inode number
    mode_t    st_mode;    // File type & permissions
    nlink_t   st_nlink;   // Number of hard links
    uid_t     st_uid;     // User ID
    gid_t     st_gid;     // Group ID
    off_t     st_size;    // Size in bytes
    time_t    st_atime;   // Last access
    time_t    st_mtime;   // Last modification
    time_t    st_ctime;   // Last status change
};

st_mode breakdown:
+----+----+----+----+----+----+----+----+----+----+----+----+
|type|  ? |suid|sgid|stky| r  | w  | x  | r  | w  | x  | r  | w  | x  |
+----+----+----+----+----+----+----+----+----+----+----+----+
|     file type     |    user   |   group   |   other   |
     (4 bits)           (3 bits)    (3 bits)    (3 bits)


stat() vs lstat()
=================

      stat("/path/link")              lstat("/path/link")
            |                               |
            v                               v
      +----------+                    +----------+
      |  link    |--follows-->        |  link    | (stops here)
      +----------+                    +----------+
            |
            v
      +----------+
      |  target  |
      +----------+

stat() returns info about target
lstat() returns info about link itself


DIRECTORY TRAVERSAL
===================

opendir("/home/user")
       |
       v
   +--------+
   | DIR*   |---> internal position
   +--------+

readdir(dir) loop:
   Call 1: returns "."
   Call 2: returns ".."
   Call 3: returns "Documents"
   Call 4: returns ".bashrc"
   Call 5: returns "link"
   Call 6: returns NULL (end)

closedir(dir) <- IMPORTANT!


RECURSIVE WALK VISUALIZATION
============================

walk_directory("/home/user", ..., depth=2)
  |
  +-- callback("/home/user", ...)
  |
  +-- opendir("/home/user")
      |
      +-- walk_directory("/home/user/Documents", ..., depth=1)
      |     |
      |     +-- callback("/home/user/Documents", ...)
      |     |
      |     +-- walk_directory(".../report.pdf", ..., depth=0)
      |     |     +-- callback(".../report.pdf", ...)
      |     |     +-- (not a directory, no recursion)
      |     |
      |     +-- walk_directory(".../notes.txt", ..., depth=0)
      |           +-- callback(".../notes.txt", ...)
      |
      +-- callback("/home/user/.bashrc", ...)
      |
      +-- callback("/home/user/link", ...)
      |     +-- (symlink, use lstat to avoid loop!)
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 2 stat` - Documentation stat()
- `man 3 readdir` - Documentation readdir()
- `man 7 inode` - Comprendre les inodes
- "Advanced Programming in the UNIX Environment" - Stevens

### 6.2 Commandes utiles

```bash
# Voir les infos d'un fichier
stat /etc/passwd

# Voir l'inode
ls -i /etc/passwd

# Trouver des fichiers
find /home -name "*.c" -type f

# Voir la structure
tree /home/user

# Taille d'un repertoire
du -sh /home/user
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Utiliser** stat()/lstat() pour obtenir les metadonnees
2. **Parcourir** des repertoires avec opendir/readdir
3. **Implementer** un parcours recursif d'arbre
4. **Gerer** les symlinks correctement
5. **Eviter** les fuites memoire et de file descriptors

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.42 permissions | chmod/chown sur les fichiers |
| Shell (minishell) | Commandes ls, find, cd |
| Backup tools | rsync, tar |
