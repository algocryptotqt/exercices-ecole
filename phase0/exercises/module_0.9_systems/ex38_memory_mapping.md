# Exercice 0.9.38 : memory_mapper

**Module :**
0.9 — Systems Programming

**Concept :**
mmap(), munmap(), shared memory, memory-mapped files

**Difficulte :**
6/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
C (c17)

**Prerequis :**
- Syntaxe C de base
- Notion de memoire virtuelle
- File descriptors
- Processus et fork()

**Domaines :**
Memory, Unix, Sys, IPC

**Duree estimee :**
75 min

**XP Base :**
175

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `memory_mapper.c`, `memory_mapper.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `mmap`, `munmap`, `msync`, `mprotect`, `shm_open`, `shm_unlink`, `ftruncate`, `open`, `close`, `fstat`, `fork`, `wait`, `perror`, `printf`, `write` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `malloc`, `calloc`, `realloc` pour les buffers principaux (utiliser mmap!) |

---

### 1.2 Consigne

#### Section Culture : "The Matrix - La Memoire Partagee"

**THE MATRIX - "There is no spoon, only mapped memory"**

Dans la Matrice, Neo decouvre que la realite n'est qu'une simulation - un espace memoire partage entre tous les humains connectes. Quand il plie une cuillere, tous les autres voient le changement instantanement car ils partagent la meme region memoire.

*"I can only show you the door to shared memory. You're the one that has to mmap() through it."*

Morpheus t'explique :

*"Les Agents peuvent modifier la Matrice car ils ont un acces mmap avec PROT_WRITE. Les humains normaux sont limites a PROT_READ. Mais toi, Neo, tu vas apprendre a manipuler directement cette memoire partagee."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un ensemble de fonctions pour la gestion de memoire mappee :

1. **map_file** : Mappe un fichier en memoire
2. **map_anonymous** : Cree une region memoire anonyme
3. **create_shared_region** : Cree une region de memoire partagee nommee
4. **attach_shared_region** : S'attache a une region partagee existante
5. **sync_mapping** : Synchronise les modifications avec le stockage

**Entree (C) :**

```c
#ifndef MEMORY_MAPPER_H
# define MEMORY_MAPPER_H

# include <stddef.h>
# include <sys/types.h>

typedef struct s_mapping {
    void    *addr;          // Adresse de la zone mappee
    size_t  size;           // Taille de la zone
    int     fd;             // File descriptor associe (-1 si anonyme)
    int     flags;          // Flags utilises pour mmap
    int     prot;           // Protections (PROT_READ, PROT_WRITE, etc.)
    char    *name;          // Nom de la region partagee (NULL si anonyme/fichier)
} t_mapping;

// Mappe un fichier en memoire (lecture seule ou lecture/ecriture)
// Retourne un pointeur vers la structure mapping ou NULL en cas d'erreur
t_mapping   *map_file(const char *filepath, int writable);

// Cree une region memoire anonyme de la taille specifiee
// Si shared=1, la region sera partagee entre processus forkes
t_mapping   *map_anonymous(size_t size, int shared);

// Cree une nouvelle region de memoire partagee nommee
// La region peut etre accedee par d'autres processus via son nom
t_mapping   *create_shared_region(const char *name, size_t size);

// S'attache a une region partagee existante par son nom
t_mapping   *attach_shared_region(const char *name, int writable);

// Synchronise les modifications avec le fichier/stockage sous-jacent
// flags: MS_SYNC (synchrone) ou MS_ASYNC (asynchrone)
int         sync_mapping(t_mapping *mapping, int flags);

// Change les protections d'une region mappee
int         protect_mapping(t_mapping *mapping, int prot);

// Libere une region mappee
int         unmap(t_mapping *mapping);

// Detruit une region partagee nommee (shm_unlink)
int         destroy_shared_region(const char *name);

#endif
```

**Sortie :**
- `map_file` : Pointeur vers t_mapping ou NULL
- `map_anonymous` : Pointeur vers t_mapping ou NULL
- `create_shared_region` : Pointeur vers t_mapping ou NULL
- `attach_shared_region` : Pointeur vers t_mapping ou NULL
- `sync_mapping` : 0 succes, -1 erreur
- `protect_mapping` : 0 succes, -1 erreur
- `unmap` : 0 succes, -1 erreur

**Contraintes :**
- Toujours verifier la validite des pointeurs
- Gerer correctement les erreurs de mmap (MAP_FAILED)
- Fermer les file descriptors quand necessaire
- Respecter l'alignement sur PAGE_SIZE

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `map_file("/etc/passwd", 0)` | - | t_mapping* | Fichier mappe en lecture |
| `map_anonymous(4096, 1)` | - | t_mapping* | 1 page partagee |
| `create_shared_region("/matrix", 8192)` | - | t_mapping* | SHM cree |
| `attach_shared_region("/matrix", 1)` | - | t_mapping* | Acces R/W |
| `unmap(mapping)` | - | 0 | Liberation propre |

---

### 1.3 Prototype

**C :**
```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

t_mapping   *map_file(const char *filepath, int writable);
t_mapping   *map_anonymous(size_t size, int shared);
t_mapping   *create_shared_region(const char *name, size_t size);
t_mapping   *attach_shared_region(const char *name, int writable);
int         sync_mapping(t_mapping *mapping, int flags);
int         protect_mapping(t_mapping *mapping, int prot);
int         unmap(t_mapping *mapping);
int         destroy_shared_region(const char *name);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**mmap() est partout !**

Quasiment tous les programmes modernes utilisent mmap() sans que vous le sachiez :

- Les executables sont mappes en memoire (pas copies !)
- Les bibliotheques partagees (.so) utilisent mmap()
- malloc() utilise mmap() pour les grosses allocations
- Les bases de donnees (SQLite, PostgreSQL) mappent leurs fichiers

**Copy-on-Write magic**

Quand fork() duplique un processus, les pages memoire ne sont pas vraiment copiees. Elles sont marquees "copy-on-write". Ce n'est que si un processus modifie une page qu'elle est copiee.

**Page fault = pas toujours une erreur**

Un "page fault" n'est pas forcement une erreur. C'est ainsi que le kernel charge les pages a la demande. mmap() ne charge pas le fichier - il configure juste la memoire virtuelle.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Database Developer** | Mapping des fichiers de donnees pour acces rapide |
| **Game Developer** | Chargement rapide des assets, textures |
| **Embedded Developer** | Acces direct aux registres hardware |
| **Security Researcher** | Analyse de binaires, injection memoire |
| **Kernel Developer** | Implementation de systemes de fichiers |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "memory_mapper.h"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    // Test 1: Map a file
    t_mapping *file_map = map_file("test.txt", 0);
    if (file_map) {
        printf("File content: %.50s...\n", (char*)file_map->addr);
        unmap(file_map);
    }

    // Test 2: Shared memory between parent and child
    t_mapping *shared = create_shared_region("/test_shm", 4096);
    if (!shared) {
        perror("create_shared_region");
        return 1;
    }

    strcpy(shared->addr, "Initial message");

    pid_t pid = fork();
    if (pid == 0) {
        // Child: modify shared memory
        sleep(1);
        strcpy(shared->addr, "Modified by child!");
        unmap(shared);
        return 0;
    }

    // Parent: read after child modifies
    sleep(2);
    printf("Parent reads: %s\n", (char*)shared->addr);

    wait(NULL);
    unmap(shared);
    destroy_shared_region("/test_shm");

    return 0;
}

$ echo "Hello, this is a test file for memory mapping!" > test.txt
$ gcc -Wall -Wextra -Werror memory_mapper.c main.c -o test -lrt
$ ./test
File content: Hello, this is a test file for memory mapping!...
Parent reads: Modified by child!
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un systeme de ring buffer partage entre processus :

```c
typedef struct s_ring_buffer {
    t_mapping   *mapping;
    size_t      capacity;
    size_t      *head;      // Pointeur dans la zone partagee
    size_t      *tail;      // Pointeur dans la zone partagee
    char        *data;      // Zone de donnees
} t_ring_buffer;

// Cree un ring buffer partage
t_ring_buffer *create_ring_buffer(const char *name, size_t capacity);

// Ecrit des donnees dans le buffer (bloquant si plein)
ssize_t ring_write(t_ring_buffer *rb, const void *data, size_t len);

// Lit des donnees du buffer (bloquant si vide)
ssize_t ring_read(t_ring_buffer *rb, void *data, size_t len);

// Libere le ring buffer
void destroy_ring_buffer(t_ring_buffer *rb);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | map_file_read | map_file("test.txt", 0) | valid mapping | 10 | Basic |
| 2 | map_file_write | map_file + write + sync | file modified | 10 | Basic |
| 3 | map_anon_private | map_anonymous(4096, 0) | valid, private | 10 | Anonymous |
| 4 | map_anon_shared | map_anonymous + fork | changes visible | 15 | Shared |
| 5 | create_shm | create_shared_region("/x", 4096) | valid shm | 10 | SHM |
| 6 | attach_shm | attach after create | same data | 10 | SHM |
| 7 | cross_process | 2 processes share | communication | 15 | IPC |
| 8 | protect_rdonly | protect PROT_READ then write | SIGSEGV | 5 | Protection |
| 9 | unmap_cleanup | unmap all | no leaks | 5 | Cleanup |
| 10 | error_handling | invalid path | NULL + errno | 10 | Error |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "memory_mapper.h"

void test_map_file(void) {
    // Create test file
    FILE *f = fopen("/tmp/mmap_test.txt", "w");
    fprintf(f, "Test content for mmap");
    fclose(f);

    t_mapping *m = map_file("/tmp/mmap_test.txt", 0);
    assert(m != NULL);
    assert(m->addr != NULL);
    assert(strncmp(m->addr, "Test content", 12) == 0);
    assert(unmap(m) == 0);

    unlink("/tmp/mmap_test.txt");
    printf("Test map_file: OK\n");
}

void test_anonymous_private(void) {
    t_mapping *m = map_anonymous(4096, 0);
    assert(m != NULL);
    assert(m->addr != NULL);

    strcpy(m->addr, "Private data");

    pid_t pid = fork();
    if (pid == 0) {
        // Child modifies
        strcpy(m->addr, "Modified");
        unmap(m);
        exit(0);
    }

    wait(NULL);
    // Parent should still see original (private mapping)
    assert(strcmp(m->addr, "Private data") == 0);
    unmap(m);
    printf("Test anonymous_private: OK\n");
}

void test_anonymous_shared(void) {
    t_mapping *m = map_anonymous(4096, 1);
    assert(m != NULL);

    strcpy(m->addr, "Shared data");

    pid_t pid = fork();
    if (pid == 0) {
        sleep(1);
        strcpy(m->addr, "Modified by child");
        unmap(m);
        exit(0);
    }

    sleep(2);
    // Parent should see child's modification (shared mapping)
    assert(strcmp(m->addr, "Modified by child") == 0);
    wait(NULL);
    unmap(m);
    printf("Test anonymous_shared: OK\n");
}

void test_shared_region(void) {
    const char *name = "/test_shm_region";

    t_mapping *m1 = create_shared_region(name, 4096);
    assert(m1 != NULL);

    strcpy(m1->addr, "Hello SHM");

    t_mapping *m2 = attach_shared_region(name, 0);
    assert(m2 != NULL);
    assert(strcmp(m2->addr, "Hello SHM") == 0);

    unmap(m2);
    unmap(m1);
    destroy_shared_region(name);
    printf("Test shared_region: OK\n");
}

int main(void) {
    test_map_file();
    test_anonymous_private();
    test_anonymous_shared();
    test_shared_region();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "memory_mapper.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static t_mapping *create_mapping_struct(void) {
    t_mapping *m = mmap(NULL, sizeof(t_mapping),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        return NULL;
    memset(m, 0, sizeof(t_mapping));
    m->fd = -1;
    return m;
}

t_mapping *map_file(const char *filepath, int writable) {
    if (!filepath)
        return NULL;

    int flags = writable ? O_RDWR : O_RDONLY;
    int fd = open(filepath, flags);
    if (fd == -1)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return NULL;
    }

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    int mflags = writable ? MAP_SHARED : MAP_PRIVATE;

    void *addr = mmap(NULL, st.st_size, prot, mflags, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    t_mapping *m = create_mapping_struct();
    if (!m) {
        munmap(addr, st.st_size);
        close(fd);
        return NULL;
    }

    m->addr = addr;
    m->size = st.st_size;
    m->fd = fd;
    m->flags = mflags;
    m->prot = prot;

    return m;
}

t_mapping *map_anonymous(size_t size, int shared) {
    if (size == 0)
        return NULL;

    int flags = MAP_ANONYMOUS | (shared ? MAP_SHARED : MAP_PRIVATE);
    int prot = PROT_READ | PROT_WRITE;

    void *addr = mmap(NULL, size, prot, flags, -1, 0);
    if (addr == MAP_FAILED)
        return NULL;

    t_mapping *m = create_mapping_struct();
    if (!m) {
        munmap(addr, size);
        return NULL;
    }

    m->addr = addr;
    m->size = size;
    m->flags = flags;
    m->prot = prot;

    return m;
}

t_mapping *create_shared_region(const char *name, size_t size) {
    if (!name || size == 0)
        return NULL;

    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd == -1)
        return NULL;

    if (ftruncate(fd, size) == -1) {
        close(fd);
        shm_unlink(name);
        return NULL;
    }

    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        shm_unlink(name);
        return NULL;
    }

    t_mapping *m = create_mapping_struct();
    if (!m) {
        munmap(addr, size);
        close(fd);
        shm_unlink(name);
        return NULL;
    }

    m->addr = addr;
    m->size = size;
    m->fd = fd;
    m->flags = MAP_SHARED;
    m->prot = PROT_READ | PROT_WRITE;
    m->name = strdup(name);

    return m;
}

t_mapping *attach_shared_region(const char *name, int writable) {
    if (!name)
        return NULL;

    int flags = writable ? O_RDWR : O_RDONLY;
    int fd = shm_open(name, flags, 0);
    if (fd == -1)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return NULL;
    }

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    void *addr = mmap(NULL, st.st_size, prot, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    t_mapping *m = create_mapping_struct();
    if (!m) {
        munmap(addr, st.st_size);
        close(fd);
        return NULL;
    }

    m->addr = addr;
    m->size = st.st_size;
    m->fd = fd;
    m->flags = MAP_SHARED;
    m->prot = prot;
    m->name = strdup(name);

    return m;
}

int sync_mapping(t_mapping *mapping, int flags) {
    if (!mapping || !mapping->addr)
        return -1;
    return msync(mapping->addr, mapping->size, flags);
}

int protect_mapping(t_mapping *mapping, int prot) {
    if (!mapping || !mapping->addr)
        return -1;
    if (mprotect(mapping->addr, mapping->size, prot) == -1)
        return -1;
    mapping->prot = prot;
    return 0;
}

int unmap(t_mapping *mapping) {
    if (!mapping)
        return -1;

    int ret = 0;

    if (mapping->addr && mapping->addr != MAP_FAILED) {
        if (munmap(mapping->addr, mapping->size) == -1)
            ret = -1;
    }

    if (mapping->fd != -1) {
        close(mapping->fd);
    }

    if (mapping->name) {
        // Note: we use munmap for the strdup'd string workaround
        free(mapping->name);
    }

    munmap(mapping, sizeof(t_mapping));
    return ret;
}

int destroy_shared_region(const char *name) {
    if (!name)
        return -1;
    return shm_unlink(name);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de verification MAP_FAILED**

```c
/* Mutant A : Ignore MAP_FAILED */
t_mapping *map_file(const char *filepath, int writable) {
    int fd = open(filepath, O_RDONLY);
    struct stat st;
    fstat(fd, &st);

    void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    // ERREUR: pas de check MAP_FAILED !

    t_mapping *m = malloc(sizeof(t_mapping));
    m->addr = addr;  // Peut etre MAP_FAILED (-1) !
    return m;
}
// Pourquoi c'est faux: MAP_FAILED est (void*)-1, pas NULL
```

**Mutant B (Safety) : Fuite de file descriptor**

```c
/* Mutant B : FD jamais ferme */
t_mapping *map_file(const char *filepath, int writable) {
    int fd = open(filepath, O_RDONLY);
    struct stat st;
    fstat(fd, &st);

    void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    // ERREUR: fd n'est pas stocke ni ferme apres mmap !
    // Le mapping reste valide mais le fd fuit

    t_mapping *m = malloc(sizeof(t_mapping));
    m->addr = addr;
    m->fd = -1;  // On perd le fd !
    return m;
}
// Pourquoi c'est faux: Fuite de fd a chaque appel
```

**Mutant C (Resource) : munmap avec mauvaise taille**

```c
/* Mutant C : Taille incorrecte */
int unmap(t_mapping *mapping) {
    // ERREUR: utilise sizeof au lieu de la vraie taille !
    return munmap(mapping->addr, sizeof(mapping->addr));
}
// Pourquoi c'est faux: Libere seulement 8 bytes, pas toute la zone
```

**Mutant D (Logic) : MAP_PRIVATE pour memoire partagee**

```c
/* Mutant D : Mauvais flags */
t_mapping *create_shared_region(const char *name, size_t size) {
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, size);

    // ERREUR: MAP_PRIVATE au lieu de MAP_SHARED !
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE, fd, 0);

    // Les modifications ne seront pas visibles par les autres processus !
    ...
}
// Pourquoi c'est faux: MAP_PRIVATE cree une copie privee
```

**Mutant E (Return) : Pas de shm_unlink en cas d'erreur**

```c
/* Mutant E : SHM orphelin */
t_mapping *create_shared_region(const char *name, size_t size) {
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (ftruncate(fd, size) == -1) {
        close(fd);
        return NULL;  // ERREUR: shm_unlink oublie !
    }
    ...
}
// Pourquoi c'est faux: Le SHM reste dans /dev/shm indefiniment
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| mmap() | Mapping memoire de fichiers/regions | Fondamental |
| Shared Memory | Communication inter-processus rapide | Essentiel |
| Virtual Memory | Pages, alignement, protection | Important |
| Copy-on-Write | Optimisation fork/mmap | Avance |

---

### 5.2 LDA - Traduction litterale

```
FONCTION map_file QUI PREND filepath ET writable
DEBUT FONCTION
    OUVRIR LE FICHIER EN LECTURE (ou LECTURE/ECRITURE si writable)
    SI ERREUR D'OUVERTURE ALORS
        RETOURNER NULL
    FIN SI

    OBTENIR LA TAILLE DU FICHIER AVEC fstat

    APPELER mmap AVEC:
        - addr = NULL (laisser le kernel choisir)
        - size = taille du fichier
        - prot = PROT_READ (+ PROT_WRITE si writable)
        - flags = MAP_SHARED si writable, MAP_PRIVATE sinon
        - fd = le file descriptor
        - offset = 0

    SI mmap RETOURNE MAP_FAILED ALORS
        FERMER LE FICHIER
        RETOURNER NULL
    FIN SI

    CREER ET REMPLIR LA STRUCTURE t_mapping
    RETOURNER LA STRUCTURE
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
MEMORY MAPPING : Vue d'ensemble
================================

Processus A                    Processus B
+------------------+          +------------------+
|  Virtual Memory  |          |  Virtual Memory  |
|                  |          |                  |
|  0x7fff...       |          |  0x7fff...       |
|  [Stack]         |          |  [Stack]         |
|                  |          |                  |
|  0x7f00...       |          |  0x7f00...       |
|  [mmap region]---+----+-----+--[mmap region]   |
|                  |    |     |                  |
|  [Heap]          |    |     |  [Heap]          |
|                  |    |     |                  |
|  [Code/Data]     |    |     |  [Code/Data]     |
+------------------+    |     +------------------+
                        |
                        v
              +-------------------+
              |   Physical RAM    |
              |                   |
              |  [Shared Page]    |
              |   "Hello SHM"     |
              |                   |
              +-------------------+


FILE MAPPING vs ANONYMOUS
=========================

File Mapping:                    Anonymous Mapping:
+-------------+                  +-------------+
| Process     |                  | Process     |
|   mmap()----+---> File         |   mmap()----+---> Nothing
|             |     on disk      |             |     (RAM only)
+-------------+                  +-------------+

        +----------+                   +----------+
        |          |                   |          |
        | data.db  |                   | (zeros)  |
        |          |                   |          |
        +----------+                   +----------+
           Disk                        RAM only


PROTECTION FLAGS
================

PROT_READ | PROT_WRITE:
+------------------------+
|  R W                   |
|  [readable & writable] |
+------------------------+

PROT_READ only:
+------------------------+
|  R                     |
|  [read-only, SIGSEGV   |
|   on write attempt]    |
+------------------------+

PROT_NONE:
+------------------------+
|                        |
|  [guard page, SIGSEGV  |
|   on any access]       |
+------------------------+


SHARED vs PRIVATE
=================

MAP_SHARED (fork):
Parent              Child
+------+           +------+
| ptr--+--+--------+--ptr |
+------+  |        +------+
          v
     +--------+
     | Shared |  <-- Both see changes
     | Memory |
     +--------+

MAP_PRIVATE (fork):
Parent              Child
+------+           +------+
| ptr--+-->Page    | ptr--+-->Page (copy)
+------+           +------+
         [COW: Copy only on write]
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 2 mmap` - Documentation complete de mmap
- `man 3 shm_open` - POSIX shared memory
- "Advanced Programming in the UNIX Environment" - Stevens
- `/proc/[pid]/maps` - Voir les mappings d'un processus

### 6.2 Commandes utiles

```bash
# Voir les mappings memoire d'un processus
cat /proc/self/maps

# Lister les segments de memoire partagee
ls -la /dev/shm/

# Surveiller l'utilisation memoire
watch -n 1 'free -h'

# Voir les page faults
perf stat -e page-faults ./mon_programme
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Comprendre** le mecanisme de memoire virtuelle et de pagination
2. **Utiliser** mmap() pour mapper des fichiers en memoire
3. **Creer** des regions de memoire partagee entre processus
4. **Gerer** les protections memoire (lecture, ecriture, execution)
5. **Diagnostiquer** les problemes lies au mapping memoire

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.34 fork_exec | mmap + fork pour IPC |
| 0.9.39 pipes | Alternative aux pipes pour gros volumes |
| 2.10 Containers | Namespaces et isolation memoire |
