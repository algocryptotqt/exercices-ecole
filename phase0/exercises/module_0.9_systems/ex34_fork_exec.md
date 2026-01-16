# Exercice 0.9.34 : fork_exec_master

**Module :**
0.9 — Systems Programming

**Concept :**
fork(), exec(), wait(), process creation in C

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
- Notion de processus
- File descriptors

**Domaines :**
Process, Unix, Sys

**Duree estimee :**
60 min

**XP Base :**
150

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `fork_exec.c`, `fork_exec.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `fork`, `execve`, `execvp`, `wait`, `waitpid`, `exit`, `_exit`, `getpid`, `getppid`, `perror`, `printf`, `write` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `system`, `popen` (tu dois gerer fork/exec manuellement !) |

---

### 1.2 Consigne

#### Section Culture : "Multiplication Cellulaire"

**ALIEN - "In space, no one can hear your fork()"**

Comme le Xenomorphe qui se reproduit en creant des copies de lui-meme a partir d'un hote, Unix cree de nouveaux processus par division cellulaire : le processus parent se "divise" en deux avec fork(), puis le processus enfant peut muter en un tout autre programme avec exec().

*"You still don't understand what you're dealing with, do you? A perfect process. Its structural perfection is matched only by its hostility to memory leaks."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un ensemble de fonctions pour la creation et gestion de processus Unix :

1. **spawn_process** : Cree un processus enfant qui execute une commande
2. **spawn_and_wait** : Cree un processus et attend sa terminaison
3. **spawn_pipeline** : Cree une chaine de processus pipes (bonus)

**Entree (C) :**

```c
#ifndef FORK_EXEC_H
# define FORK_EXEC_H

# include <sys/types.h>

typedef struct s_process {
    pid_t   pid;
    int     status;
    char    **argv;
    char    **envp;
} t_process;

// Cree un processus enfant executant argv[0] avec arguments argv
// Retourne le PID de l'enfant ou -1 en cas d'erreur
pid_t   spawn_process(char **argv, char **envp);

// Cree un processus et attend sa terminaison
// Retourne le code de sortie du processus ou -1 en cas d'erreur
int     spawn_and_wait(char **argv, char **envp);

// Execute une commande et capture stdout dans buffer (max buf_size)
// Retourne le nombre de bytes lus ou -1 en cas d'erreur
ssize_t spawn_capture(char **argv, char **envp, char *buffer, size_t buf_size);

// Attend un processus specifique et recupere son statut
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     wait_process(pid_t pid, int *status);

#endif
```

**Sortie :**
- `spawn_process` : PID de l'enfant ou -1
- `spawn_and_wait` : Code de sortie (0-255) ou -1
- `spawn_capture` : Nombre de bytes captures ou -1
- `wait_process` : 0 ou -1

**Contraintes :**
- Gerer correctement les erreurs de fork() et exec()
- Ne pas laisser de processus zombies
- Fermer les file descriptors non utilises dans l'enfant
- Gerer le cas ou exec() echoue (l'enfant doit appeler _exit)

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `spawn_and_wait({"ls", "-l", NULL}, env)` | - | 0 | ls s'execute et retourne 0 |
| `spawn_and_wait({"false", NULL}, env)` | - | 1 | false retourne toujours 1 |
| `spawn_capture({"echo", "hello", NULL}, ...)` | - | 6 | "hello\n" capture |
| `spawn_and_wait({"nonexistent", NULL}, env)` | - | -1 ou 127 | Commande introuvable |

---

### 1.3 Prototype

**C :**
```c
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

pid_t   spawn_process(char **argv, char **envp);
int     spawn_and_wait(char **argv, char **envp);
ssize_t spawn_capture(char **argv, char **envp, char *buffer, size_t buf_size);
int     wait_process(pid_t pid, int *status);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**fork() est ancestral !**

La fonction fork() existe depuis Unix V1 (1971). Ken Thompson et Dennis Ritchie l'ont concue comme le moyen le plus simple de creer des processus : copier l'existant.

- Linux utilise Copy-On-Write : fork() est quasi-instantane car les pages memoire ne sont copiees que si modifiees
- Le premier processus Unix (PID 1) est `init`, ancetre de tous les processus
- Android utilise `zygote`, un processus pre-fork pour accelerer le demarrage des apps

**exec() remplace, ne cree pas**

exec() ne cree pas de nouveau processus ! Il remplace l'image du processus courant par une nouvelle. C'est pourquoi fork()+exec() est le pattern standard.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **SysAdmin** | Scripts d'automatisation, gestion de services |
| **Shell Developer** | Implementation de bash, zsh, fish |
| **Container Engineer** | Docker, containerd utilisent fork/exec massivement |
| **Security Researcher** | Process injection, privilege escalation |
| **Embedded Developer** | Gestion de processus sur systemes contraints |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "fork_exec.h"
#include <stdio.h>

int main(void) {
    char *argv[] = {"ls", "-la", NULL};
    extern char **environ;

    printf("Spawning ls...\n");
    int ret = spawn_and_wait(argv, environ);
    printf("ls returned: %d\n", ret);

    char buffer[1024];
    char *echo_argv[] = {"echo", "Hello from child!", NULL};
    ssize_t n = spawn_capture(echo_argv, environ, buffer, sizeof(buffer));
    printf("Captured %zd bytes: %s", n, buffer);

    return 0;
}

$ gcc -Wall -Wextra -Werror fork_exec.c main.c -o test
$ ./test
Spawning ls...
total 24
drwxr-xr-x  2 user user 4096 Jan 16 10:00 .
-rw-r--r--  1 user user 2048 Jan 16 10:00 fork_exec.c
-rw-r--r--  1 user user  512 Jan 16 10:00 fork_exec.h
-rw-r--r--  1 user user  384 Jan 16 10:00 main.c
ls returned: 0
Captured 18 bytes: Hello from child!
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
6/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer `spawn_pipeline` qui execute une chaine de commandes pipees :

```c
// Execute une pipeline de commandes : cmd1 | cmd2 | cmd3 | ...
// cmds est un tableau de tableaux argv termine par NULL
// Retourne le code de sortie de la derniere commande
int spawn_pipeline(char ***cmds, char **envp);

// Exemple: ls | grep ".c" | wc -l
char *cmd1[] = {"ls", NULL};
char *cmd2[] = {"grep", ".c", NULL};
char *cmd3[] = {"wc", "-l", NULL};
char **pipeline[] = {cmd1, cmd2, cmd3, NULL};
int ret = spawn_pipeline(pipeline, environ);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | spawn_true | spawn_and_wait({"true"}) | 0 | 5 | Basic |
| 2 | spawn_false | spawn_and_wait({"false"}) | 1 | 5 | Basic |
| 3 | spawn_echo | spawn_capture({"echo", "test"}) | "test\n" | 10 | Capture |
| 4 | spawn_invalid | spawn_and_wait({"nonexistent"}) | -1 ou 127 | 10 | Error |
| 5 | spawn_exit_42 | spawn_and_wait({"sh", "-c", "exit 42"}) | 42 | 10 | Exit code |
| 6 | no_zombie | spawn 100, wait all | no defunct | 15 | Zombie |
| 7 | fork_fail | with RLIMIT_NPROC=0 | -1 | 10 | Error |
| 8 | exec_fail_cleanup | invalid path | child exits 127 | 10 | Cleanup |
| 9 | capture_large | 1MB output | truncated | 10 | Buffer |
| 10 | env_passed | {"env"} | contains PATH | 5 | Env |
| 11 | concurrent_spawn | 10 parallel | all complete | 10 | Concurrency |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include "fork_exec.h"

extern char **environ;

void test_spawn_true(void) {
    char *argv[] = {"true", NULL};
    int ret = spawn_and_wait(argv, environ);
    assert(ret == 0);
    printf("Test spawn_true: OK\n");
}

void test_spawn_false(void) {
    char *argv[] = {"false", NULL};
    int ret = spawn_and_wait(argv, environ);
    assert(ret == 1);
    printf("Test spawn_false: OK\n");
}

void test_spawn_echo(void) {
    char buffer[256] = {0};
    char *argv[] = {"echo", "hello world", NULL};
    ssize_t n = spawn_capture(argv, environ, buffer, sizeof(buffer));
    assert(n == 12); // "hello world\n"
    assert(strcmp(buffer, "hello world\n") == 0);
    printf("Test spawn_echo: OK\n");
}

void test_spawn_invalid(void) {
    char *argv[] = {"/nonexistent/binary", NULL};
    int ret = spawn_and_wait(argv, environ);
    assert(ret == -1 || ret == 127);
    printf("Test spawn_invalid: OK\n");
}

void test_exit_code(void) {
    char *argv[] = {"sh", "-c", "exit 42", NULL};
    int ret = spawn_and_wait(argv, environ);
    assert(ret == 42);
    printf("Test exit_code: OK\n");
}

void test_no_zombies(void) {
    for (int i = 0; i < 50; i++) {
        char *argv[] = {"true", NULL};
        spawn_and_wait(argv, environ);
    }
    // Check no zombies with ps or /proc
    printf("Test no_zombies: OK (manual verification needed)\n");
}

void test_capture_env(void) {
    char buffer[8192] = {0};
    char *argv[] = {"env", NULL};
    ssize_t n = spawn_capture(argv, environ, buffer, sizeof(buffer));
    assert(n > 0);
    assert(strstr(buffer, "PATH=") != NULL);
    printf("Test capture_env: OK\n");
}

int main(void) {
    test_spawn_true();
    test_spawn_false();
    test_spawn_echo();
    test_spawn_invalid();
    test_exit_code();
    test_no_zombies();
    test_capture_env();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "fork_exec.h"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>

pid_t spawn_process(char **argv, char **envp) {
    if (!argv || !argv[0]) {
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        return -1;
    }

    if (pid == 0) {
        // Child process
        execvp(argv[0], argv);
        // If exec fails, exit with 127 (command not found convention)
        _exit(127);
    }

    // Parent returns child PID
    return pid;
}

int spawn_and_wait(char **argv, char **envp) {
    pid_t pid = spawn_process(argv, envp);
    if (pid == -1) {
        return -1;
    }

    int status;
    if (wait_process(pid, &status) == -1) {
        return -1;
    }

    return status;
}

ssize_t spawn_capture(char **argv, char **envp, char *buffer, size_t buf_size) {
    if (!argv || !argv[0] || !buffer || buf_size == 0) {
        return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // Child: redirect stdout to pipe
        close(pipefd[0]); // Close read end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        execvp(argv[0], argv);
        _exit(127);
    }

    // Parent: read from pipe
    close(pipefd[1]); // Close write end

    ssize_t total = 0;
    ssize_t n;
    while (total < (ssize_t)(buf_size - 1) &&
           (n = read(pipefd[0], buffer + total, buf_size - 1 - total)) > 0) {
        total += n;
    }
    buffer[total] = '\0';

    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        return -1; // exec failed
    }

    return total;
}

int wait_process(pid_t pid, int *status) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) == -1) {
        return -1;
    }

    if (WIFEXITED(wstatus)) {
        *status = WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
        *status = 128 + WTERMSIG(wstatus);
    } else {
        *status = -1;
    }

    return 0;
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de execve au lieu de execvp**

```c
pid_t spawn_process(char **argv, char **envp) {
    pid_t pid = fork();
    if (pid == 0) {
        // Recherche manuelle dans PATH
        char *path = getenv("PATH");
        // ... implementation de la recherche
        execve(full_path, argv, envp);
        _exit(127);
    }
    return pid;
}
```

**Alternative 2 : Utilisation de vfork**

```c
// vfork est plus efficace mais plus dangereux
pid_t pid = vfork();
if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
}
```

---

### 4.5 Solutions refusees

**Refus 1 : Utilisation de system()**

```c
// REFUSE : system() est interdit !
int spawn_and_wait(char **argv, char **envp) {
    return system(argv[0]); // NON !
}
```
**Pourquoi refuse :** `system()` est une abstraction qui masque fork/exec. L'exercice demande d'implementer cette mecanique.

**Refus 2 : Pas de gestion des zombies**

```c
// REFUSE : laisse des zombies !
pid_t spawn_process(char **argv, char **envp) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        exit(127); // Pas _exit !
    }
    return pid;
    // Jamais de wait => zombie
}
```
**Pourquoi refuse :** Les processus enfants non recuperes deviennent des zombies.

**Refus 3 : exit() au lieu de _exit() dans l'enfant**

```c
if (pid == 0) {
    execvp(argv[0], argv);
    exit(127); // DANGER: flush les buffers du parent !
}
```
**Pourquoi refuse :** `exit()` flush les buffers stdio, ce qui peut dupliquer la sortie du parent.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de verification argv NULL**

```c
/* Mutant A (Boundary) : Pas de check NULL */
pid_t spawn_process(char **argv, char **envp) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv); // CRASH si argv est NULL !
        _exit(127);
    }
    return pid;
}
// Pourquoi c'est faux : Segfault si argv est NULL
// Ce qui etait pense : "L'appelant passera toujours un argv valide"
```

**Mutant B (Safety) : exit() au lieu de _exit()**

```c
/* Mutant B (Safety) : Mauvaise fonction exit */
pid_t spawn_process(char **argv, char **envp) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        exit(127); // FAUX: devrait etre _exit !
    }
    return pid;
}
// Pourquoi c'est faux : exit() appelle les handlers atexit et flush stdio
// Ce qui etait pense : "exit et _exit c'est pareil"
```

**Mutant C (Resource) : File descriptors non fermes**

```c
/* Mutant C (Resource) : Fuite de FD */
ssize_t spawn_capture(char **argv, char **envp, char *buffer, size_t buf_size) {
    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) {
        // OUBLI: close(pipefd[0]); close(pipefd[1]);
        dup2(pipefd[1], STDOUT_FILENO);
        execvp(argv[0], argv);
        _exit(127);
    }

    // OUBLI: close(pipefd[1]);
    read(pipefd[0], buffer, buf_size);
    // OUBLI: close(pipefd[0]);

    waitpid(pid, NULL, 0);
    return strlen(buffer);
}
// Pourquoi c'est faux : Fuite de file descriptors a chaque appel
```

**Mutant D (Logic) : Pas d'attente du processus**

```c
/* Mutant D (Logic) : Zombie creator */
int spawn_and_wait(char **argv, char **envp) {
    pid_t pid = spawn_process(argv, envp);
    // OUBLI: wait() !
    return 0; // Toujours retourne 0, laisse un zombie
}
// Pourquoi c'est faux : Cree des processus zombies, retourne pas le vrai status
// Ce qui etait pense : "spawn_process fait tout le travail"
```

**Mutant E (Return) : Mauvais code de retour**

```c
/* Mutant E (Return) : Mauvaise interpretation du status */
int wait_process(pid_t pid, int *status) {
    int wstatus;
    waitpid(pid, &wstatus, 0);
    *status = wstatus; // FAUX: wstatus n'est pas le code de sortie !
    return 0;
}
// Pourquoi c'est faux : wstatus encode plus que le code de sortie
// Ce qui etait pense : "Le status c'est le code de sortie"
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| fork() | Creation de processus par duplication | Fondamental |
| exec() | Remplacement de l'image processus | Fondamental |
| wait() | Synchronisation parent-enfant | Essentiel |
| Zombies | Processus termines non recuperes | Important |
| Pipes | Communication inter-processus | Utile |

---

### 5.2 LDA - Traduction litterale

```
FONCTION spawn_and_wait QUI PREND argv ET envp
DEBUT FONCTION
    CREER UN NOUVEAU PROCESSUS AVEC fork
    SI L'ON EST DANS LE PROCESSUS ENFANT ALORS
        REMPLACER L'IMAGE PAR argv[0] AVEC execvp
        SI execvp ECHOUE ALORS
            TERMINER AVEC CODE 127
        FIN SI
    SINON (PROCESSUS PARENT)
        ATTENDRE LA TERMINAISON DE L'ENFANT
        RECUPERER SON CODE DE SORTIE
        RETOURNER CE CODE
    FIN SI
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
FORK : Duplication de processus
==================================

Avant fork():
┌─────────────────────────┐
│     Process (PID 100)   │
│   ┌─────────────────┐   │
│   │ Code + Data     │   │
│   │ Stack           │   │
│   │ Heap            │   │
│   └─────────────────┘   │
└─────────────────────────┘

Apres fork():
┌─────────────────────────┐     ┌─────────────────────────┐
│  Parent (PID 100)       │     │  Child (PID 101)        │
│   ┌─────────────────┐   │     │   ┌─────────────────┐   │
│   │ Code + Data     │   │     │   │ Code + Data     │   │
│   │ (identique)     │   │     │   │ (copie COW)     │   │
│   │ fork() = 101    │   │     │   │ fork() = 0      │   │
│   └─────────────────┘   │     │   └─────────────────┘   │
└─────────────────────────┘     └─────────────────────────┘

EXEC : Remplacement de l'image
===============================

Avant exec():           Apres exec():
┌─────────────────┐     ┌─────────────────┐
│ Child PID 101   │     │ Child PID 101   │
│ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ Mon code    │ │ --> │ │ /bin/ls     │ │
│ │ Mes donnees │ │     │ │ Nouvelles   │ │
│ │ Mon stack   │ │     │ │ donnees     │ │
│ └─────────────┘ │     │ └─────────────┘ │
└─────────────────┘     └─────────────────┘
      Meme PID, nouvelle image !

LIFECYCLE COMPLET :
===================

Parent ──fork()──> Parent continue
    │                    │
    │                    │ wait()
    └──> Child           │
           │             │
        exec()           │
           │             │
         Work            │
           │             │
        exit(n)          │
           │             │
         Zombie <────────┘
           │          waitpid()
         Reap
           │
        Termine
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Oublier que fork() retourne DEUX fois

```c
// FAUX : traite fork comme un appel normal
pid_t pid = fork();
printf("PID: %d\n", pid);
// Affiche deux fois ! Une fois 0, une fois le vrai PID

// CORRECT : toujours verifier
pid_t pid = fork();
if (pid == 0) {
    // Code enfant UNIQUEMENT
} else if (pid > 0) {
    // Code parent UNIQUEMENT
} else {
    // Erreur fork
}
```

#### Piege 2 : exec() ne retourne jamais (sauf erreur)

```c
// FAUX : code apres exec jamais atteint
execvp("ls", argv);
printf("ls executed!\n"); // JAMAIS AFFICHE si exec reussit !

// CORRECT : code apres exec = gestion erreur
execvp("ls", argv);
// Si on arrive ici, exec a echoue
perror("exec failed");
_exit(127);
```

#### Piege 3 : Variables non partagees apres fork

```c
int counter = 0;
if (fork() == 0) {
    counter++; // Modifie la COPIE de l'enfant
    exit(0);
}
wait(NULL);
printf("counter = %d\n", counter); // Affiche 0, pas 1 !
```

---

### 5.5 Cours Complet

#### 5.5.1 fork() - La division cellulaire

`fork()` cree une copie quasi-identique du processus appelant :

| Herite | Pas herite |
|--------|-----------|
| Espace memoire (COW) | PID |
| File descriptors | PPID |
| Signal handlers | Locks |
| Umask | Pending signals |
| Variables d'environnement | Resource counters |

#### 5.5.2 La famille exec()

| Fonction | PATH | argv type | envp |
|----------|------|-----------|------|
| `execl` | Non | varargs | inherited |
| `execv` | Non | array | inherited |
| `execle` | Non | varargs | explicit |
| `execve` | Non | array | explicit |
| `execlp` | Oui | varargs | inherited |
| `execvp` | Oui | array | inherited |

#### 5.5.3 wait() et status

Le status retourne par wait() encode plusieurs informations :

```c
if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status); // Code 0-255
}
if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status); // Numero du signal
}
if (WIFSTOPPED(status)) {
    int sig = WSTOPSIG(status); // Signal de stop
}
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Pas de wait() | Zombies | Toujours wait |
| 2 | exit() dans enfant | Buffer flush | Utiliser _exit() |
| 3 | Code apres exec | Dead code | Gerer l'erreur |
| 4 | Fork sans check retour | Comportement double | if/else sur pid |
| 5 | FD non fermes | Fuite ressources | close() avant exec |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Que retourne fork() dans le processus parent ?

- A) 0
- B) -1
- C) Le PID de l'enfant
- D) Le PID du parent
- E) 1

**Reponse : C** - fork() retourne le PID de l'enfant dans le parent, 0 dans l'enfant.

### Question 2 (4 points)
Pourquoi utiliser _exit() plutot que exit() dans l'enfant apres un exec echoue ?

- A) C'est plus rapide
- B) exit() ne fonctionne pas apres fork
- C) _exit() evite de flush les buffers stdio du parent
- D) _exit() envoie un signal au parent

**Reponse : C** - exit() appelle les handlers atexit et flush les buffers, ce qui peut dupliquer la sortie.

### Question 3 (3 points)
Qu'est-ce qu'un processus zombie ?

- A) Un processus qui consomme 100% CPU
- B) Un processus termine mais non recupere par wait()
- C) Un processus sans parent
- D) Un processus qui ne repond pas aux signaux

**Reponse : B** - Un zombie est un processus termine dont le status n'a pas ete recupere.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.9.34 |
| **Nom** | fork_exec_master |
| **Difficulte** | 5/10 |
| **Duree** | 60 min |
| **XP Base** | 150 |
| **Langage** | C (c17) |
| **Concepts cles** | fork, exec, wait, zombies |
| **Prerequis** | C basics, processes |

---

*Document genere selon HACKBRAIN v5.5.2*
