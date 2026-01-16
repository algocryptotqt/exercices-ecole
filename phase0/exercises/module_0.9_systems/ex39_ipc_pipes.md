# Exercice 0.9.39 : pipe_master

**Module :**
0.9 — Systems Programming

**Concept :**
pipe(), dup2(), file descriptor redirection, IPC

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
- fork() et processus
- File descriptors (stdin, stdout, stderr)
- Exercice ex34_fork_exec

**Domaines :**
IPC, Unix, Sys, Process

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
| C | `pipe_master.c`, `pipe_master.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `pipe`, `dup`, `dup2`, `close`, `read`, `write`, `fork`, `wait`, `waitpid`, `execvp`, `exit`, `_exit`, `perror`, `printf` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `popen`, `system` (tu dois gerer les pipes manuellement!) |

---

### 1.2 Consigne

#### Section Culture : "Mario Bros - Les Tuyaux de Communication"

**SUPER MARIO BROS - "It's-a me, pipe()!"**

Dans le Royaume Champignon, Mario voyage entre les mondes grace aux fameux tuyaux verts (warp pipes). Ces tuyaux connectent deux zones : une entree et une sortie. Exactement comme les pipes Unix !

*"When you enter a pipe, you come out somewhere else. That's basically what dup2() does - redirect where your data flows!"*

Luigi t'explique le systeme :

- **Tuyau vert** = pipe() - cree deux extremites (pipefd[0] pour lire, pipefd[1] pour ecrire)
- **Entrer dans le tuyau** = dup2(pipefd[1], STDOUT) - la sortie va dans le tuyau
- **Sortir du tuyau** = dup2(pipefd[0], STDIN) - l'entree vient du tuyau
- **Warp Zone** = pipeline de commandes (ls | grep | wc)

*"Remember: what goes in one end, comes out the other. Close the ends you don't use, or you'll get stuck in the pipe forever!"*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un ensemble de fonctions pour la gestion des pipes Unix :

1. **create_pipe** : Cree un pipe et retourne les descripteurs
2. **redirect_stdout** : Redirige stdout vers un file descriptor
3. **redirect_stdin** : Redirige stdin depuis un file descriptor
4. **pipe_command** : Execute une commande avec stdin/stdout rediriges
5. **create_pipeline** : Execute une chaine de commandes pipees

**Entree (C) :**

```c
#ifndef PIPE_MASTER_H
# define PIPE_MASTER_H

# include <sys/types.h>
# include <unistd.h>

typedef struct s_pipe {
    int read_fd;    // Extremite lecture (pipefd[0])
    int write_fd;   // Extremite ecriture (pipefd[1])
} t_pipe;

typedef struct s_command {
    char    **argv;     // Arguments (argv[0] = programme)
    int     stdin_fd;   // FD pour stdin (-1 = pas de redirection)
    int     stdout_fd;  // FD pour stdout (-1 = pas de redirection)
} t_command;

// Cree un nouveau pipe
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     create_pipe(t_pipe *p);

// Ferme les deux extremites d'un pipe
void    close_pipe(t_pipe *p);

// Redirige stdout vers le fd specifie (utilise dup2)
// Retourne l'ancien stdout ou -1 en cas d'erreur
int     redirect_stdout(int new_fd);

// Redirige stdin depuis le fd specifie (utilise dup2)
// Retourne l'ancien stdin ou -1 en cas d'erreur
int     redirect_stdin(int new_fd);

// Restaure un fd precedemment sauvegarde
int     restore_fd(int saved_fd, int target_fd);

// Execute une commande avec les redirections specifiees
// Retourne le code de sortie de la commande
int     pipe_command(t_command *cmd, char **envp);

// Execute un pipeline de n commandes
// cmds[i].stdout est automatiquement connecte a cmds[i+1].stdin
// Retourne le code de sortie de la derniere commande
int     create_pipeline(t_command *cmds, int n, char **envp);

// Fonction utilitaire : lit tout le contenu d'un fd dans un buffer
// Retourne le nombre d'octets lus ou -1 en cas d'erreur
ssize_t read_all(int fd, char *buffer, size_t size);

// Fonction utilitaire : ecrit tout le buffer dans un fd
// Retourne le nombre d'octets ecrits ou -1 en cas d'erreur
ssize_t write_all(int fd, const char *buffer, size_t size);

#endif
```

**Sortie :**
- `create_pipe` : 0 succes, -1 erreur
- `redirect_stdout/stdin` : ancien fd ou -1
- `pipe_command` : code de sortie (0-255) ou -1
- `create_pipeline` : code de sortie de la derniere commande

**Contraintes :**
- Toujours fermer les extremites de pipe non utilisees
- Gerer les erreurs de fork() et pipe()
- Eviter les deadlocks (fermer write_fd avant de lire)
- Ne pas laisser de processus zombies

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `create_pipe(&p)` | - | 0 | Pipe cree avec p.read_fd et p.write_fd |
| `redirect_stdout(p.write_fd)` | - | 1 | stdout redirige, ancien fd=1 |
| Pipeline `ls \| wc -l` | - | exit code | Compte les fichiers |

---

### 1.3 Prototype

**C :**
```c
#include <unistd.h>
#include <sys/wait.h>

int     create_pipe(t_pipe *p);
void    close_pipe(t_pipe *p);
int     redirect_stdout(int new_fd);
int     redirect_stdin(int new_fd);
int     restore_fd(int saved_fd, int target_fd);
int     pipe_command(t_command *cmd, char **envp);
int     create_pipeline(t_command *cmds, int n, char **envp);
ssize_t read_all(int fd, char *buffer, size_t size);
ssize_t write_all(int fd, const char *buffer, size_t size);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Les pipes sont anciens !**

Les pipes Unix ont ete inventes par Doug McIlroy en 1973. L'idee etait de "connecter des programmes comme des tuyaux de plomberie". Cette philosophie a defini Unix : des petits programmes qui font une seule chose bien, connectes ensemble.

**Le fameux '|'**

Le caractere pipe '|' a ete ajoute au clavier specifiquement pour Unix. Avant cela, il n'existait pas sur les machines a ecrire !

**Taille du buffer**

Un pipe Linux a un buffer de 64KB (configurable). Si le writer ecrit plus vite que le reader ne lit, write() bloquera quand le buffer est plein. C'est le flow control automatique !

**Pipes nommes (FIFO)**

Les pipes normaux sont anonymes et n'existent qu'entre processus apparentes. Les pipes nommes (mkfifo) permettent a n'importe quel processus de communiquer.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Shell Developer** | Implementation de bash, zsh (pipelines) |
| **DevOps Engineer** | Scripts shell complexes, log processing |
| **System Administrator** | Monitoring, filtrage de logs |
| **Backend Developer** | Communication entre services |
| **Build Engineer** | Systemes de build, CI/CD pipelines |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "pipe_master.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern char **environ;

int main(void) {
    // Test 1: Simple pipe between two processes
    printf("=== Test: ls | grep .c ===\n");

    char *ls_argv[] = {"ls", "-la", NULL};
    char *grep_argv[] = {"grep", ".c", NULL};

    t_command cmds[2] = {
        {.argv = ls_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = grep_argv, .stdin_fd = -1, .stdout_fd = -1}
    };

    int ret = create_pipeline(cmds, 2, environ);
    printf("Pipeline exit code: %d\n\n", ret);

    // Test 2: Three-stage pipeline
    printf("=== Test: cat /etc/passwd | grep root | wc -l ===\n");

    char *cat_argv[] = {"cat", "/etc/passwd", NULL};
    char *grep2_argv[] = {"grep", "root", NULL};
    char *wc_argv[] = {"wc", "-l", NULL};

    t_command cmds2[3] = {
        {.argv = cat_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = grep2_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = wc_argv, .stdin_fd = -1, .stdout_fd = -1}
    };

    ret = create_pipeline(cmds2, 3, environ);
    printf("Pipeline exit code: %d\n\n", ret);

    // Test 3: Manual pipe usage
    printf("=== Test: Manual pipe ===\n");
    t_pipe p;
    create_pipe(&p);

    pid_t pid = fork();
    if (pid == 0) {
        close(p.read_fd);
        write_all(p.write_fd, "Hello from child!\n", 18);
        close(p.write_fd);
        exit(0);
    }

    close(p.write_fd);
    char buffer[256] = {0};
    read_all(p.read_fd, buffer, sizeof(buffer));
    close(p.read_fd);

    printf("Parent received: %s", buffer);
    wait(NULL);

    return 0;
}

$ gcc -Wall -Wextra -Werror pipe_master.c main.c -o test
$ ./test
=== Test: ls | grep .c ===
-rw-r--r-- 1 user user 2048 Jan 16 10:00 main.c
-rw-r--r-- 1 user user 4096 Jan 16 10:00 pipe_master.c
Pipeline exit code: 0

=== Test: cat /etc/passwd | grep root | wc -l ===
1
Pipeline exit code: 0

=== Test: Manual pipe ===
Parent received: Hello from child!
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un mini-shell avec support des pipes et redirections :

```c
typedef struct s_redirect {
    int     type;       // 0=none, 1=input(<), 2=output(>), 3=append(>>)
    char    *filename;
} t_redirect;

typedef struct s_shell_cmd {
    char        **argv;
    t_redirect  in;
    t_redirect  out;
} t_shell_cmd;

// Parse une ligne de commande en structure
// Exemple: "ls -la | grep foo > output.txt"
t_shell_cmd *parse_command_line(const char *line, int *count);

// Execute une ligne de commande complete
int execute_command_line(const char *line, char **envp);

// Exemple d'utilisation:
// execute_command_line("cat file.txt | sort | uniq > result.txt", environ);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_pipe | create_pipe(&p) | p.read_fd, p.write_fd valid | 10 | Basic |
| 2 | pipe_rw | write then read | data transferred | 10 | Basic |
| 3 | redirect_stdout | redirect + printf | output to fd | 10 | Redirect |
| 4 | redirect_stdin | redirect + getchar | input from fd | 10 | Redirect |
| 5 | simple_pipeline | ls \| wc | correct count | 15 | Pipeline |
| 6 | three_stage | cat \| grep \| wc | correct result | 15 | Pipeline |
| 7 | close_unused | fork + close | no hang | 10 | Safety |
| 8 | error_handling | invalid fd | -1 returned | 5 | Error |
| 9 | no_zombies | 10 pipelines | no defunct | 10 | Cleanup |
| 10 | large_data | 1MB through pipe | no deadlock | 5 | Stress |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "pipe_master.h"

extern char **environ;

void test_create_pipe(void) {
    t_pipe p;
    assert(create_pipe(&p) == 0);
    assert(p.read_fd >= 0);
    assert(p.write_fd >= 0);
    assert(p.read_fd != p.write_fd);
    close_pipe(&p);
    printf("Test create_pipe: OK\n");
}

void test_pipe_communication(void) {
    t_pipe p;
    create_pipe(&p);

    const char *msg = "Hello, pipe!";
    write_all(p.write_fd, msg, strlen(msg));
    close(p.write_fd);

    char buffer[64] = {0};
    ssize_t n = read_all(p.read_fd, buffer, sizeof(buffer));
    close(p.read_fd);

    assert(n == (ssize_t)strlen(msg));
    assert(strcmp(buffer, msg) == 0);
    printf("Test pipe_communication: OK\n");
}

void test_redirect_stdout(void) {
    t_pipe p;
    create_pipe(&p);

    int saved = redirect_stdout(p.write_fd);
    assert(saved >= 0);

    printf("Redirected output");
    fflush(stdout);

    restore_fd(saved, STDOUT_FILENO);
    close(p.write_fd);

    char buffer[64] = {0};
    read_all(p.read_fd, buffer, sizeof(buffer));
    close(p.read_fd);

    assert(strcmp(buffer, "Redirected output") == 0);
    printf("Test redirect_stdout: OK\n");
}

void test_simple_pipeline(void) {
    char *echo_argv[] = {"echo", "hello world", NULL};
    char *wc_argv[] = {"wc", "-c", NULL};

    t_command cmds[2] = {
        {.argv = echo_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = wc_argv, .stdin_fd = -1, .stdout_fd = -1}
    };

    int ret = create_pipeline(cmds, 2, environ);
    assert(ret == 0);
    printf("Test simple_pipeline: OK\n");
}

void test_three_stage(void) {
    char *echo_argv[] = {"echo", "-e", "a\\nb\\nc\\na\\nb", NULL};
    char *sort_argv[] = {"sort", NULL};
    char *uniq_argv[] = {"uniq", NULL};

    t_command cmds[3] = {
        {.argv = echo_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = sort_argv, .stdin_fd = -1, .stdout_fd = -1},
        {.argv = uniq_argv, .stdin_fd = -1, .stdout_fd = -1}
    };

    int ret = create_pipeline(cmds, 3, environ);
    assert(ret == 0);
    printf("Test three_stage: OK\n");
}

int main(void) {
    test_create_pipe();
    test_pipe_communication();
    test_redirect_stdout();
    test_simple_pipeline();
    test_three_stage();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "pipe_master.h"
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int create_pipe(t_pipe *p) {
    int pipefd[2];

    if (!p)
        return -1;

    if (pipe(pipefd) == -1)
        return -1;

    p->read_fd = pipefd[0];
    p->write_fd = pipefd[1];
    return 0;
}

void close_pipe(t_pipe *p) {
    if (!p)
        return;
    if (p->read_fd >= 0)
        close(p->read_fd);
    if (p->write_fd >= 0)
        close(p->write_fd);
    p->read_fd = -1;
    p->write_fd = -1;
}

int redirect_stdout(int new_fd) {
    if (new_fd < 0)
        return -1;

    int saved = dup(STDOUT_FILENO);
    if (saved == -1)
        return -1;

    if (dup2(new_fd, STDOUT_FILENO) == -1) {
        close(saved);
        return -1;
    }

    return saved;
}

int redirect_stdin(int new_fd) {
    if (new_fd < 0)
        return -1;

    int saved = dup(STDIN_FILENO);
    if (saved == -1)
        return -1;

    if (dup2(new_fd, STDIN_FILENO) == -1) {
        close(saved);
        return -1;
    }

    return saved;
}

int restore_fd(int saved_fd, int target_fd) {
    if (saved_fd < 0 || target_fd < 0)
        return -1;

    if (dup2(saved_fd, target_fd) == -1)
        return -1;

    close(saved_fd);
    return 0;
}

ssize_t read_all(int fd, char *buffer, size_t size) {
    if (fd < 0 || !buffer || size == 0)
        return -1;

    ssize_t total = 0;
    ssize_t n;

    while (total < (ssize_t)(size - 1)) {
        n = read(fd, buffer + total, size - 1 - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        total += n;
    }

    buffer[total] = '\0';
    return total;
}

ssize_t write_all(int fd, const char *buffer, size_t size) {
    if (fd < 0 || !buffer)
        return -1;

    ssize_t total = 0;
    ssize_t n;

    while (total < (ssize_t)size) {
        n = write(fd, buffer + total, size - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += n;
    }

    return total;
}

int pipe_command(t_command *cmd, char **envp) {
    if (!cmd || !cmd->argv || !cmd->argv[0])
        return -1;

    pid_t pid = fork();
    if (pid == -1)
        return -1;

    if (pid == 0) {
        // Child process
        if (cmd->stdin_fd >= 0) {
            dup2(cmd->stdin_fd, STDIN_FILENO);
            close(cmd->stdin_fd);
        }
        if (cmd->stdout_fd >= 0) {
            dup2(cmd->stdout_fd, STDOUT_FILENO);
            close(cmd->stdout_fd);
        }

        execvp(cmd->argv[0], cmd->argv);
        _exit(127);
    }

    // Parent
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

int create_pipeline(t_command *cmds, int n, char **envp) {
    if (!cmds || n <= 0 || !envp)
        return -1;

    if (n == 1)
        return pipe_command(&cmds[0], envp);

    t_pipe *pipes = malloc(sizeof(t_pipe) * (n - 1));
    if (!pipes)
        return -1;

    // Create all pipes
    for (int i = 0; i < n - 1; i++) {
        if (create_pipe(&pipes[i]) == -1) {
            // Cleanup on error
            for (int j = 0; j < i; j++)
                close_pipe(&pipes[j]);
            free(pipes);
            return -1;
        }
    }

    pid_t *pids = malloc(sizeof(pid_t) * n);
    if (!pids) {
        for (int i = 0; i < n - 1; i++)
            close_pipe(&pipes[i]);
        free(pipes);
        return -1;
    }

    // Fork all processes
    for (int i = 0; i < n; i++) {
        pids[i] = fork();
        if (pids[i] == -1) {
            // Error handling omitted for brevity
            break;
        }

        if (pids[i] == 0) {
            // Child process

            // Setup stdin (from previous pipe)
            if (i > 0) {
                dup2(pipes[i - 1].read_fd, STDIN_FILENO);
            } else if (cmds[i].stdin_fd >= 0) {
                dup2(cmds[i].stdin_fd, STDIN_FILENO);
            }

            // Setup stdout (to next pipe)
            if (i < n - 1) {
                dup2(pipes[i].write_fd, STDOUT_FILENO);
            } else if (cmds[i].stdout_fd >= 0) {
                dup2(cmds[i].stdout_fd, STDOUT_FILENO);
            }

            // Close all pipe fds in child
            for (int j = 0; j < n - 1; j++)
                close_pipe(&pipes[j]);

            execvp(cmds[i].argv[0], cmds[i].argv);
            _exit(127);
        }
    }

    // Parent: close all pipes
    for (int i = 0; i < n - 1; i++)
        close_pipe(&pipes[i]);

    // Wait for all children
    int last_status = 0;
    for (int i = 0; i < n; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (i == n - 1 && WIFEXITED(status))
            last_status = WEXITSTATUS(status);
    }

    free(pipes);
    free(pids);

    return last_status;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de close() des extremites inutilisees**

```c
/* Mutant A : Deadlock garanti */
int create_pipeline(t_command *cmds, int n, char **envp) {
    t_pipe p;
    create_pipe(&p);

    if (fork() == 0) {
        // Child 1 (writer)
        dup2(p.write_fd, STDOUT_FILENO);
        // ERREUR: p.read_fd pas ferme !
        execvp(cmds[0].argv[0], cmds[0].argv);
    }

    if (fork() == 0) {
        // Child 2 (reader)
        dup2(p.read_fd, STDIN_FILENO);
        // ERREUR: p.write_fd pas ferme !
        // read() ne retournera jamais EOF !
        execvp(cmds[1].argv[0], cmds[1].argv);
    }
    // Deadlock: le reader attend EOF qui ne viendra jamais
}
// Pourquoi c'est faux: Il faut fermer write_fd pour que read() voit EOF
```

**Mutant B (Safety) : dup2 avant fork**

```c
/* Mutant B : Modification du parent */
int pipe_command(t_command *cmd, char **envp) {
    // ERREUR: dup2 AVANT fork !
    if (cmd->stdout_fd >= 0)
        dup2(cmd->stdout_fd, STDOUT_FILENO);

    pid_t pid = fork();
    // Maintenant le PARENT a aussi stdout redirige !
    ...
}
// Pourquoi c'est faux: Le parent perd son stdout original
```

**Mutant C (Resource) : Fuite de file descriptors**

```c
/* Mutant C : FD leaks */
int create_pipeline(t_command *cmds, int n, char **envp) {
    for (int i = 0; i < n - 1; i++) {
        t_pipe p;
        create_pipe(&p);

        if (fork() == 0) {
            dup2(p.write_fd, STDOUT_FILENO);
            // Ferme seulement write_fd, pas read_fd !
            close(p.write_fd);
            execvp(...);
        }
        // ERREUR: pipes jamais fermees dans le parent !
    }
    // Fuite de 2 * (n-1) file descriptors
}
// Pourquoi c'est faux: Limite de FD ouverts atteinte rapidement
```

**Mutant D (Logic) : Ordre incorrect read/write**

```c
/* Mutant D : pipefd inverse */
int create_pipe(t_pipe *p) {
    int pipefd[2];
    pipe(pipefd);

    // ERREUR: indices inverses !
    p->read_fd = pipefd[1];   // Devrait etre [0]
    p->write_fd = pipefd[0];  // Devrait etre [1]
    return 0;
}
// Pourquoi c'est faux: Ecriture sur read end = SIGPIPE/EPIPE
```

**Mutant E (Return) : Pas d'attente des enfants**

```c
/* Mutant E : Zombie factory */
int create_pipeline(t_command *cmds, int n, char **envp) {
    for (int i = 0; i < n; i++) {
        if (fork() == 0) {
            execvp(cmds[i].argv[0], cmds[i].argv);
            _exit(127);
        }
        // ERREUR: pas de wait() !
    }
    return 0;  // Code de sortie inconnu
}
// Pourquoi c'est faux: Processus zombies, pas de code de retour
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| pipe() | Creation de canaux de communication | Fondamental |
| dup2() | Redirection de file descriptors | Essentiel |
| Pipeline | Chaine de processus connectes | Classique |
| Flow control | Gestion du buffer et blocage | Important |

---

### 5.2 LDA - Traduction litterale

```
FONCTION create_pipeline QUI PREND cmds, n, envp
DEBUT FONCTION
    CREER (n-1) PIPES POUR CONNECTER LES n COMMANDES

    POUR i DE 0 A n-1 FAIRE
        CREER UN PROCESSUS ENFANT AVEC fork

        SI PROCESSUS ENFANT ALORS
            SI i > 0 ALORS
                REDIRIGER STDIN VERS pipes[i-1].read_fd
            FIN SI

            SI i < n-1 ALORS
                REDIRIGER STDOUT VERS pipes[i].write_fd
            FIN SI

            FERMER TOUS LES PIPES DANS L'ENFANT
            EXECUTER cmds[i].argv AVEC execvp
        FIN SI
    FIN POUR

    FERMER TOUS LES PIPES DANS LE PARENT
    ATTENDRE TOUS LES ENFANTS
    RETOURNER LE CODE DE SORTIE DU DERNIER
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
PIPE UNIX : Structure de base
==============================

         pipefd[1]                pipefd[0]
          (write)                  (read)
            |                        |
            v                        v
    +-------+------------------------+-------+
    |       |     KERNEL BUFFER      |       |
    | Writer|     (64KB default)     | Reader|
    |   --> |  [================]    | -->   |
    |       |                        |       |
    +-------+------------------------+-------+

    write(pipefd[1], data, len)  ->  read(pipefd[0], buf, size)


PIPELINE : ls | grep | wc
=========================

Process 1        Pipe 1        Process 2        Pipe 2        Process 3
   (ls)          [===]          (grep)          [===]          (wc)
+--------+      +-----+       +--------+       +-----+       +--------+
|        |      |     |       |        |       |     |       |        |
| stdout-+----->|     |------>+-stdin  |       |     |       |        |
|        |      |     |       | stdout-+------>|     |------>+-stdin  |
+--------+      +-----+       +--------+       +-----+       | stdout-+---> terminal
                                                             +--------+


DUP2 : Redirection de FD
========================

Avant dup2(pipe_write, STDOUT_FILENO):
+------------------+
| FD Table         |
|   0 -> stdin     |
|   1 -> terminal  |  <-- stdout normal
|   2 -> terminal  |
|   3 -> pipe_read |
|   4 -> pipe_write|
+------------------+

Apres dup2(pipe_write, STDOUT_FILENO):
+------------------+
| FD Table         |
|   0 -> stdin     |
|   1 -> pipe_write|  <-- stdout redirige !
|   2 -> terminal  |
|   3 -> pipe_read |
|   4 -> pipe_write|
+------------------+

printf("Hello") -> va dans le pipe maintenant !


IMPORTANCE DE FERMER LES FD
===========================

Scenario: A ecrit, B lit via pipe

CORRECT:                          INCORRECT:
A ferme read_fd                   A garde read_fd ouvert
A ecrit puis ferme write_fd       A ecrit puis ferme write_fd
B ferme write_fd                  B garde write_fd ouvert
B lit jusqu'a EOF                 B lit...
B recoit EOF, termine             B attend indefiniment !
                                  (write_fd ouvert = pas d'EOF)

+---+     +-----+     +---+       +---+     +-----+     +---+
| A |---->|PIPE |---->| B |       | A |---->|PIPE |---->| B |
+---+     +-----+     +---+       +---+  ^  +-----+     +---+
  |_________|X|_________|             |__|     ^          |
     Fermes correctement                |_____|__________|
                                        FD non fermes = DEADLOCK
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 2 pipe` - Documentation de pipe()
- `man 2 dup2` - Documentation de dup2()
- "The Linux Programming Interface" - Chapitre sur les pipes
- `man 7 pipe` - Semantique des pipes

### 6.2 Commandes utiles

```bash
# Voir les file descriptors d'un processus
ls -la /proc/$$/fd

# Tester un pipeline
echo "test" | cat | wc -c

# Voir le buffer size d'un pipe
cat /proc/sys/fs/pipe-max-size

# Tracer les appels systeme
strace -e pipe,dup2,read,write ./mon_programme
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Creer** des pipes pour la communication inter-processus
2. **Utiliser** dup2() pour rediriger stdin/stdout
3. **Implementer** des pipelines de commandes (comme bash)
4. **Eviter** les deadlocks en fermant les FD correctement
5. **Gerer** les erreurs et le nettoyage des ressources

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.34 fork_exec | Prerequis pour comprendre les processus |
| 0.9.38 mmap | Alternative pour gros volumes de donnees |
| 0.9.40 sockets | Communication reseau (vs locale) |
| Shell (minishell) | Application complete des pipes |
