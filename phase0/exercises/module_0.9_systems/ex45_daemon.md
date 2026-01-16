# Exercice 0.9.45 : daemon_creator

**Module :**
0.9 — Systems Programming

**Concept :**
fork(), setsid(), chdir(), close(), daemon creation, background processes

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
- fork() et processus (ex34)
- Signaux (ex36)
- File descriptors

**Domaines :**
Process, Unix, Sys, Server

**Duree estimee :**
60 min

**XP Base :**
150

**Complexite :**
T2 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `daemon_creator.c`, `daemon_creator.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `fork`, `setsid`, `chdir`, `umask`, `close`, `open`, `dup2`, `getpid`, `signal`, `sigaction`, `sigemptyset`, `sigaddset`, `sigprocmask`, `fopen`, `fclose`, `fprintf`, `fflush`, `unlink`, `stat`, `syslog`, `openlog`, `closelog`, `sleep`, `usleep`, `exit`, `_exit`, `perror`, `printf` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `daemon()` (fonction BSD, tu dois l'implementer!) |

---

### 1.2 Consigne

#### Section Culture : "The Matrix - Agent Smith, le Daemon"

**THE MATRIX - "I'm going to enjoy watching you die, Mr. Anderson... again and again."**

Dans la Matrice, l'Agent Smith est un daemon - un programme qui s'execute en arriere-plan, sans interface utilisateur, surveillant et intervenant dans le systeme. Comme un vrai daemon Unix, il :

- S'execute independamment de tout terminal
- Se reproduit (fork) pour gerer plusieurs taches
- Surveille le systeme en permanence
- Ecrit des logs pour le systeme central

*"You hear that, Mr. Anderson? That is the sound of inevitability. It is the sound of your process being daemonized."*

Morpheus t'explique le processus de daemonisation :
1. **Premier fork** = Se detacher du terminal parent
2. **setsid()** = Devenir le leader d'une nouvelle session
3. **Second fork** = S'assurer de ne jamais reacquerir de terminal
4. **chdir("/")** = Ne pas bloquer un systeme de fichiers
5. **Fermer stdin/stdout/stderr** = Independance complete

*"There is no terminal. Then you'll see, it is not the TTY that controls you, it is only yourself."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un framework de creation de daemons :

1. **daemonize** : Transforme le processus courant en daemon
2. **create_pidfile** : Cree un fichier PID
3. **setup_signals** : Configure les gestionnaires de signaux
4. **daemon_log** : Log via syslog
5. **cleanup** : Nettoyage propre a l'arret

**Entree (C) :**

```c
#ifndef DAEMON_CREATOR_H
# define DAEMON_CREATOR_H

# include <sys/types.h>
# include <signal.h>
# include <syslog.h>

typedef struct s_daemon_config {
    const char  *name;          // Nom du daemon
    const char  *pidfile;       // Chemin du fichier PID
    const char  *workdir;       // Repertoire de travail (default: "/")
    const char  *logfile;       // Fichier de log (ou NULL pour syslog)
    mode_t      umask;          // Masque de creation de fichiers
    int         use_syslog;     // Utiliser syslog ?
    int         log_level;      // Niveau de log (LOG_DEBUG, LOG_INFO, etc.)
} t_daemon_config;

typedef struct s_daemon {
    t_daemon_config config;
    pid_t           pid;
    int             running;        // Flag pour boucle principale
    int             reload;         // Flag pour rechargement config
    void            (*main_loop)(struct s_daemon *);  // Fonction principale
    void            (*on_reload)(struct s_daemon *);  // Callback SIGHUP
    void            (*on_shutdown)(struct s_daemon *); // Callback SIGTERM
    void            *user_data;     // Donnees utilisateur
} t_daemon;

// === DAEMONIZATION ===

// Transforme le processus en daemon
// Retourne 0 en cas de succes, -1 en cas d'erreur
// ATTENTION: Ne retourne que dans le processus daemon !
int     daemonize(void);

// Version complete avec configuration
int     daemonize_full(const t_daemon_config *config);

// Double-fork method (traditionnelle)
int     daemonize_double_fork(void);

// === PID FILE ===

// Cree le fichier PID
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     create_pidfile(const char *path);

// Verifie si un daemon avec ce pidfile est deja en cours
// Retourne le PID si existe, 0 sinon, -1 en cas d'erreur
pid_t   check_pidfile(const char *path);

// Supprime le fichier PID
int     remove_pidfile(const char *path);

// === SIGNAL HANDLING ===

// Configure les signaux standards pour un daemon
// SIGTERM -> arret propre
// SIGHUP -> rechargement config
// SIGCHLD -> reap children
int     setup_daemon_signals(t_daemon *daemon);

// Bloque les signaux pendant une section critique
void    block_signals(sigset_t *oldmask);

// Restaure les signaux
void    unblock_signals(sigset_t *oldmask);

// === LOGGING ===

// Initialise le logging
int     daemon_log_init(t_daemon *daemon);

// Log un message
void    daemon_log(t_daemon *daemon, int priority, const char *fmt, ...);

// Ferme le logging
void    daemon_log_close(t_daemon *daemon);

// === DAEMON LIFECYCLE ===

// Initialise la structure daemon
int     daemon_init(t_daemon *daemon, const t_daemon_config *config);

// Demarre le daemon
// Ne retourne que si le daemon s'arrete
int     daemon_start(t_daemon *daemon);

// Demande l'arret du daemon
void    daemon_stop(t_daemon *daemon);

// Demande le rechargement de la configuration
void    daemon_reload(t_daemon *daemon);

// Nettoyage final
void    daemon_cleanup(t_daemon *daemon);

// === UTILITY ===

// Redirige stdin, stdout, stderr vers /dev/null
int     redirect_std_fds(void);

// Ferme tous les file descriptors sauf ceux specifies
int     close_all_fds(int *except, int except_count);

// Change le repertoire de travail
int     change_workdir(const char *path);

// Configure le umask
mode_t  set_daemon_umask(mode_t mask);

// Verifie si le processus est un daemon (no controlling tty)
int     is_daemon(void);

#endif
```

**Sortie :**
- `daemonize` : 0 succes (dans le daemon), -1 erreur
- `create_pidfile` : 0 succes, -1 erreur
- `check_pidfile` : PID existant, 0 si pas de daemon, -1 erreur
- `daemon_start` : code de sortie

**Contraintes :**
- Gerer correctement le double-fork
- Fermer tous les file descriptors herites
- Creer un fichier PID pour eviter les instances multiples
- Logger les evenements importants
- Gerer SIGTERM et SIGHUP proprement

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `daemonize()` | - | 0 | Processus daemonise |
| `create_pidfile("/var/run/myapp.pid")` | - | 0 | PID ecrit |
| `check_pidfile("/var/run/myapp.pid")` | - | 12345 | Daemon deja actif |
| `daemon_stop(&d)` | - | - | Flag running = 0 |

---

### 1.3 Prototype

**C :**
```c
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

int     daemonize(void);
int     daemonize_full(const t_daemon_config *config);
int     daemonize_double_fork(void);
int     create_pidfile(const char *path);
pid_t   check_pidfile(const char *path);
int     remove_pidfile(const char *path);
int     setup_daemon_signals(t_daemon *daemon);
void    block_signals(sigset_t *oldmask);
void    unblock_signals(sigset_t *oldmask);
int     daemon_log_init(t_daemon *daemon);
void    daemon_log(t_daemon *daemon, int priority, const char *fmt, ...);
void    daemon_log_close(t_daemon *daemon);
int     daemon_init(t_daemon *daemon, const t_daemon_config *config);
int     daemon_start(t_daemon *daemon);
void    daemon_stop(t_daemon *daemon);
void    daemon_reload(t_daemon *daemon);
void    daemon_cleanup(t_daemon *daemon);
int     redirect_std_fds(void);
int     close_all_fds(int *except, int except_count);
int     change_workdir(const char *path);
mode_t  set_daemon_umask(mode_t mask);
int     is_daemon(void);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi "daemon" ?**

Le terme vient des "Maxwell's demons" en physique - des entites hypothetiques qui travaillent en arriere-plan. En informatique, les daemons sont des processus qui "travaillent dans l'ombre" sans interaction utilisateur.

**Le double-fork**

Pourquoi deux fork() ?
1. Premier fork : le parent peut terminer, l'enfant continue
2. setsid() : l'enfant devient leader de session
3. Second fork : le petit-enfant ne peut JAMAIS reacquerir un terminal (il n'est pas leader de session)

**systemd vs SysV init**

Les vieux daemons (SysV) se daemonisent eux-memes. systemd prefere que les services restent en foreground - il gere lui-meme le daemonisation. C'est pourquoi on voit `Type=simple` vs `Type=forking`.

**Le fichier PID**

Le fichier PID sert a :
1. Eviter les instances multiples
2. Permettre `kill $(cat /var/run/myapp.pid)`
3. Verifier si le daemon tourne

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **SysAdmin** | Services systeme, cron, sshd |
| **Backend Developer** | Serveurs web, workers |
| **DevOps Engineer** | Agents de monitoring |
| **Database Admin** | MySQL, PostgreSQL daemons |
| **Security Engineer** | Antivirus, IDS daemons |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat example_daemon.c
#include "daemon_creator.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

static void my_main_loop(t_daemon *d) {
    int counter = 0;

    while (d->running) {
        daemon_log(d, LOG_INFO, "Heartbeat #%d", ++counter);

        if (d->reload) {
            daemon_log(d, LOG_NOTICE, "Reloading configuration...");
            // Recharger la config ici
            d->reload = 0;
        }

        sleep(5);
    }

    daemon_log(d, LOG_NOTICE, "Shutdown requested, cleaning up...");
}

static void on_shutdown(t_daemon *d) {
    daemon_log(d, LOG_NOTICE, "Received SIGTERM, initiating shutdown");
}

static void on_reload(t_daemon *d) {
    daemon_log(d, LOG_NOTICE, "Received SIGHUP, will reload config");
}

int main(void) {
    t_daemon_config config = {
        .name = "example_daemon",
        .pidfile = "/tmp/example_daemon.pid",
        .workdir = "/tmp",
        .logfile = NULL,  // Use syslog
        .umask = 022,
        .use_syslog = 1,
        .log_level = LOG_DEBUG
    };

    // Check if already running
    pid_t existing = check_pidfile(config.pidfile);
    if (existing > 0) {
        fprintf(stderr, "Daemon already running with PID %d\n", existing);
        return 1;
    }

    printf("Starting daemon...\n");

    t_daemon daemon;
    daemon_init(&daemon, &config);
    daemon.main_loop = my_main_loop;
    daemon.on_shutdown = on_shutdown;
    daemon.on_reload = on_reload;

    // Daemonize (this returns only in the daemon process)
    if (daemonize_full(&config) == -1) {
        perror("daemonize");
        return 1;
    }

    // Now running as daemon
    create_pidfile(config.pidfile);
    setup_daemon_signals(&daemon);
    daemon_log_init(&daemon);

    daemon_log(&daemon, LOG_NOTICE, "Daemon started with PID %d", getpid());

    // Run main loop
    daemon_start(&daemon);

    // Cleanup
    daemon_log(&daemon, LOG_NOTICE, "Daemon stopped");
    daemon_cleanup(&daemon);
    remove_pidfile(config.pidfile);

    return 0;
}

$ gcc -Wall -Wextra daemon_creator.c example_daemon.c -o mydaemon
$ ./mydaemon
Starting daemon...
$ # Process returns immediately, daemon running in background

$ cat /tmp/example_daemon.pid
12345

$ ps aux | grep example_daemon
user     12345  0.0  0.0  4500  800 ?        Ss   10:00   0:00 ./mydaemon

$ tail -f /var/log/syslog | grep example_daemon
Jan 16 10:00:01 host example_daemon[12345]: Daemon started with PID 12345
Jan 16 10:00:06 host example_daemon[12345]: Heartbeat #1
Jan 16 10:00:11 host example_daemon[12345]: Heartbeat #2

$ kill -HUP 12345
$ tail /var/log/syslog
Jan 16 10:00:15 host example_daemon[12345]: Received SIGHUP, will reload config
Jan 16 10:00:16 host example_daemon[12345]: Reloading configuration...

$ kill 12345
$ tail /var/log/syslog
Jan 16 10:00:20 host example_daemon[12345]: Received SIGTERM, initiating shutdown
Jan 16 10:00:20 host example_daemon[12345]: Shutdown requested, cleaning up...
Jan 16 10:00:20 host example_daemon[12345]: Daemon stopped

$ cat /tmp/example_daemon.pid
cat: /tmp/example_daemon.pid: No such file or directory
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un superviseur de processus simple :

```c
typedef enum e_restart_policy {
    RESTART_NEVER,      // Ne jamais redemarrer
    RESTART_ALWAYS,     // Toujours redemarrer
    RESTART_ON_FAILURE  // Redemarrer si exit code != 0
} t_restart_policy;

typedef struct s_supervised_process {
    char            *name;
    char            **argv;
    char            **envp;
    pid_t           pid;
    int             status;
    t_restart_policy policy;
    int             restart_count;
    int             max_restarts;
    time_t          last_start;
} t_supervised_process;

typedef struct s_supervisor {
    t_daemon                *daemon;
    t_supervised_process    **processes;
    int                     process_count;
} t_supervisor;

// Cree un superviseur
t_supervisor *supervisor_create(t_daemon *daemon);

// Ajoute un processus a superviser
int supervisor_add(t_supervisor *sup, const char *name, char **argv,
                   t_restart_policy policy);

// Demarre tous les processus
int supervisor_start_all(t_supervisor *sup);

// Boucle principale de supervision
void supervisor_loop(t_supervisor *sup);

// Arrete tous les processus
void supervisor_stop_all(t_supervisor *sup);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | daemonize | daemonize() | runs in bg | 15 | Basic |
| 2 | no_tty | after daemonize | no ctty | 10 | Basic |
| 3 | pidfile | create/check | works | 10 | PID |
| 4 | pidfile_lock | two instances | second fails | 10 | PID |
| 5 | sigterm | send SIGTERM | clean stop | 10 | Signal |
| 6 | sighup | send SIGHUP | reload flag | 10 | Signal |
| 7 | redirect_fds | std fds | to /dev/null | 10 | FD |
| 8 | chdir_root | after daemon | cwd = / | 5 | Setup |
| 9 | syslog | daemon_log | appears in log | 10 | Log |
| 10 | cleanup | on stop | pidfile removed | 10 | Cleanup |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include "daemon_creator.h"

#define TEST_PIDFILE "/tmp/test_daemon.pid"

void test_daemonize(void) {
    pid_t pid = fork();

    if (pid == 0) {
        // Child: will daemonize
        if (daemonize() == 0) {
            // Now running as daemon
            create_pidfile(TEST_PIDFILE);
            sleep(2);
            remove_pidfile(TEST_PIDFILE);
            _exit(0);
        }
        _exit(1);
    }

    // Parent: wait a bit and check
    sleep(1);
    pid_t daemon_pid = check_pidfile(TEST_PIDFILE);
    assert(daemon_pid > 0);

    // Verify it's actually daemonized (different PID from child)
    assert(daemon_pid != pid);

    // Clean up
    kill(daemon_pid, SIGTERM);
    sleep(1);
    assert(check_pidfile(TEST_PIDFILE) == 0);

    // Wait for original child
    waitpid(pid, NULL, WNOHANG);

    printf("Test daemonize: OK\n");
}

void test_pidfile(void) {
    const char *path = "/tmp/test_pid.pid";

    // Create pidfile
    assert(create_pidfile(path) == 0);

    // Check it exists with our PID
    pid_t p = check_pidfile(path);
    assert(p == getpid());

    // Remove it
    assert(remove_pidfile(path) == 0);

    // Check it's gone
    assert(check_pidfile(path) == 0);

    printf("Test pidfile: OK\n");
}

void test_redirect_fds(void) {
    // Save original fds
    int saved_stdin = dup(STDIN_FILENO);
    int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);

    assert(redirect_std_fds() == 0);

    // Verify stdin is now /dev/null
    char buf[1];
    assert(read(STDIN_FILENO, buf, 1) == 0);  // EOF from /dev/null

    // Restore for further tests
    dup2(saved_stdin, STDIN_FILENO);
    dup2(saved_stdout, STDOUT_FILENO);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdin);
    close(saved_stdout);
    close(saved_stderr);

    printf("Test redirect_fds: OK\n");
}

void test_is_daemon(void) {
    // We have a controlling terminal, so not a daemon
    assert(is_daemon() == 0);

    printf("Test is_daemon: OK\n");
}

void test_set_umask(void) {
    mode_t old = set_daemon_umask(077);
    mode_t current = umask(0);
    umask(current);

    assert(current == 077);

    // Restore
    set_daemon_umask(old);

    printf("Test set_umask: OK\n");
}

void test_change_workdir(void) {
    char original[PATH_MAX];
    getcwd(original, sizeof(original));

    assert(change_workdir("/tmp") == 0);

    char current[PATH_MAX];
    getcwd(current, sizeof(current));
    assert(strcmp(current, "/tmp") == 0);

    // Restore
    chdir(original);

    printf("Test change_workdir: OK\n");
}

int main(void) {
    test_pidfile();
    test_redirect_fds();
    test_is_daemon();
    test_set_umask();
    test_change_workdir();
    test_daemonize();  // This one forks, run last

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "daemon_creator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static t_daemon *g_daemon = NULL;

int daemonize(void) {
    // First fork
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);  // Parent exits

    // Create new session
    if (setsid() < 0)
        return -1;

    // Second fork (optional but recommended)
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);  // First child exits

    // Now running as daemon (grandchild)

    // Change working directory
    chdir("/");

    // Reset umask
    umask(0);

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect to /dev/null
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2)
            close(fd);
    }

    return 0;
}

int daemonize_full(const t_daemon_config *config) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);

    if (setsid() < 0)
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);

    if (config->workdir)
        chdir(config->workdir);
    else
        chdir("/");

    umask(config->umask);

    redirect_std_fds();

    return 0;
}

int daemonize_double_fork(void) {
    return daemonize();
}

int create_pidfile(const char *path) {
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());

    if (write(fd, buf, len) != len) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

pid_t check_pidfile(const char *path) {
    if (!path)
        return -1;

    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        return 0;
    }
    fclose(f);

    // Check if process exists
    if (kill(pid, 0) == 0)
        return pid;

    if (errno == ESRCH) {
        // Process doesn't exist, stale pidfile
        return 0;
    }

    return pid;  // Process exists but we can't signal it
}

int remove_pidfile(const char *path) {
    if (!path)
        return -1;
    return unlink(path);
}

static void signal_handler(int sig) {
    if (!g_daemon)
        return;

    switch (sig) {
        case SIGTERM:
        case SIGINT:
            g_daemon->running = 0;
            if (g_daemon->on_shutdown)
                g_daemon->on_shutdown(g_daemon);
            break;

        case SIGHUP:
            g_daemon->reload = 1;
            if (g_daemon->on_reload)
                g_daemon->on_reload(g_daemon);
            break;

        case SIGCHLD:
            // Reap children
            while (waitpid(-1, NULL, WNOHANG) > 0)
                ;
            break;
    }
}

int setup_daemon_signals(t_daemon *daemon) {
    if (!daemon)
        return -1;

    g_daemon = daemon;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    // Ignore SIGPIPE
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    return 0;
}

void block_signals(sigset_t *oldmask) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, oldmask);
}

void unblock_signals(sigset_t *oldmask) {
    sigprocmask(SIG_SETMASK, oldmask, NULL);
}

int daemon_log_init(t_daemon *daemon) {
    if (!daemon)
        return -1;

    if (daemon->config.use_syslog) {
        openlog(daemon->config.name, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    return 0;
}

void daemon_log(t_daemon *daemon, int priority, const char *fmt, ...) {
    if (!daemon || !fmt)
        return;

    va_list ap;
    va_start(ap, fmt);

    if (daemon->config.use_syslog) {
        vsyslog(priority, fmt, ap);
    } else if (daemon->config.logfile) {
        FILE *f = fopen(daemon->config.logfile, "a");
        if (f) {
            time_t now = time(NULL);
            char timebuf[64];
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
                    localtime(&now));
            fprintf(f, "[%s] ", timebuf);
            vfprintf(f, fmt, ap);
            fprintf(f, "\n");
            fclose(f);
        }
    }

    va_end(ap);
}

void daemon_log_close(t_daemon *daemon) {
    if (daemon && daemon->config.use_syslog) {
        closelog();
    }
}

int daemon_init(t_daemon *daemon, const t_daemon_config *config) {
    if (!daemon || !config)
        return -1;

    memset(daemon, 0, sizeof(t_daemon));
    daemon->config = *config;
    daemon->pid = getpid();
    daemon->running = 1;
    daemon->reload = 0;

    return 0;
}

int daemon_start(t_daemon *daemon) {
    if (!daemon || !daemon->main_loop)
        return -1;

    daemon->running = 1;
    daemon->main_loop(daemon);

    return 0;
}

void daemon_stop(t_daemon *daemon) {
    if (daemon)
        daemon->running = 0;
}

void daemon_reload(t_daemon *daemon) {
    if (daemon)
        daemon->reload = 1;
}

void daemon_cleanup(t_daemon *daemon) {
    if (!daemon)
        return;

    daemon_log_close(daemon);
    g_daemon = NULL;
}

int redirect_std_fds(void) {
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return -1;

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    if (fd > 2)
        close(fd);

    return 0;
}

int close_all_fds(int *except, int except_count) {
    int max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0)
        max_fd = 1024;

    for (int fd = 3; fd < max_fd; fd++) {
        int keep = 0;
        for (int i = 0; i < except_count; i++) {
            if (except[i] == fd) {
                keep = 1;
                break;
            }
        }
        if (!keep)
            close(fd);
    }

    return 0;
}

int change_workdir(const char *path) {
    if (!path)
        return chdir("/");
    return chdir(path);
}

mode_t set_daemon_umask(mode_t mask) {
    return umask(mask);
}

int is_daemon(void) {
    // Check if we have a controlling terminal
    int fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
        // No controlling terminal = daemon
        return 1;
    }
    close(fd);
    return 0;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Un seul fork**

```c
/* Mutant A : Peut reacquerir un terminal */
int daemonize(void) {
    pid_t pid = fork();
    if (pid > 0) exit(0);

    setsid();
    // ERREUR: pas de second fork !
    // Ce processus est leader de session et peut
    // reacquerir un terminal en ouvrant un TTY

    return 0;
}
// Pourquoi c'est faux: Leader de session peut obtenir un controlling tty
```

**Mutant B (Safety) : exit() au lieu de _exit()**

```c
/* Mutant B : Flush des buffers parent */
int daemonize(void) {
    pid_t pid = fork();
    if (pid > 0)
        exit(0);  // ERREUR: flush stdio !
    // ...
}
// Si le parent a des donnees bufferisees, elles seront ecrites
// deux fois (une fois dans le parent, une fois dans l'enfant)
// Pourquoi c'est faux: exit() appelle les handlers atexit et flush stdio
```

**Mutant C (Resource) : Pas de fermeture des FD**

```c
/* Mutant C : FD leaks */
int daemonize(void) {
    fork(); setsid(); fork();
    chdir("/");
    umask(0);
    // ERREUR: stdin/stdout/stderr pas fermes !
    // Ils pointent encore vers le terminal d'origine
    return 0;
}
// Pourquoi c'est faux: Les FD herites peuvent bloquer le terminal
// ou causer des ecritures inattendues
```

**Mutant D (Logic) : setsid() avant fork()**

```c
/* Mutant D : setsid echoue */
int daemonize(void) {
    setsid();  // ERREUR: on est deja leader de groupe !
    // setsid() echoue si le processus est deja leader
    pid_t pid = fork();
    // ...
}
// Pourquoi c'est faux: setsid() doit etre appele par un non-leader
// Le premier fork() permet de s'assurer qu'on n'est pas leader
```

**Mutant E (Return) : Pas de gestion SIGCHLD**

```c
/* Mutant E : Zombies */
int setup_daemon_signals(t_daemon *daemon) {
    signal(SIGTERM, handler);
    signal(SIGHUP, handler);
    // ERREUR: SIGCHLD pas gere !
    // Les enfants fork() deviennent zombies
}
// Pourquoi c'est faux: Sans reap des enfants, accumulation de zombies
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| fork()/setsid() | Detachement du terminal | Fondamental |
| Double-fork | Empecher l'acquisition de TTY | Essentiel |
| Fichier PID | Eviter les instances multiples | Important |
| Signaux | SIGTERM, SIGHUP pour controle | Essentiel |

---

### 5.2 LDA - Traduction litterale

```
FONCTION daemonize
DEBUT FONCTION
    PREMIER FORK
    SI PARENT ALORS
        TERMINER AVEC _exit(0)
    FIN SI

    APPELER setsid() POUR CREER UNE NOUVELLE SESSION
    (Le processus devient leader de session)

    SECOND FORK
    SI PREMIER ENFANT (nouveau parent) ALORS
        TERMINER AVEC _exit(0)
    FIN SI

    (Maintenant le petit-enfant tourne, pas leader de session)

    CHANGER LE REPERTOIRE DE TRAVAIL VERS "/"
    REINITIALISER umask A 0

    FERMER stdin, stdout, stderr
    LES REDIRIGER VERS /dev/null

    RETOURNER 0 (succes, dans le daemon)
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
PROCESSUS DE DAEMONISATION
==========================

Terminal
    |
    v
+----------------+
| Parent Process |  PID=1000, PGID=1000, SID=1000
|   main()       |  Has controlling TTY
+----------------+
    |
    | fork()
    |
    +-------> Parent exits (_exit)
    |
    v
+----------------+
| Child Process  |  PID=1001, PGID=1000, SID=1000
|                |  Still same session
+----------------+
    |
    | setsid()
    |
    v
+----------------+
| Session Leader |  PID=1001, PGID=1001, SID=1001
|                |  New session, NO controlling TTY
|                |  But COULD acquire one (is leader)
+----------------+
    |
    | fork() (second)
    |
    +-------> First child exits (_exit)
    |
    v
+----------------+
| DAEMON         |  PID=1002, PGID=1001, SID=1001
|                |  Not session leader
|                |  CANNOT acquire controlling TTY
+----------------+


POURQUOI DOUBLE-FORK ?
======================

Seul un "session leader" peut ouvrir un terminal de controle.
Apres setsid(), le processus EST session leader.

         Scenario sans second fork:
         +---------+
         | Daemon  |  <- Session leader (SID=PID)
         | setsid()|
         +---------+
              |
              | open("/dev/tty...")
              v
         Acquiert un terminal de controle !


         Scenario avec second fork:
         +---------+
         | Daemon  |  <- PAS session leader (SID != PID)
         | child   |
         +---------+
              |
              | open("/dev/tty...")
              v
         Impossible ! (pas leader)


FICHIER PID
===========

/var/run/myapp.pid:
+--------+
|  1234  |
+--------+

Utilisations:
1. Demarrage:
   - Lire le fichier
   - Si PID existe et processus actif -> erreur "deja en cours"
   - Sinon -> creer/ecraser avec notre PID

2. Arret:
   kill $(cat /var/run/myapp.pid)

3. Status:
   if kill -0 $(cat /var/run/myapp.pid) 2>/dev/null; then
       echo "Running"
   else
       echo "Stopped"
   fi


SIGNAUX POUR DAEMONS
====================

SIGTERM (15):  Arret propre
               daemon->running = 0
               Finir la boucle, cleanup, exit

SIGHUP (1):    Rechargement de configuration
               daemon->reload = 1
               Relire config sans redemarrer

SIGINT (2):    Comme SIGTERM (souvent ignore)

SIGCHLD (17):  Un enfant a termine
               while (waitpid(-1, NULL, WNOHANG) > 0);
               Evite les zombies


CYCLE DE VIE D'UN DAEMON
========================

     +--------+
     | Start  |
     +--------+
          |
          v
     +--------+
     |Daemonize|  fork -> setsid -> fork -> redirect fds
     +--------+
          |
          v
     +--------+
     | Setup  |  Create PID file, setup signals
     +--------+
          |
          v
    +----------+
    | Main Loop|<---+
    |          |    |
    | (work)   |----+
    |          |    ^
    +----------+    | SIGHUP: reload
          |
          | SIGTERM
          v
    +----------+
    | Cleanup  |  Remove PID file, close resources
    +----------+
          |
          v
     +--------+
     |  Exit  |
     +--------+
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 7 daemon` - Guide de creation de daemons
- `man 3 syslog` - Logging systeme
- `man 2 setsid` - Creation de session
- "Advanced Programming in the UNIX Environment" - Stevens

### 6.2 Commandes utiles

```bash
# Voir les processus daemon
ps aux | grep -v '\[' | awk '$7 == "?" {print}'

# Voir la session et le groupe de processus
ps -o pid,ppid,pgid,sid,tty,comm

# Envoyer SIGHUP a un daemon
kill -HUP $(cat /var/run/myapp.pid)

# Voir les logs syslog
tail -f /var/log/syslog | grep myapp
journalctl -u myapp -f

# Verifier si un processus a un terminal
ls -la /proc/PID/fd/0
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Comprendre** le processus de daemonisation Unix
2. **Implementer** un daemon avec double-fork
3. **Gerer** les fichiers PID pour eviter les instances multiples
4. **Configurer** les signaux pour controle propre
5. **Utiliser** syslog pour le logging

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.34 fork_exec | Base du fork() |
| 0.9.36 signals | Gestion SIGTERM/SIGHUP |
| 0.9.40 sockets | Serveurs daemon |
| systemd | Integration moderne |
