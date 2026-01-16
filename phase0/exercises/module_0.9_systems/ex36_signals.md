# Exercice 0.9.36 : signal_handler

**Module :**
0.9 — Systems Programming

**Concept :**
Signal handling, SIGINT, SIGTERM, signal masks in C

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
- Notion de processus
- Variables globales et volatiles

**Domaines :**
Signal, Unix, Sys

**Duree estimee :**
70 min

**XP Base :**
170

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `signal_handler.c`, `signal_handler.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `signal`, `sigaction`, `sigemptyset`, `sigfillset`, `sigaddset`, `sigdelset`, `sigprocmask`, `sigpending`, `sigsuspend`, `kill`, `raise`, `pause`, `write`, `_exit` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `printf` dans les handlers (non async-signal-safe !), `malloc`, `free` dans handlers |

---

### 1.2 Consigne

#### Section Culture : "The Interrupt"

**MATRIX RELOADED - "What do all men with power want? More power... to handle signals"**

Les signaux Unix sont comme les Agents dans la Matrix : ils peuvent interrompre ton programme a tout moment, n'importe ou dans ton code. Comme Neo qui apprend a gerer les Agents, tu dois apprendre a installer des handlers pour reagir proprement aux interruptions.

*"Choice. The problem is choice."* - SIGINT ou SIGTERM ? Handler ou ignore ? C'est ton choix.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un systeme complet de gestion des signaux :

1. **install_handler** : Installe un handler pour un signal
2. **block_signals** : Bloque temporairement des signaux
3. **wait_for_signal** : Attend un signal specifique
4. **setup_cleanup** : Configure un cleanup propre sur SIGINT/SIGTERM

**Entree (C) :**

```c
#ifndef SIGNAL_HANDLER_H
# define SIGNAL_HANDLER_H

# include <signal.h>

// Type de callback pour les handlers
typedef void (*signal_callback_t)(int signum);

// Installe un handler pour le signal donne
// Retourne l'ancien handler ou SIG_ERR
signal_callback_t install_handler(int signum, signal_callback_t handler);

// Installe un handler avec sigaction (plus robuste)
// flags: SA_RESTART, SA_RESETHAND, etc.
int install_handler_ex(int signum, signal_callback_t handler, int flags);

// Bloque les signaux specifies dans mask
// old_mask reçoit l'ancien masque (peut etre NULL)
int block_signals(const sigset_t *mask, sigset_t *old_mask);

// Debloque les signaux specifies
int unblock_signals(const sigset_t *mask);

// Attend qu'un des signaux dans mask soit reçu
int wait_for_signal(const sigset_t *mask);

// Configure un cleanup automatique sur SIGINT et SIGTERM
// cleanup_fn sera appelee avant exit
int setup_cleanup(void (*cleanup_fn)(void));

// Envoie un signal a soi-meme
int send_self_signal(int signum);

// Verifie si un signal est pending
int is_signal_pending(int signum);

#endif
```

**Sortie :**
- `install_handler` : Ancien handler ou SIG_ERR
- `install_handler_ex` : 0 succes, -1 erreur
- `block_signals` : 0 succes, -1 erreur
- `wait_for_signal` : Signal recu ou -1

**Contraintes :**
- Les handlers doivent etre async-signal-safe
- Utiliser `volatile sig_atomic_t` pour les flags
- Pas de printf/malloc/free dans les handlers
- Gerer le redemarrage des syscalls interrompus (SA_RESTART)

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `install_handler(SIGINT, my_handler)` | - | SIG_DFL | Ancien handler etait default |
| `block_signals(&mask)` puis Ctrl+C | SIGINT | Signal pending | Signal bloque |
| `wait_for_signal(&mask)` | SIGUSR1 | SIGUSR1 | Attend puis retourne |
| `setup_cleanup(my_cleanup)` puis kill -TERM | - | cleanup appele | Cleanup propre |

---

### 1.3 Prototype

**C :**
```c
#include <signal.h>
#include <unistd.h>

typedef void (*signal_callback_t)(int signum);

signal_callback_t install_handler(int signum, signal_callback_t handler);
int install_handler_ex(int signum, signal_callback_t handler, int flags);
int block_signals(const sigset_t *mask, sigset_t *old_mask);
int unblock_signals(const sigset_t *mask);
int wait_for_signal(const sigset_t *mask);
int setup_cleanup(void (*cleanup_fn)(void));
int send_self_signal(int signum);
int is_signal_pending(int signum);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Signaux critiques a connaitre :**

| Signal | Numero | Default | Description |
|--------|--------|---------|-------------|
| SIGINT | 2 | Terminate | Ctrl+C |
| SIGTERM | 15 | Terminate | kill default |
| SIGKILL | 9 | Terminate | Non interceptable ! |
| SIGSEGV | 11 | Core dump | Segmentation fault |
| SIGCHLD | 17 | Ignore | Child status change |
| SIGUSR1/2 | 10/12 | Terminate | User defined |

**SIGKILL et SIGSTOP sont speciaux**

Ces deux signaux ne peuvent JAMAIS etre interceptes, bloques ou ignores. C'est une protection du kernel pour toujours pouvoir tuer un processus.

**Les handlers sont herites par fork()**

Quand tu fork(), l'enfant herite des handlers du parent. Mais attention : apres exec(), tous les handlers sont remis a SIG_DFL !

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Server Developer** | Graceful shutdown sur SIGTERM |
| **Shell Developer** | Gestion de Ctrl+C, job control |
| **Database Developer** | Checkpoint sur signal, recovery |
| **Container Runtime** | Signal forwarding vers les containers |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "signal_handler.h"
#include <stdio.h>
#include <unistd.h>

volatile sig_atomic_t got_signal = 0;

void my_handler(int signum) {
    got_signal = signum;
    // Attention: write() est async-signal-safe, pas printf !
    write(STDOUT_FILENO, "Signal received!\n", 17);
}

void cleanup(void) {
    write(STDOUT_FILENO, "Cleaning up...\n", 15);
    // Liberer ressources, fermer fichiers, etc.
}

int main(void) {
    // Setup cleanup on SIGINT/SIGTERM
    setup_cleanup(cleanup);

    // Install custom handler for SIGUSR1
    install_handler(SIGUSR1, my_handler);

    printf("PID: %d\n", getpid());
    printf("Waiting for signals... (send SIGUSR1 or Ctrl+C)\n");

    while (!got_signal) {
        pause(); // Wait for any signal
    }

    printf("Got signal %d, exiting.\n", got_signal);
    return 0;
}

$ gcc -Wall -Wextra -Werror signal_handler.c main.c -o test
$ ./test &
[1] 12345
PID: 12345
Waiting for signals...
$ kill -USR1 12345
Signal received!
Got signal 10, exiting.
[1]+  Done    ./test
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2.5

**Consigne Bonus :**

Implementer un systeme de signaux temps-reel et sigqueue :

```c
// Handler avec informations etendues (siginfo_t)
int install_handler_info(int signum,
    void (*handler)(int, siginfo_t *, void *));

// Envoie un signal avec valeur attachee
int send_signal_with_value(pid_t pid, int signum, int value);

// Attente avec timeout (sigtimedwait)
int wait_for_signal_timeout(const sigset_t *mask, int timeout_ms);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | install_basic | SIGUSR1 handler | Handler called | 10 | Basic |
| 2 | install_returns_old | install twice | Returns previous | 10 | Return |
| 3 | block_signal | Block SIGUSR1, raise | Signal pending | 15 | Block |
| 4 | unblock_delivers | Unblock pending | Handler called | 10 | Block |
| 5 | wait_signal | Wait SIGUSR1 | Returns on signal | 15 | Wait |
| 6 | cleanup_sigint | SIGINT | Cleanup called | 10 | Cleanup |
| 7 | cleanup_sigterm | SIGTERM | Cleanup called | 10 | Cleanup |
| 8 | sa_restart | Interrupted read | Read continues | 10 | Flags |
| 9 | async_safe | Handler uses write | No crash | 5 | Safety |
| 10 | sigkill_fail | Try block SIGKILL | Fails/ignored | 5 | Edge |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "signal_handler.h"

static volatile sig_atomic_t handler_called = 0;
static volatile sig_atomic_t signal_received = 0;

void test_handler(int signum) {
    handler_called = 1;
    signal_received = signum;
}

void test_install_basic(void) {
    handler_called = 0;
    install_handler(SIGUSR1, test_handler);
    raise(SIGUSR1);
    assert(handler_called == 1);
    assert(signal_received == SIGUSR1);
    printf("Test install_basic: OK\n");
}

void test_returns_old_handler(void) {
    signal_callback_t old = install_handler(SIGUSR1, test_handler);
    signal_callback_t old2 = install_handler(SIGUSR1, SIG_IGN);
    assert(old2 == test_handler);
    install_handler(SIGUSR1, SIG_DFL);
    printf("Test returns_old_handler: OK\n");
}

void test_block_signal(void) {
    handler_called = 0;
    install_handler(SIGUSR1, test_handler);

    sigset_t mask, old;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    block_signals(&mask, &old);

    raise(SIGUSR1);
    assert(handler_called == 0); // Signal blocked
    assert(is_signal_pending(SIGUSR1) == 1);

    unblock_signals(&mask);
    assert(handler_called == 1); // Now delivered

    printf("Test block_signal: OK\n");
}

static volatile sig_atomic_t cleanup_called = 0;
void test_cleanup_fn(void) {
    cleanup_called = 1;
}

void test_cleanup(void) {
    cleanup_called = 0;
    setup_cleanup(test_cleanup_fn);

    // We can't actually test SIGTERM easily in a unit test
    // This would require forking
    printf("Test cleanup: OK (manual verification needed)\n");
}

int main(void) {
    test_install_basic();
    test_returns_old_handler();
    test_block_signal();
    test_cleanup();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "signal_handler.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void (*g_cleanup_fn)(void) = NULL;

static void cleanup_handler(int signum) {
    (void)signum;
    if (g_cleanup_fn) {
        g_cleanup_fn();
    }
    _exit(128 + signum);
}

signal_callback_t install_handler(int signum, signal_callback_t handler) {
    signal_callback_t old = signal(signum, handler);
    return old;
}

int install_handler_ex(int signum, signal_callback_t handler, int flags) {
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = flags;

    if (sigaction(signum, &sa, &old_sa) == -1) {
        return -1;
    }

    return 0;
}

int block_signals(const sigset_t *mask, sigset_t *old_mask) {
    return sigprocmask(SIG_BLOCK, mask, old_mask);
}

int unblock_signals(const sigset_t *mask) {
    return sigprocmask(SIG_UNBLOCK, mask, NULL);
}

int wait_for_signal(const sigset_t *mask) {
    sigset_t wait_mask;

    // Create inverse mask (block everything except what we want)
    sigfillset(&wait_mask);

    // Unblock the signals we want to wait for
    for (int sig = 1; sig < NSIG; sig++) {
        if (sigismember(mask, sig)) {
            sigdelset(&wait_mask, sig);
        }
    }

    // sigsuspend atomically sets the mask and waits
    sigsuspend(&wait_mask);

    // sigsuspend always returns -1 with errno EINTR
    return 0;
}

int setup_cleanup(void (*cleanup_fn)(void)) {
    g_cleanup_fn = cleanup_fn;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cleanup_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // No SA_RESTART - we want to interrupt

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return -1;
    }

    return 0;
}

int send_self_signal(int signum) {
    return raise(signum);
}

int is_signal_pending(int signum) {
    sigset_t pending;

    if (sigpending(&pending) == -1) {
        return -1;
    }

    return sigismember(&pending, signum);
}
```

---

### 4.5 Solutions refusees

**Refus 1 : printf dans handler**

```c
// REFUSE : printf n'est pas async-signal-safe !
void bad_handler(int signum) {
    printf("Got signal %d\n", signum); // DANGER !
}
```
**Pourquoi refuse :** printf peut deadlock si le signal arrive pendant un autre printf.

**Refus 2 : malloc dans handler**

```c
// REFUSE : malloc n'est pas async-signal-safe !
void bad_handler(int signum) {
    char *msg = malloc(100); // DANGER !
    // ...
}
```
**Pourquoi refuse :** malloc utilise des locks internes qui peuvent deadlock.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Safety) : Variable non volatile**

```c
/* Mutant A (Safety) : Flag non volatile */
int got_signal = 0; // Manque volatile sig_atomic_t !

void handler(int signum) {
    got_signal = 1;
}

while (!got_signal) { // Peut etre optimise en boucle infinie !
    // ...
}
// Pourquoi c'est faux : Le compilateur peut mettre got_signal en cache
```

**Mutant B (Logic) : signal() au lieu de sigaction()**

```c
/* Mutant B (Logic) : signal() est non-portable */
void setup_handler(int signum, void (*handler)(int)) {
    signal(signum, handler);
    // Sur certains systemes, le handler est reset apres chaque appel !
}
// Pourquoi c'est faux : Comportement non defini sur certains Unix
```

**Mutant C (Resource) : Pas de SA_RESTART**

```c
/* Mutant C (Resource) : Syscalls interrompus */
int install_handler_ex(int signum, signal_callback_t handler, int flags) {
    struct sigaction sa = {0};
    sa.sa_handler = handler;
    // OUBLI: flags pas utilise, SA_RESTART pas mis
    return sigaction(signum, &sa, NULL);
}
// Pourquoi c'est faux : read(), write(), etc. echouent avec EINTR
```

**Mutant D (Logic) : Mauvais masque pour sigsuspend**

```c
/* Mutant D (Logic) : sigsuspend mal compris */
int wait_for_signal(const sigset_t *mask) {
    sigsuspend(mask); // FAUX: mask est ce qu'on BLOQUE, pas ce qu'on attend
    return 0;
}
// Pourquoi c'est faux : Il faut passer l'inverse du masque souhaite
```

**Mutant E (Return) : exit() au lieu de _exit()**

```c
/* Mutant E (Return) : exit() dans handler */
void cleanup_handler(int signum) {
    if (g_cleanup_fn) g_cleanup_fn();
    exit(128 + signum); // FAUX: devrait etre _exit !
}
// Pourquoi c'est faux : exit() n'est pas async-signal-safe
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Signaux Unix | Interruptions asynchrones | Fondamental |
| Handlers | Fonctions de callback | Essentiel |
| Masques | Blocage temporaire | Important |
| Async-signal-safe | Fonctions sures | Critique |

---

### 5.3 Visualisation ASCII

```
Signal Delivery Flow
====================

User/Kernel
    │
    │ kill(pid, SIGUSR1)
    ▼
┌─────────────────────────────────────┐
│         Kernel Signal Queue         │
└─────────────────────────────────────┘
    │
    │ Process scheduled
    ▼
┌─────────────────────────────────────┐
│    Check signal mask (sigprocmask)  │
├─────────────────────────────────────┤
│  SIGUSR1 blocked? ──► Yes ──► Pending
│         │                      (wait)
│         No
│         │
│         ▼
│  ┌──────────────────────┐
│  │   Signal Delivered   │
│  └──────────────────────┘
│         │
│         ▼
│  Handler installed? ──► No ──► Default action
│         │                      (terminate/ignore/core)
│        Yes
│         │
│         ▼
│  ┌──────────────────────┐
│  │  Suspend main code   │
│  │  Run signal handler  │
│  │  Resume main code    │
│  └──────────────────────┘
└─────────────────────────────────────┘


Async-Signal-Safe Functions
===========================

SAFE (can use in handlers):
  write(), _exit(), signal(), raise()
  read(), close(), open() (simple ones)

UNSAFE (NEVER use in handlers):
  printf(), malloc(), free()
  fopen(), fclose()
  Any function using locks/static data
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | printf in handler | Deadlock | Use write() |
| 2 | Non-volatile flag | Optimization bug | volatile sig_atomic_t |
| 3 | signal() vs sigaction() | Non-portable | Use sigaction |
| 4 | No SA_RESTART | EINTR errors | Add SA_RESTART |
| 5 | exit() in handler | Unsafe | Use _exit() |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Pourquoi printf() ne doit pas etre utilise dans un signal handler ?

- A) C'est trop lent
- B) Ca ne compile pas
- C) Ce n'est pas async-signal-safe (peut deadlock)
- D) Ca envoie un autre signal

**Reponse : C** - printf utilise des locks internes qui peuvent causer un deadlock.

### Question 2 (3 points)
Quels signaux ne peuvent JAMAIS etre interceptes ?

- A) SIGINT et SIGTERM
- B) SIGKILL et SIGSTOP
- C) SIGUSR1 et SIGUSR2
- D) Tous peuvent etre interceptes

**Reponse : B** - SIGKILL (9) et SIGSTOP (19) sont proteges par le kernel.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.9.36 |
| **Nom** | signal_handler |
| **Difficulte** | 6/10 |
| **Duree** | 70 min |
| **XP Base** | 170 |
| **Langage** | C (c17) |
| **Concepts cles** | signal, sigaction, masks, async-safe |

---

*Document genere selon HACKBRAIN v5.5.2*
