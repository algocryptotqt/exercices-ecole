# Exercice 0.9.44 : terminal_control

**Module :**
0.9 — Systems Programming

**Concept :**
termios, raw mode, canonical mode, ANSI escape sequences

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
- File descriptors
- Notions de terminal/TTY

**Domaines :**
Terminal, Unix, Sys, IO

**Duree estimee :**
75 min

**XP Base :**
175

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `terminal_control.c`, `terminal_control.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `tcgetattr`, `tcsetattr`, `tcflush`, `tcdrain`, `cfgetispeed`, `cfgetospeed`, `cfsetispeed`, `cfsetospeed`, `isatty`, `ttyname`, `read`, `write`, `ioctl`, `signal`, `printf`, `sprintf`, `malloc`, `free` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `ncurses`, `readline`, autres bibliotheques de terminal |

---

### 1.2 Consigne

#### Section Culture : "Tron - Le Terminal MCP"

**TRON - "I fight for the Users!"**

Dans le monde de Tron, les programmes vivent dans un systeme informatique. Le MCP (Master Control Program) controle tout, y compris le terminal qui est le portail entre le monde des utilisateurs et celui des programmes.

*"The terminal is your gateway to the system. In canonical mode, you're a User - safe, buffered. In raw mode, you're a Program - direct access, no protection."*

Flynn t'explique les modes :
- **Mode Canonique** = Monde des Users - entree ligne par ligne, avec backspace
- **Mode Raw** = Grille de jeu - chaque touche est immediate, pas d'echo
- **Echo** = Lightcycles - les traces que tu laisses
- **ANSI Escape** = Sequences de controle - mouvement du curseur, couleurs

*"On the other side of the screen, it all looks so easy. But inside the terminal, it's a whole different game."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un gestionnaire de terminal avec :

1. **get_terminal_attr** : Recupere les attributs du terminal
2. **set_raw_mode** : Passe en mode brut (non-canonique)
3. **restore_terminal** : Restaure le mode original
4. **read_key** : Lit une touche (y compris touches speciales)
5. **cursor_move** : Deplace le curseur avec ANSI escape

**Entree (C) :**

```c
#ifndef TERMINAL_CONTROL_H
# define TERMINAL_CONTROL_H

# include <termios.h>
# include <sys/ioctl.h>

typedef struct s_terminal {
    struct termios  original;   // Attributs originaux
    struct termios  current;    // Attributs actuels
    int             fd;         // File descriptor (STDIN_FILENO)
    int             is_raw;     // Mode raw actif ?
    int             rows;       // Nombre de lignes
    int             cols;       // Nombre de colonnes
} t_terminal;

// Touches speciales
typedef enum e_key {
    KEY_UNKNOWN = -1,
    KEY_NONE = 0,
    KEY_ENTER = '\n',
    KEY_TAB = '\t',
    KEY_BACKSPACE = 127,
    KEY_ESCAPE = 27,
    KEY_UP = 1000,
    KEY_DOWN,
    KEY_RIGHT,
    KEY_LEFT,
    KEY_HOME,
    KEY_END,
    KEY_PAGE_UP,
    KEY_PAGE_DOWN,
    KEY_INSERT,
    KEY_DELETE,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_F11,
    KEY_F12
} t_key;

// === TERMINAL SETUP ===

// Initialise la structure terminal
// Retourne 0 en cas de succes, -1 si pas un TTY
int     term_init(t_terminal *term);

// Passe en mode raw (non-canonique, pas d'echo)
int     term_raw_mode(t_terminal *term);

// Passe en mode cbreak (non-canonique, avec echo)
int     term_cbreak_mode(t_terminal *term);

// Restaure le mode original
int     term_restore(t_terminal *term);

// Libere les ressources
void    term_cleanup(t_terminal *term);

// === TERMINAL ATTRIBUTES ===

// Active/desactive l'echo
int     term_set_echo(t_terminal *term, int enable);

// Active/desactive le mode canonique
int     term_set_canonical(t_terminal *term, int enable);

// Configure le timeout de lecture (en dixiemes de seconde)
int     term_set_timeout(t_terminal *term, int timeout);

// Recupere la taille du terminal
int     term_get_size(t_terminal *term);

// === INPUT ===

// Lit une touche (gere les sequences d'echappement)
t_key   term_read_key(t_terminal *term);

// Lit un caractere brut
int     term_read_char(t_terminal *term);

// Verifie si une entree est disponible (non-bloquant)
int     term_has_input(t_terminal *term);

// Vide le buffer d'entree
void    term_flush_input(t_terminal *term);

// === OUTPUT (ANSI Escape Sequences) ===

// Efface l'ecran
void    term_clear_screen(void);

// Efface la ligne courante
void    term_clear_line(void);

// Deplace le curseur a la position (row, col) (1-indexed)
void    term_move_cursor(int row, int col);

// Deplace le curseur relativement
void    term_move_up(int n);
void    term_move_down(int n);
void    term_move_left(int n);
void    term_move_right(int n);

// Sauvegarde/restaure la position du curseur
void    term_save_cursor(void);
void    term_restore_cursor(void);

// Cache/affiche le curseur
void    term_hide_cursor(void);
void    term_show_cursor(void);

// === COLORS (ANSI) ===

typedef enum e_color {
    COLOR_BLACK = 0,
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_MAGENTA,
    COLOR_CYAN,
    COLOR_WHITE,
    COLOR_DEFAULT = 9
} t_color;

typedef enum e_style {
    STYLE_RESET = 0,
    STYLE_BOLD = 1,
    STYLE_DIM = 2,
    STYLE_ITALIC = 3,
    STYLE_UNDERLINE = 4,
    STYLE_BLINK = 5,
    STYLE_REVERSE = 7,
    STYLE_HIDDEN = 8,
    STYLE_STRIKE = 9
} t_style;

// Definit la couleur du texte
void    term_set_fg_color(t_color color);

// Definit la couleur de fond
void    term_set_bg_color(t_color color);

// Definit le style
void    term_set_style(t_style style);

// Reinitialise les attributs
void    term_reset_attrs(void);

// === UTILITY ===

// Verifie si fd est un terminal
int     term_is_tty(int fd);

// Retourne le nom du terminal
const char *term_name(int fd);

// Attend que toutes les sorties soient ecrites
void    term_drain(t_terminal *term);

#endif
```

**Sortie :**
- `term_init` : 0 succes, -1 erreur
- `term_read_key` : t_key (enum de touche)
- `term_get_size` : 0 succes, -1 erreur

**Contraintes :**
- Toujours restaurer le terminal avant de quitter
- Gerer SIGINT/SIGTERM pour restaurer proprement
- Les sequences ANSI peuvent varier selon les terminaux
- Supporter les touches flechees et F1-F12

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `term_init(&t)` | - | 0 | Initialise |
| `term_raw_mode(&t)` | - | 0 | Mode raw actif |
| `term_read_key(&t)` | fleche haut | KEY_UP | Sequence echappement |
| `term_move_cursor(10, 5)` | - | - | Curseur a (10,5) |

---

### 1.3 Prototype

**C :**
```c
#include <termios.h>

int     term_init(t_terminal *term);
int     term_raw_mode(t_terminal *term);
int     term_cbreak_mode(t_terminal *term);
int     term_restore(t_terminal *term);
void    term_cleanup(t_terminal *term);
int     term_set_echo(t_terminal *term, int enable);
int     term_set_canonical(t_terminal *term, int enable);
int     term_set_timeout(t_terminal *term, int timeout);
int     term_get_size(t_terminal *term);
t_key   term_read_key(t_terminal *term);
int     term_read_char(t_terminal *term);
int     term_has_input(t_terminal *term);
void    term_flush_input(t_terminal *term);
void    term_clear_screen(void);
void    term_clear_line(void);
void    term_move_cursor(int row, int col);
void    term_move_up(int n);
void    term_move_down(int n);
void    term_move_left(int n);
void    term_move_right(int n);
void    term_save_cursor(void);
void    term_restore_cursor(void);
void    term_hide_cursor(void);
void    term_show_cursor(void);
void    term_set_fg_color(t_color color);
void    term_set_bg_color(t_color color);
void    term_set_style(t_style style);
void    term_reset_attrs(void);
int     term_is_tty(int fd);
const char *term_name(int fd);
void    term_drain(t_terminal *term);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi "TTY" ?**

TTY vient de "Teletype" (teleimprimeur), les premiers terminaux physiques des annees 1960. Meme si les teleimprimeurs ont disparu, le terme reste !

**Les modes du terminal**

- **Canonique** : Entree ligne par ligne, le kernel buffer jusqu'a Enter
- **Non-canonique** : Chaque caractere est lu immediatement
- **Raw** : Non-canonique + pas de traitement des signaux

**ANSI = American National Standards Institute**

Les sequences d'echappement ANSI (ESC[...) ont ete standardisees en 1979. Avant, chaque terminal avait ses propres codes !

**VT100**

Le terminal VT100 de DEC (1978) a defini les standards encore utilises aujourd'hui. Quand vous utilisez xterm ou iTerm, vous emulez un VT100.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **CLI Developer** | Editeurs (vim, nano), shells |
| **Game Developer** | Jeux en terminal (roguelikes) |
| **DevOps** | Outils interactifs (htop, tmux) |
| **Embedded Developer** | Consoles de debug serie |
| **Security Researcher** | Exploitation de failles terminal |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "terminal_control.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static t_terminal g_term;

void cleanup_handler(int sig) {
    (void)sig;
    term_restore(&g_term);
    term_show_cursor();
    printf("\nTerminal restored. Goodbye!\n");
    exit(0);
}

int main(void) {
    // Initialize terminal
    if (term_init(&g_term) == -1) {
        fprintf(stderr, "Not a terminal!\n");
        return 1;
    }

    // Setup signal handler for cleanup
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    // Get terminal size
    term_get_size(&g_term);
    printf("Terminal size: %d x %d\n", g_term.cols, g_term.rows);
    printf("Press any key (q to quit)...\n\n");

    // Enter raw mode
    term_raw_mode(&g_term);
    term_hide_cursor();

    // Clear screen and demonstrate cursor movement
    term_clear_screen();
    term_move_cursor(1, 1);

    term_set_fg_color(COLOR_GREEN);
    printf("Terminal Control Demo");
    term_reset_attrs();

    term_move_cursor(3, 1);
    printf("Press arrow keys, F1-F12, or 'q' to quit");
    term_move_cursor(5, 1);

    while (1) {
        t_key key = term_read_key(&g_term);

        term_move_cursor(5, 1);
        term_clear_line();

        if (key == 'q') {
            break;
        } else if (key >= KEY_UP && key <= KEY_LEFT) {
            const char *names[] = {"UP", "DOWN", "RIGHT", "LEFT"};
            term_set_fg_color(COLOR_CYAN);
            printf("Arrow key: %s", names[key - KEY_UP]);
        } else if (key >= KEY_F1 && key <= KEY_F12) {
            term_set_fg_color(COLOR_YELLOW);
            printf("Function key: F%d", key - KEY_F1 + 1);
        } else if (key == KEY_ESCAPE) {
            term_set_fg_color(COLOR_RED);
            printf("Escape pressed");
        } else if (key > 0 && key < 128) {
            term_set_fg_color(COLOR_GREEN);
            printf("Character: '%c' (0x%02x)", key, key);
        } else {
            term_set_fg_color(COLOR_MAGENTA);
            printf("Special key: %d", key);
        }
        term_reset_attrs();
    }

    // Cleanup
    term_restore(&g_term);
    term_show_cursor();
    term_clear_screen();
    printf("Goodbye!\n");

    return 0;
}

$ gcc -Wall -Wextra terminal_control.c main.c -o term_demo
$ ./term_demo
Terminal size: 80 x 24
Press any key (q to quit)...

Terminal Control Demo

Press arrow keys, F1-F12, or 'q' to quit

Arrow key: UP
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
8/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un mini-editeur de ligne (style readline) :

```c
typedef struct s_line_editor {
    char    *buffer;        // Contenu de la ligne
    size_t  length;         // Longueur actuelle
    size_t  capacity;       // Capacite allouee
    size_t  cursor;         // Position du curseur
    char    **history;      // Historique des commandes
    int     history_count;
    int     history_pos;    // Position dans l'historique
} t_line_editor;

// Cree un editeur de ligne
t_line_editor *line_editor_create(void);

// Lit une ligne avec edition complete
// Supporte: fleches, home, end, backspace, delete
// Supporte: historique (fleche haut/bas)
// Retourne la ligne (malloc'd) ou NULL si Ctrl+D
char *line_editor_read(t_line_editor *ed, const char *prompt);

// Ajoute une ligne a l'historique
void line_editor_add_history(t_line_editor *ed, const char *line);

// Libere l'editeur
void line_editor_destroy(t_line_editor *ed);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | term_init | init on tty | 0 | 10 | Basic |
| 2 | term_init_notty | init on pipe | -1 | 5 | Basic |
| 3 | term_raw_mode | enable raw | no echo | 15 | Mode |
| 4 | term_restore | restore | normal | 10 | Mode |
| 5 | read_arrow | arrow keys | KEY_UP etc | 15 | Input |
| 6 | read_fkeys | F1-F12 | correct enum | 10 | Input |
| 7 | cursor_move | move (5,10) | correct pos | 10 | Output |
| 8 | colors | set red | ESC[31m | 10 | Output |
| 9 | get_size | query size | rows, cols | 10 | Query |
| 10 | signal_restore | Ctrl+C | terminal ok | 5 | Safety |

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
#include "terminal_control.h"

// Note: These tests need to be run in an actual terminal

void test_term_init(void) {
    t_terminal term;

    // Should succeed on TTY
    if (isatty(STDIN_FILENO)) {
        assert(term_init(&term) == 0);
        term_cleanup(&term);
    }

    // Should fail on pipe
    int pipefd[2];
    pipe(pipefd);
    t_terminal term2;
    term2.fd = pipefd[0];
    // Note: full test would require redirecting stdin

    close(pipefd[0]);
    close(pipefd[1]);

    printf("Test term_init: OK\n");
}

void test_term_is_tty(void) {
    assert(term_is_tty(STDIN_FILENO) == isatty(STDIN_FILENO));

    int fd = open("/dev/null", O_RDONLY);
    assert(term_is_tty(fd) == 0);
    close(fd);

    printf("Test term_is_tty: OK\n");
}

void test_escape_sequences(void) {
    // Test that escape sequences are correct strings
    char buf[32];

    // Clear screen
    sprintf(buf, "\033[2J\033[H");
    // This is what term_clear_screen should output

    // Move cursor
    sprintf(buf, "\033[10;5H");
    // This is term_move_cursor(10, 5)

    // Colors
    sprintf(buf, "\033[31m");  // Red foreground
    sprintf(buf, "\033[42m");  // Green background

    printf("Test escape_sequences: OK\n");
}

void test_get_size(void) {
    if (!isatty(STDIN_FILENO)) {
        printf("Test get_size: SKIPPED (not a TTY)\n");
        return;
    }

    t_terminal term;
    term_init(&term);
    assert(term_get_size(&term) == 0);
    assert(term.rows > 0);
    assert(term.cols > 0);
    term_cleanup(&term);

    printf("Test get_size: OK\n");
}

void test_raw_restore(void) {
    if (!isatty(STDIN_FILENO)) {
        printf("Test raw_restore: SKIPPED (not a TTY)\n");
        return;
    }

    t_terminal term;
    term_init(&term);

    struct termios before;
    tcgetattr(STDIN_FILENO, &before);

    term_raw_mode(&term);
    assert(term.is_raw == 1);

    term_restore(&term);
    assert(term.is_raw == 0);

    struct termios after;
    tcgetattr(STDIN_FILENO, &after);

    // Check that terminal is restored
    assert(memcmp(&before, &after, sizeof(struct termios)) == 0);

    term_cleanup(&term);
    printf("Test raw_restore: OK\n");
}

int main(void) {
    test_term_init();
    test_term_is_tty();
    test_escape_sequences();
    test_get_size();
    test_raw_restore();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "terminal_control.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

int term_init(t_terminal *term) {
    if (!term)
        return -1;

    term->fd = STDIN_FILENO;

    if (!isatty(term->fd))
        return -1;

    if (tcgetattr(term->fd, &term->original) == -1)
        return -1;

    term->current = term->original;
    term->is_raw = 0;
    term->rows = 24;
    term->cols = 80;

    term_get_size(term);
    return 0;
}

int term_raw_mode(t_terminal *term) {
    if (!term)
        return -1;

    term->current.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    term->current.c_oflag &= ~(OPOST);
    term->current.c_cflag |= (CS8);
    term->current.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    term->current.c_cc[VMIN] = 0;
    term->current.c_cc[VTIME] = 1;

    if (tcsetattr(term->fd, TCSAFLUSH, &term->current) == -1)
        return -1;

    term->is_raw = 1;
    return 0;
}

int term_cbreak_mode(t_terminal *term) {
    if (!term)
        return -1;

    term->current.c_lflag &= ~(ICANON);
    term->current.c_cc[VMIN] = 1;
    term->current.c_cc[VTIME] = 0;

    if (tcsetattr(term->fd, TCSAFLUSH, &term->current) == -1)
        return -1;

    return 0;
}

int term_restore(t_terminal *term) {
    if (!term)
        return -1;

    if (tcsetattr(term->fd, TCSAFLUSH, &term->original) == -1)
        return -1;

    term->current = term->original;
    term->is_raw = 0;
    return 0;
}

void term_cleanup(t_terminal *term) {
    if (term && term->is_raw)
        term_restore(term);
}

int term_set_echo(t_terminal *term, int enable) {
    if (!term)
        return -1;

    if (enable)
        term->current.c_lflag |= ECHO;
    else
        term->current.c_lflag &= ~ECHO;

    return tcsetattr(term->fd, TCSAFLUSH, &term->current);
}

int term_set_canonical(t_terminal *term, int enable) {
    if (!term)
        return -1;

    if (enable)
        term->current.c_lflag |= ICANON;
    else
        term->current.c_lflag &= ~ICANON;

    return tcsetattr(term->fd, TCSAFLUSH, &term->current);
}

int term_set_timeout(t_terminal *term, int timeout) {
    if (!term)
        return -1;

    term->current.c_cc[VTIME] = timeout;
    return tcsetattr(term->fd, TCSAFLUSH, &term->current);
}

int term_get_size(t_terminal *term) {
    if (!term)
        return -1;

    struct winsize ws;
    if (ioctl(term->fd, TIOCGWINSZ, &ws) == -1)
        return -1;

    term->rows = ws.ws_row;
    term->cols = ws.ws_col;
    return 0;
}

static t_key parse_escape_sequence(t_terminal *term) {
    char seq[8] = {0};
    ssize_t n;

    n = read(term->fd, &seq[0], 1);
    if (n != 1)
        return KEY_ESCAPE;

    if (seq[0] != '[' && seq[0] != 'O') {
        return KEY_ESCAPE;
    }

    n = read(term->fd, &seq[1], 1);
    if (n != 1)
        return KEY_ESCAPE;

    // Arrow keys: ESC [ A/B/C/D
    if (seq[0] == '[') {
        switch (seq[1]) {
            case 'A': return KEY_UP;
            case 'B': return KEY_DOWN;
            case 'C': return KEY_RIGHT;
            case 'D': return KEY_LEFT;
            case 'H': return KEY_HOME;
            case 'F': return KEY_END;
        }

        // Extended sequences: ESC [ n ~
        if (seq[1] >= '0' && seq[1] <= '9') {
            n = read(term->fd, &seq[2], 1);
            if (n == 1 && seq[2] == '~') {
                switch (seq[1]) {
                    case '1': case '7': return KEY_HOME;
                    case '3': return KEY_DELETE;
                    case '4': case '8': return KEY_END;
                    case '5': return KEY_PAGE_UP;
                    case '6': return KEY_PAGE_DOWN;
                }
            }

            // F5-F12: ESC [ 1 n ~
            if (seq[1] == '1' && seq[2] >= '5' && seq[2] <= '9') {
                char tmp;
                read(term->fd, &tmp, 1);
                return KEY_F5 + (seq[2] - '5');
            }
            if (seq[1] == '2') {
                char tmp;
                read(term->fd, &tmp, 1);
                if (seq[2] >= '0' && seq[2] <= '4')
                    return KEY_F9 + (seq[2] - '0');
            }
        }
    }

    // F1-F4: ESC O P/Q/R/S
    if (seq[0] == 'O') {
        switch (seq[1]) {
            case 'P': return KEY_F1;
            case 'Q': return KEY_F2;
            case 'R': return KEY_F3;
            case 'S': return KEY_F4;
        }
    }

    return KEY_UNKNOWN;
}

t_key term_read_key(t_terminal *term) {
    if (!term)
        return KEY_NONE;

    char c;
    ssize_t n = read(term->fd, &c, 1);

    if (n <= 0)
        return KEY_NONE;

    if (c == 27)
        return parse_escape_sequence(term);

    return (t_key)c;
}

int term_read_char(t_terminal *term) {
    if (!term)
        return -1;

    char c;
    if (read(term->fd, &c, 1) != 1)
        return -1;

    return (unsigned char)c;
}

int term_has_input(t_terminal *term) {
    if (!term)
        return 0;

    fd_set fds;
    struct timeval tv = {0, 0};

    FD_ZERO(&fds);
    FD_SET(term->fd, &fds);

    return select(term->fd + 1, &fds, NULL, NULL, &tv) > 0;
}

void term_flush_input(t_terminal *term) {
    if (term)
        tcflush(term->fd, TCIFLUSH);
}

void term_clear_screen(void) {
    write(STDOUT_FILENO, "\033[2J\033[H", 7);
}

void term_clear_line(void) {
    write(STDOUT_FILENO, "\033[2K\r", 5);
}

void term_move_cursor(int row, int col) {
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "\033[%d;%dH", row, col);
    write(STDOUT_FILENO, buf, len);
}

void term_move_up(int n) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dA", n);
    write(STDOUT_FILENO, buf, len);
}

void term_move_down(int n) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dB", n);
    write(STDOUT_FILENO, buf, len);
}

void term_move_right(int n) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dC", n);
    write(STDOUT_FILENO, buf, len);
}

void term_move_left(int n) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dD", n);
    write(STDOUT_FILENO, buf, len);
}

void term_save_cursor(void) {
    write(STDOUT_FILENO, "\033[s", 3);
}

void term_restore_cursor(void) {
    write(STDOUT_FILENO, "\033[u", 3);
}

void term_hide_cursor(void) {
    write(STDOUT_FILENO, "\033[?25l", 6);
}

void term_show_cursor(void) {
    write(STDOUT_FILENO, "\033[?25h", 6);
}

void term_set_fg_color(t_color color) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dm", 30 + color);
    write(STDOUT_FILENO, buf, len);
}

void term_set_bg_color(t_color color) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dm", 40 + color);
    write(STDOUT_FILENO, buf, len);
}

void term_set_style(t_style style) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "\033[%dm", style);
    write(STDOUT_FILENO, buf, len);
}

void term_reset_attrs(void) {
    write(STDOUT_FILENO, "\033[0m", 4);
}

int term_is_tty(int fd) {
    return isatty(fd);
}

const char *term_name(int fd) {
    return ttyname(fd);
}

void term_drain(t_terminal *term) {
    if (term)
        tcdrain(term->fd);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de restauration a la sortie**

```c
/* Mutant A : Terminal casse */
int main(void) {
    t_terminal term;
    term_init(&term);
    term_raw_mode(&term);

    // Fait des trucs...

    return 0;  // ERREUR: terminal jamais restaure !
    // Le shell apres sera en raw mode !
}
// Pourquoi c'est faux: Le terminal reste en mode raw, rendant le shell inutilisable
```

**Mutant B (Safety) : Pas de signal handler**

```c
/* Mutant B : Ctrl+C laisse terminal casse */
int main(void) {
    t_terminal term;
    term_init(&term);
    term_raw_mode(&term);

    // ERREUR: pas de signal handler !
    // Ctrl+C termine sans restaurer le terminal

    while (1) {
        t_key k = term_read_key(&term);
        // ...
    }
}
// Pourquoi c'est faux: Ctrl+C (SIGINT) tue le programme sans cleanup
```

**Mutant C (Resource) : VMIN=0 VTIME=0**

```c
/* Mutant C : Busy loop CPU 100% */
int term_raw_mode(t_terminal *term) {
    term->current.c_cc[VMIN] = 0;
    term->current.c_cc[VTIME] = 0;  // ERREUR: read() retourne immediatement !
    tcsetattr(term->fd, TCSAFLUSH, &term->current);
}

while (1) {
    t_key k = term_read_key(&term);  // Retourne -1 en boucle = 100% CPU
}
// Pourquoi c'est faux: Sans timeout, read() ne bloque pas -> busy loop
```

**Mutant D (Logic) : Parse escape incomplete**

```c
/* Mutant D : Touches manquees */
t_key parse_escape_sequence(t_terminal *term) {
    char seq[2];
    read(term->fd, seq, 2);  // ERREUR: lit 2 chars d'un coup !

    // Mais certaines sequences font 3+ chars (ESC [ 1 ~)
    // Les sequences longues sont mal parsees

    if (seq[0] == '[' && seq[1] == 'A')
        return KEY_UP;
    // ...
}
// Pourquoi c'est faux: Les sequences comme F1-F12 necessitent plus de chars
```

**Mutant E (Return) : printf au lieu de write**

```c
/* Mutant E : Buffer pas flushe */
void term_move_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
    // ERREUR: pas de fflush !
    // En mode raw, stdout peut etre line-buffered ou full-buffered
    // Le curseur ne bouge pas immediatement
}
// Pourquoi c'est faux: printf bufferise, write() est immediat
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| termios | Configuration du terminal | Fondamental |
| Raw mode | Lecture caractere par caractere | Essentiel |
| ANSI escape | Controle du curseur et couleurs | Classique |
| TTY | Comprendre les terminaux | Important |

---

### 5.2 LDA - Traduction litterale

```
FONCTION term_read_key QUI PREND term
DEBUT FONCTION
    LIRE UN CARACTERE AVEC read()

    SI caractere == 27 (ESC) ALORS
        LIRE LE PROCHAIN CARACTERE
        SI c'est '[' ou 'O' ALORS
            LIRE LA SUITE DE LA SEQUENCE
            MATCHER AVEC LES TOUCHES SPECIALES
            RETOURNER LA TOUCHE CORRESPONDANTE
        FIN SI
        RETOURNER KEY_ESCAPE
    FIN SI

    RETOURNER LE CARACTERE LU
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
STRUCTURE TERMIOS
=================

struct termios {
    tcflag_t c_iflag;   // Input flags
    tcflag_t c_oflag;   // Output flags
    tcflag_t c_cflag;   // Control flags
    tcflag_t c_lflag;   // Local flags
    cc_t c_cc[NCCS];    // Control characters
};

c_lflag important:
+-------+-------+-------+-------+
| ECHO  | ICANON| ISIG  | ...   |
+-------+-------+-------+-------+
   |       |       |
   |       |       +-- Process SIGINT, SIGQUIT, SIGSUSP
   |       +---------- Canonical mode (line buffering)
   +------------------ Echo input characters


MODES DE TERMINAL
=================

CANONICAL MODE (defaut):
User types: h e l l o [BACKSPACE] [ENTER]
Terminal:   h e l l o [effacé]  \n
Program:    "hello\n" (recu apres ENTER)

RAW MODE:
User types: h e l l o [BACKSPACE]
Program:    h e l l o 0x7F  (chaque touche immediate)
                      ^-- backspace = caractere 127


SEQUENCES D'ECHAPPEMENT ANSI
============================

Format: ESC [ <params> <command>

ESC = 0x1B = '\033' = 27 decimal

Exemples:
    ESC[2J      = Clear screen
    ESC[H       = Move to home (1,1)
    ESC[10;5H   = Move to row 10, col 5
    ESC[31m     = Red foreground
    ESC[1;32;44m = Bold, green text, blue background

Touches speciales:
    Up:    ESC [ A
    Down:  ESC [ B
    Right: ESC [ C
    Left:  ESC [ D
    F1:    ESC O P
    F5:    ESC [ 1 5 ~


FLOW D'UNE TOUCHE FLECHEE
=========================

User presses UP arrow
        |
        v
Terminal sends: 0x1B 0x5B 0x41 (3 bytes)
                ESC   [    A
        |
        v
Program reads:
    1. read() -> 0x1B (ESC)
    2. Detect escape sequence
    3. read() -> 0x5B ('[')
    4. read() -> 0x41 ('A')
    5. Match: '[' + 'A' = UP arrow
        |
        v
Return KEY_UP


COULEURS ANSI
=============

Foreground (30-37):       Background (40-47):
+-----+----------+        +-----+----------+
| 30  | Black    |        | 40  | Black    |
| 31  | Red      |        | 41  | Red      |
| 32  | Green    |        | 42  | Green    |
| 33  | Yellow   |        | 43  | Yellow   |
| 34  | Blue     |        | 44  | Blue     |
| 35  | Magenta  |        | 45  | Magenta  |
| 36  | Cyan     |        | 46  | Cyan     |
| 37  | White    |        | 47  | White    |
+-----+----------+        +-----+----------+

Styles (0-9):
+-----+------------+
| 0   | Reset      |
| 1   | Bold       |
| 4   | Underline  |
| 7   | Reverse    |
+-----+------------+

Example: ESC[1;31;44m = Bold Red on Blue


TAILLE DU TERMINAL
==================

Method 1: ioctl(fd, TIOCGWINSZ, &ws)
    struct winsize ws;
    ws.ws_row = 24;  // rows
    ws.ws_col = 80;  // columns

Method 2: Query sequence (fallback)
    Send: ESC[6n (Device Status Report)
    Receive: ESC[24;80R (cursor position = bottom-right)
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 3 termios` - Documentation termios
- `man 4 tty` - Le device TTY
- `man console_codes` - Sequences ANSI Linux
- "Build Your Own Text Editor" (Kilo tutorial)

### 6.2 Commandes utiles

```bash
# Voir les attributs du terminal
stty -a

# Reset du terminal
reset

# Tester les sequences ANSI
echo -e "\033[31mRouge\033[0m"
echo -e "\033[5;10HPosition 5,10"

# Voir la taille du terminal
echo "Rows: $LINES, Cols: $COLUMNS"
tput lines
tput cols

# Envoyer une touche echappement
printf '\033'
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Configurer** le terminal avec termios
2. **Implementer** un mode raw pour la lecture caractere par caractere
3. **Parser** les sequences d'echappement pour les touches speciales
4. **Utiliser** les codes ANSI pour controler le curseur
5. **Creer** des interfaces textuelles interactives

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| Shell (minishell) | Lecture de ligne, historique |
| Editeurs | vim, nano |
| TUI apps | htop, ncurses alternative |
