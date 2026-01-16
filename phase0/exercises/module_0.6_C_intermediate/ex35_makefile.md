# Exercice 0.6.12-a : makefile

**Module :**
0.6.12 — Systeme de Build

**Concept :**
a-c — targets, dependencies, variables

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5 (bases C), ligne de commande

**Domaines :**
Build, Tooling, DevOps

**Duree estimee :**
120 min

**XP Base :**
200

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `Makefile`

**Outils autorises :**
- `make`, `gcc`, `rm`, `ar`

### 1.2 Consigne

Creer un Makefile complet pour un projet C avec gestion des dependances, compilation separee et cibles multiples.

**Ta mission :**

Ecrire un Makefile professionnel qui automatise la compilation d'un projet C avec les bonnes pratiques.

**Structure du projet :**
```
project/
├── Makefile
├── src/
│   ├── main.c
│   ├── utils.c
│   └── math_ops.c
├── include/
│   ├── utils.h
│   └── math_ops.h
├── tests/
│   └── test_main.c
└── obj/
    └── (fichiers .o generes)
```

**Cibles requises :**
```makefile
all        # Compile le programme principal (defaut)
$(NAME)    # Le binaire final (ex: myprogram)
clean      # Supprime les fichiers objets
fclean     # clean + supprime le binaire
re         # fclean + all
test       # Compile et execute les tests
debug      # Compile avec symboles de debug (-g)
release    # Compile avec optimisations (-O2)
lib        # Cree une bibliotheque statique (.a)
install    # Copie le binaire vers /usr/local/bin
help       # Affiche l'aide
```

**Variables requises :**
```makefile
NAME       # Nom du binaire
CC         # Compilateur (gcc)
CFLAGS     # Flags de compilation
LDFLAGS    # Flags de linkage
SRC_DIR    # Dossier sources
OBJ_DIR    # Dossier objets
INC_DIR    # Dossier headers
SRC        # Liste des fichiers source
OBJ        # Liste des fichiers objet
```

**Comportement :**
- Compilation separee (un .o par .c)
- Recompilation uniquement si fichier modifie
- Creation automatique du dossier obj/
- Affichage des commandes executees
- Support des headers (dependances)

**Exemple d'utilisation :**
```bash
make            # Compile tout
make clean      # Nettoie les .o
make fclean     # Nettoie tout
make re         # Recompile tout
make debug      # Version debug
make test       # Lance les tests
make help       # Affiche l'aide
```

**Contraintes :**
- Utiliser des variables pour eviter la repetition
- Utiliser des regles pattern (%.o: %.c)
- Declarer les cibles PHONY
- Indentation avec TAB (pas espaces!)
- Compiler avec `-Wall -Wextra -Werror -std=c17`

### 1.3 Prototype

```makefile
# Makefile minimal attendu

NAME = myprogram

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c17
LDFLAGS =

SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean fclean re test debug release help

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Variables automatiques

| Variable | Signification |
|----------|---------------|
| `$@` | Cible actuelle |
| `$<` | Premiere dependance |
| `$^` | Toutes les dependances |
| `$*` | Stem du pattern (%) |

### 2.2 Fonctions make

```makefile
$(wildcard *.c)      # Liste les fichiers .c
$(patsubst %.c,%.o,$(SRC))  # Remplace .c par .o
$(addprefix dir/,$(FILES))  # Ajoute prefixe
$(notdir $(SRC))     # Enleve le chemin
$(basename $(FILE))  # Enleve l'extension
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Build Engineer**

Make est utilise dans:
- Compilation de noyaux (Linux Kernel)
- Projets open source (GNU tools)
- Systemes embarques

**Metier : DevOps**

Alternatives modernes:
- CMake (generation multi-plateforme)
- Meson (moderne, rapide)
- Ninja (execution rapide)
- Bazel (Google, grands projets)

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls -la
total 16
drwxr-xr-x 5 user user 4096 Jan 15 10:00 .
drwxr-xr-x 3 user user 4096 Jan 15 09:00 ..
-rw-r--r-- 1 user user 1234 Jan 15 10:00 Makefile
drwxr-xr-x 2 user user 4096 Jan 15 10:00 include
drwxr-xr-x 2 user user 4096 Jan 15 10:00 src

$ make
mkdir -p obj
gcc -Wall -Wextra -Werror -std=c17 -Iinclude -c src/main.c -o obj/main.o
gcc -Wall -Wextra -Werror -std=c17 -Iinclude -c src/utils.c -o obj/utils.o
gcc -Wall -Wextra -Werror -std=c17 -Iinclude -c src/math_ops.c -o obj/math_ops.o
gcc -Wall -Wextra -Werror -std=c17 obj/main.o obj/utils.o obj/math_ops.o -o myprogram

$ ./myprogram
Hello from myprogram!

$ make clean
rm -rf obj

$ make debug
mkdir -p obj
gcc -Wall -Wextra -Werror -std=c17 -g -Iinclude -c src/main.c -o obj/main.o
gcc -Wall -Wextra -Werror -std=c17 -g -Iinclude -c src/utils.c -o obj/utils.o
gcc -Wall -Wextra -Werror -std=c17 -g -Iinclude -c src/math_ops.c -o obj/math_ops.o
gcc -Wall -Wextra -Werror -std=c17 -g obj/main.o obj/utils.o obj/math_ops.o -o myprogram

$ make help
Available targets:
  all      - Build the program (default)
  clean    - Remove object files
  fclean   - Remove all generated files
  re       - Rebuild everything
  test     - Build and run tests
  debug    - Build with debug symbols
  release  - Build with optimizations
  help     - Show this help

$ make fclean && make re
rm -rf obj
rm -f myprogram
mkdir -p obj
gcc -Wall -Wextra -Werror -std=c17 -Iinclude -c src/main.c -o obj/main.o
[...]
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Ajouter des fonctionnalites avancees au Makefile.

```makefile
# Generation automatique des dependances headers
DEPS = $(OBJ:.o=.d)
-include $(DEPS)
CFLAGS += -MMD -MP

# Support de la compilation parallele
# make -j4

# Cible pour la documentation (Doxygen)
doc:
	doxygen Doxyfile

# Cible pour l'analyse statique
lint:
	cppcheck --enable=all $(SRC_DIR)

# Cible pour le formatage du code
format:
	clang-format -i $(SRC_DIR)/*.c $(INC_DIR)/*.h

# Variables conditionnelles
ifdef VERBOSE
	Q =
else
	Q = @
endif
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Commande | Expected | Points |
|---------|-------------|----------|----------|--------|
| T01 | make compile | make | binaire cree | 15 |
| T02 | make clean | make clean | obj/ supprime | 10 |
| T03 | make fclean | make fclean | tout supprime | 10 |
| T04 | make re | make re | recompile tout | 10 |
| T05 | recompile partiel | touch src/utils.c && make | seul utils.o | 15 |
| T06 | PHONY declares | grep PHONY | present | 10 |
| T07 | variables utilisees | grep CC | present | 10 |
| T08 | debug flag | make debug | -g present | 10 |
| T09 | help target | make help | affiche aide | 10 |

### 4.2 Script de test

```bash
#!/bin/bash

pass=0
fail=0

# Setup
mkdir -p src include
cat > src/main.c << 'EOF'
#include <stdio.h>
int main(void) { printf("Hello!\n"); return 0; }
EOF

# T01: make compile
make > /dev/null 2>&1
if [ -f "myprogram" ]; then
    echo "T01 PASS: make creates binary"
    ((pass++))
else
    echo "T01 FAIL: binary not created"
    ((fail++))
fi

# T02: make clean
make clean > /dev/null 2>&1
if [ ! -d "obj" ] || [ -z "$(ls -A obj 2>/dev/null)" ]; then
    echo "T02 PASS: make clean removes objects"
    ((pass++))
else
    echo "T02 FAIL: objects not removed"
    ((fail++))
fi

# T03: make fclean
make > /dev/null 2>&1
make fclean > /dev/null 2>&1
if [ ! -f "myprogram" ]; then
    echo "T03 PASS: make fclean removes binary"
    ((pass++))
else
    echo "T03 FAIL: binary not removed"
    ((fail++))
fi

# T04: make re
make > /dev/null 2>&1
touch src/main.c
make re 2>&1 | grep -q "main.c"
if [ $? -eq 0 ]; then
    echo "T04 PASS: make re recompiles"
    ((pass++))
else
    echo "T04 FAIL: re doesn't recompile"
    ((fail++))
fi

# T05: partial recompile
make > /dev/null 2>&1
sleep 1
touch src/main.c
output=$(make 2>&1)
if echo "$output" | grep -q "main.o" && ! echo "$output" | grep -q "utils.o"; then
    echo "T05 PASS: partial recompile works"
    ((pass++))
else
    echo "T05 FAIL: recompiles too much or too little"
    ((fail++))
fi

# T06: PHONY declared
if grep -q "\.PHONY" Makefile; then
    echo "T06 PASS: .PHONY declared"
    ((pass++))
else
    echo "T06 FAIL: .PHONY missing"
    ((fail++))
fi

# T07: variables used
if grep -q "^CC" Makefile && grep -q "^CFLAGS" Makefile; then
    echo "T07 PASS: variables declared"
    ((pass++))
else
    echo "T07 FAIL: variables missing"
    ((fail++))
fi

# T08: debug flag
make fclean > /dev/null 2>&1
output=$(make debug 2>&1)
if echo "$output" | grep -q "\-g"; then
    echo "T08 PASS: debug adds -g flag"
    ((pass++))
else
    echo "T08 FAIL: debug missing -g"
    ((fail++))
fi

# T09: help target
output=$(make help 2>&1)
if echo "$output" | grep -iq "clean\|target\|help"; then
    echo "T09 PASS: help displays info"
    ((pass++))
else
    echo "T09 FAIL: help not working"
    ((fail++))
fi

# Cleanup
make fclean > /dev/null 2>&1
rm -rf src include

echo ""
echo "Results: $pass passed, $fail failed"
exit $fail
```

### 4.3 Solution de reference

```makefile
# **************************************************************************** #
#                                                                              #
#    Makefile                                                                  #
#                                                                              #
#    Exercice ex35_makefile                                                    #
#                                                                              #
# **************************************************************************** #

# Program name
NAME = myprogram

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c17
LDFLAGS =
LDLIBS =

# Directories
SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include
TEST_DIR = tests

# Source files
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Test files
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJ = $(TEST_SRC:$(TEST_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_NAME = test_runner

# Library
LIB_NAME = lib$(NAME).a
LIB_OBJ = $(filter-out $(OBJ_DIR)/main.o, $(OBJ))

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
RESET = \033[0m

# **************************************************************************** #
#                                 RULES                                        #
# **************************************************************************** #

.PHONY: all clean fclean re test debug release lib install uninstall help

# Default target
all: $(NAME)

# Link the program
$(NAME): $(OBJ)
	@echo "$(GREEN)Linking $(NAME)...$(RESET)"
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS) $(LDLIBS)
	@echo "$(GREEN)Build complete!$(RESET)"

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Compile test files
$(OBJ_DIR)/%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling test $<..."
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Create object directory
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

# Clean object files
clean:
	@echo "$(RED)Cleaning object files...$(RESET)"
	rm -rf $(OBJ_DIR)

# Full clean
fclean: clean
	@echo "$(RED)Cleaning binaries...$(RESET)"
	rm -f $(NAME) $(TEST_NAME) $(LIB_NAME)

# Rebuild
re: fclean all

# Build and run tests
test: CFLAGS += -g
test: $(TEST_OBJ) $(LIB_OBJ) | $(OBJ_DIR)
	@echo "$(GREEN)Building tests...$(RESET)"
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIB_OBJ) -o $(TEST_NAME) $(LDFLAGS) $(LDLIBS)
	@echo "$(GREEN)Running tests...$(RESET)"
	./$(TEST_NAME)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: re

# Release build
release: CFLAGS += -O2 -DNDEBUG
release: re

# Create static library
lib: $(LIB_OBJ)
	@echo "$(GREEN)Creating library $(LIB_NAME)...$(RESET)"
	ar rcs $(LIB_NAME) $(LIB_OBJ)
	@echo "$(GREEN)Library created!$(RESET)"

# Install to system
install: $(NAME)
	@echo "Installing to /usr/local/bin..."
	install -m 755 $(NAME) /usr/local/bin/

# Uninstall from system
uninstall:
	@echo "Uninstalling from /usr/local/bin..."
	rm -f /usr/local/bin/$(NAME)

# Help
help:
	@echo "Available targets:"
	@echo "  all      - Build the program (default)"
	@echo "  clean    - Remove object files"
	@echo "  fclean   - Remove all generated files"
	@echo "  re       - Rebuild everything"
	@echo "  test     - Build and run tests"
	@echo "  debug    - Build with debug symbols (-g)"
	@echo "  release  - Build with optimizations (-O2)"
	@echo "  lib      - Create static library"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  help     - Show this help"
```

### 4.4 Solutions alternatives acceptees

```makefile
# Alternative 1: Sans wildcard (liste explicite)
SRC = src/main.c src/utils.c src/math_ops.c

# Alternative 2: Avec VPATH
VPATH = src:include
vpath %.c src
vpath %.h include

# Alternative 3: Dependances headers manuelles
$(OBJ_DIR)/main.o: src/main.c include/utils.h include/math_ops.h
$(OBJ_DIR)/utils.o: src/utils.c include/utils.h
```

### 4.5 Solutions refusees (avec explications)

```makefile
# REFUSE 1: Indentation avec espaces
all:
    gcc ...  # Espaces au lieu de TAB!
# Raison: make requiert TAB pour les recettes

# REFUSE 2: Pas de PHONY
all: $(NAME)
clean:
    rm -rf obj
# Raison: Si fichier "clean" existe, cible jamais executee

# REFUSE 3: Recompilation complete a chaque fois
$(NAME): $(SRC)
    gcc $(SRC) -o $(NAME)
# Raison: Pas de compilation separee, tout recompile
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.12-a",
  "name": "makefile",
  "version": "1.0.0",
  "language": "makefile",
  "language_version": "gnu-make-4.3",
  "files": {
    "submission": ["Makefile"],
    "test": ["test_makefile.sh"]
  },
  "compilation": {
    "compiler": "make",
    "flags": []
  },
  "tests": {
    "type": "script",
    "valgrind": false
  },
  "scoring": {
    "total": 100,
    "targets": 50,
    "variables": 20,
    "best_practices": 30
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```makefile
# MUTANT 1 (Syntax): Espaces au lieu de TAB
all:
    $(CC) ...  # ERREUR: espace!
# Detection: make: *** missing separator

# MUTANT 2 (Logic): Dependance cyclique
all: clean
clean: all
# Detection: make: Circular dependency

# MUTANT 3 (Logic): Pas de prerequis OBJ_DIR
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
    $(CC) ...
# Detection: Erreur si obj/ n'existe pas

# MUTANT 4 (Typo): Variable mal nommee
$(NAME): $(OBJS)  # OBJS au lieu de OBJ
    $(CC) $(OBJS) -o $(NAME)
# Detection: Linkage sans fichiers objets

# MUTANT 5 (Order): fclean avant clean
fclean:
    rm -f $(NAME)
clean: fclean  # Ordre inverse!
    rm -rf $(OBJ_DIR)
# Detection: clean supprime plus que prevu
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux de Make** :

1. **Targets** - Cibles a construire
2. **Dependencies** - Fichiers requis
3. **Variables** - Eviter la repetition

### 5.2 LDA - Traduction Litterale en Francais

```
CIBLE: DEPENDANCES
    RECETTE (commandes)

ALGORITHME Make:
DEBUT
    POUR CHAQUE cible demandee FAIRE
        SI cible n'existe pas OU dependance plus recente ALORS
            executer_recette(cible)
        FIN SI
    FIN POUR
FIN

EXEMPLE:
programme: main.o utils.o
    gcc main.o utils.o -o programme

main.o: main.c utils.h
    gcc -c main.c -o main.o
```

### 5.3 Visualisation ASCII

```
GRAPHE DE DEPENDANCES
=====================

         myprogram
             |
     +-------+-------+
     |       |       |
  main.o  utils.o  math.o
     |       |       |
  main.c  utils.c  math.c
     |       |       |
     +---+---+-------+
         |
    utils.h, math.h

EXECUTION DE MAKE
=================

$ make myprogram

1. Verifier myprogram existe?
   -> Non, continuer

2. Verifier dependances:
   - main.o existe? Non -> compiler main.c
   - utils.o existe? Non -> compiler utils.c
   - math.o existe? Non -> compiler math.c

3. Toutes dependances OK
   -> Linker en myprogram

RECOMPILATION PARTIELLE
=======================

$ touch utils.c  # Modifie utils.c
$ make

1. myprogram existe, verifier dependances
2. main.o: main.c pas modifie -> skip
3. utils.o: utils.c modifie -> recompiler
4. math.o: math.c pas modifie -> skip
5. Dependance modifiee -> re-linker myprogram

Seuls utils.o et myprogram sont reconstruits!
```

### 5.4 Les pieges en detail

#### Piege 1: TAB vs Espaces
```makefile
# FAUX - erreur de syntaxe
all:
    gcc ...   # Espaces!

# CORRECT - TAB requis
all:
	gcc ...   # TAB!
```

#### Piege 2: Oublier .PHONY
```makefile
# FAUX - si fichier "clean" existe, jamais execute
clean:
	rm -f *.o

# CORRECT
.PHONY: clean
clean:
	rm -f *.o
```

#### Piege 3: Ordre des dependances
```makefile
# FAUX - obj/ cree trop tard
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $< -o $@  # obj/ n'existe peut-etre pas!

# CORRECT - order-only prerequisite
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)
```

### 5.5 Cours Complet

#### 5.5.1 Structure d'une regle

```makefile
cible: dependances
	recette
```

- **cible**: fichier a creer ou action a executer
- **dependances**: fichiers requis
- **recette**: commandes shell (DOIVENT commencer par TAB)

#### 5.5.2 Variables

```makefile
# Definition
CC = gcc
CFLAGS = -Wall -Werror

# Utilisation
$(CC) $(CFLAGS) -c $<

# Variables automatiques
$@  # Cible
$<  # Premiere dependance
$^  # Toutes les dependances
$*  # Stem du pattern match
```

#### 5.5.3 Pattern rules

```makefile
# Compile tout .c en .o
%.o: %.c
	$(CC) -c $< -o $@

# Equivalent a:
# main.o: main.c
# 	$(CC) -c main.c -o main.o
# utils.o: utils.c
# 	$(CC) -c utils.c -o utils.o
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Utiliser TAB | Syntaxe make | `<TAB>$(CC) ...` |
| Declarer PHONY | Actions sans fichier | `.PHONY: clean` |
| Variables pour DRY | Eviter repetition | `CC = gcc` |
| Compilation separee | Recompilation partielle | `%.o: %.c` |

### 5.7 Simulation avec trace d'execution

```
$ make myprogram

1. Parse Makefile
   - Variables: CC=gcc, CFLAGS=-Wall...
   - Cibles: all, myprogram, %.o, clean...

2. Construire graphe de dependances pour "myprogram"
   myprogram -> [main.o, utils.o, math.o]
   main.o -> [main.c]
   utils.o -> [utils.c]
   math.o -> [math.c]

3. Tri topologique (ordre de construction)
   [main.c, utils.c, math.c] -> [main.o, utils.o, math.o] -> [myprogram]

4. Execution
   $ mkdir -p obj
   $ gcc -Wall -c src/main.c -o obj/main.o
   $ gcc -Wall -c src/utils.c -o obj/utils.o
   $ gcc -Wall -c src/math.c -o obj/math.o
   $ gcc -Wall obj/main.o obj/utils.o obj/math.o -o myprogram

5. Termine avec succes
```

### 5.8 Mnemotechniques

**"TDR" - Structure d'une regle**
- **T**arget (cible)
- **D**ependencies (prerequis)
- **R**ecipe (recette avec TAB)

**"Variables automatiques CATF"**
- **C**ible: `$@`
- **A**ll deps: `$^`
- **T**ete (premiere): `$<`
- **F**irst wildcard: `$*`

### 5.9 Applications pratiques

1. **Projets C/C++**: Compilation efficace
2. **Documentation**: Generation LaTeX, Doxygen
3. **Deployment**: Scripts d'installation
4. **Tests**: Automatisation des tests

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Espaces vs TAB | "missing separator" | Utiliser TAB |
| Pas de .PHONY | Cible pas executee | `.PHONY: target` |
| Ordre dependances | "No such file" | Order-only prereq |
| Variable non definie | Commande vide | Verifier nom |
| Dependance circulaire | Boucle infinie | Revoir graphe |

---

## SECTION 7 : QCM

### Question 1
Quel caractere DOIT preceder une commande dans une recette make ?

A) Espace
B) Tab
C) Tiret
D) Point
E) Arobase

**Reponse correcte: B**

### Question 2
Que represente $@ dans une recette make ?

A) La premiere dependance
B) Toutes les dependances
C) La cible actuelle
D) Le nom du Makefile
E) Une erreur

**Reponse correcte: C**

### Question 3
Pourquoi utiliser .PHONY: clean ?

A) Pour accelerer make
B) Pour eviter les conflits si un fichier "clean" existe
C) C'est obligatoire
D) Pour nettoyer automatiquement
E) Pour les erreurs

**Reponse correcte: B**

### Question 4
Que fait make sans argument ?

A) Affiche l'aide
B) Compile tout
C) Execute la premiere cible du Makefile
D) Nettoie le projet
E) Affiche les variables

**Reponse correcte: C**

### Question 5
Que signifie $(wildcard *.c) ?

A) Compile tous les .c
B) Liste tous les fichiers .c du repertoire
C) Supprime tous les .c
D) Cree des fichiers .c
E) C'est une erreur de syntaxe

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Element | Syntaxe | Description |
|---------|---------|-------------|
| Regle | `target: deps` | Definition d'une cible |
| Variable | `VAR = value` | Definition simple |
| Variable | `VAR := value` | Evaluation immediate |
| PHONY | `.PHONY: target` | Cible sans fichier |
| Pattern | `%.o: %.c` | Regle generique |

| Variable auto | Signification |
|---------------|---------------|
| `$@` | Cible |
| `$<` | Premiere dependance |
| `$^` | Toutes dependances |
| `$*` | Stem du pattern |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.12-a",
    "name": "makefile",
    "module": "0.6.12",
    "phase": 0,
    "difficulty": 3,
    "xp": 200,
    "time_minutes": 120
  },
  "metadata": {
    "concepts": ["targets", "dependencies", "variables"],
    "prerequisites": ["0.5", "command-line"],
    "language": "makefile",
    "language_version": "gnu-make"
  },
  "files": {
    "template": "Makefile.template",
    "solution": "Makefile",
    "test": "test_makefile.sh"
  },
  "compilation": {
    "tool": "make",
    "test_cmd": "make && make clean && make re"
  },
  "grading": {
    "automated": true,
    "targets_weight": 50,
    "variables_weight": 20,
    "best_practices_weight": 30
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 4
  }
}
```
