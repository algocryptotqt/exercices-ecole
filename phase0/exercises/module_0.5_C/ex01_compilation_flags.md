# Exercice 0.5.2-a : compilation_flags

**Module :**
0.5.2 — Chaine de Compilation C

**Concept :**
a-i — Preprocesseur, Compilateur, Linker, gcc flags (-o, -Wall, -Werror, -g, -O2)

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
cours_pratique

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.1 (first_program)

**Domaines :**
CPU, Encodage

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `compilation_demo.c`
- `compile.sh`
- `answers.txt`

**Fonctions autorisees :**
- Toutes fonctions de `<stdio.h>`

**Fonctions interdites :**
- Aucune restriction

### 1.2 Consigne

**Akira: La Chaine de Compilation**

Dans Neo-Tokyo, les hackers ne se contentent pas d'ecrire du code. Ils comprennent chaque etape de la transformation: du code source brut jusqu'au binaire executable. Comme Tetsuo qui doit maitriser ses pouvoirs, tu dois maitriser la chaine de compilation.

**Ta mission :**

1. Creer `compilation_demo.c` avec des **warnings intentionnels**:
   - Variable declaree mais non utilisee
   - Comparaison signed/unsigned
   - Format printf incorrect

2. Creer `compile.sh` qui demontre les etapes:
```bash
#!/bin/bash
# Etape 1: Preprocesseur seul
gcc -E compilation_demo.c -o preprocessed.i

# Etape 2: Compilation en objet
gcc -c compilation_demo.c -o compilation_demo.o

# Etape 3: Linking final
gcc compilation_demo.o -o compilation_demo

# Etape 4: Avec -Wall (affiche warnings)
gcc -Wall compilation_demo.c -o demo_wall 2>&1

# Etape 5: Avec -Wall -Werror (doit echouer)
gcc -Wall -Werror compilation_demo.c -o demo_werror 2>&1 || echo "Expected failure"

# Etape 6: Avec -g pour debug
gcc -g compilation_demo.c -o demo_debug

# Etape 7: Avec -O2 pour optimisation
gcc -O2 compilation_demo.c -o demo_optimized
```

3. Creer `answers.txt` avec les reponses aux questions

**Questions pour answers.txt :**
1. Quelle est la difference entre `-Wall` et `-Werror` ?
2. Pourquoi utiliser `-g` en developpement ?
3. Que fait le preprocesseur ?
4. Quelle est la difference entre `-O0` et `-O2` ?
5. Pourquoi les fichiers `.o` sont utiles ?

**Contraintes :**
- `compile.sh` doit etre executable (`chmod +x`)
- Les reponses doivent etre claires et precises
- Le code doit compiler sans `-Wall -Werror`

### 1.3 Prototype

```c
// compilation_demo.c
#include <stdio.h>

int main(void)
{
    int unused_var = 42;           // Warning: unused variable
    unsigned int u = 10;
    int s = -5;
    if (s < u) { }                 // Warning: signed/unsigned comparison
    printf("%d\n", "not an int");  // Warning: format specifier mismatch
    return 0;
}
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Les 4 etapes de compilation

```
Source (.c) --> Preprocesseur --> Assembleur (.s) --> Objet (.o) --> Executable
     |              |                  |                 |              |
     v              v                  v                 v              v
 Ton code      Macros/includes     Instructions     Code machine    Programme
```

### 2.2 Pourquoi gcc s'appelle gcc ?

GCC signifie "GNU Compiler Collection". A l'origine (1987), c'etait "GNU C Compiler". Aujourd'hui, il compile C, C++, Fortran, Ada, Go, et plus encore.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Build Engineer / DevOps**

Les Build Engineers configurent les pipelines de compilation:
- Flags de production vs debug
- Optimisations par plateforme
- Integration continue (CI/CD)

**Metier : Security Researcher**

Les chercheurs en securite utilisent les flags pour:
- `-fstack-protector` contre buffer overflows
- `-fsanitize=address` pour detecter memory bugs
- `-pie -fPIC` pour ASLR

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ chmod +x compile.sh
$ ./compile.sh
# Affiche les differentes etapes et leurs resultats

$ ls -la
-rw-r--r-- 1 user user  1234 preprocessed.i
-rw-r--r-- 1 user user   456 compilation_demo.o
-rwxr-xr-x 1 user user 16384 compilation_demo
-rwxr-xr-x 1 user user 16384 demo_wall
-rwxr-xr-x 1 user user 32768 demo_debug
-rwxr-xr-x 1 user user  8192 demo_optimized

$ cat answers.txt
1. -Wall active tous les warnings, -Werror transforme les warnings en erreurs
2. -g ajoute les symboles de debug pour gdb
3. Le preprocesseur traite les #include, #define, et macros
4. -O0 = pas d'optimisation, -O2 = optimisations standard
5. Les .o permettent la compilation incrementale
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | compile.sh existe et executable | True | 15 |
| T02 | compilation_demo.c compile sans -Wall | Success | 15 |
| T03 | Warnings avec -Wall | >= 3 warnings | 15 |
| T04 | Echec avec -Werror | Non-zero exit | 15 |
| T05 | answers.txt existe | True | 10 |
| T06 | 5 reponses presentes | True | 15 |
| T07 | preprocessed.i genere | True | 15 |

### 4.3 Solution de reference

**compilation_demo.c:**
```c
#include <stdio.h>

int main(void)
{
    // Warning 1: Variable non utilisee
    int unused_variable = 42;

    // Warning 2: Comparaison signed/unsigned
    unsigned int unsigned_val = 10;
    int signed_val = -5;
    if (signed_val < unsigned_val)
    {
        printf("Comparison done\n");
    }

    // Warning 3: Mauvais format specifier
    printf("This is wrong: %d\n", "should be string");

    printf("Program executed despite warnings\n");
    return 0;
}
```

**compile.sh:**
```bash
#!/bin/bash
set -e

echo "=== Etape 1: Preprocesseur seul ==="
gcc -E compilation_demo.c -o preprocessed.i
echo "Fichier preprocessed.i genere ($(wc -l < preprocessed.i) lignes)"

echo ""
echo "=== Etape 2: Compilation en objet ==="
gcc -c compilation_demo.c -o compilation_demo.o
echo "Fichier compilation_demo.o genere"

echo ""
echo "=== Etape 3: Linking final ==="
gcc compilation_demo.o -o compilation_demo
echo "Executable compilation_demo genere"

echo ""
echo "=== Etape 4: Avec -Wall ==="
gcc -Wall compilation_demo.c -o demo_wall 2>&1 || true
echo "Compilation avec warnings terminee"

echo ""
echo "=== Etape 5: Avec -Wall -Werror ==="
if gcc -Wall -Werror compilation_demo.c -o demo_werror 2>&1; then
    echo "Compilation reussie (inattendu)"
else
    echo "Echec attendu: warnings traites comme erreurs"
fi

echo ""
echo "=== Etape 6: Avec -g ==="
gcc -g compilation_demo.c -o demo_debug
echo "Executable avec debug symbols genere"

echo ""
echo "=== Etape 7: Avec -O2 ==="
gcc -O2 compilation_demo.c -o demo_optimized
echo "Executable optimise genere"

echo ""
echo "=== Comparaison des tailles ==="
ls -la demo_debug demo_optimized compilation_demo
```

**answers.txt:**
```
1. Quelle est la difference entre -Wall et -Werror ?
-Wall active l'affichage de la plupart des warnings (mais pas tous).
-Werror transforme tous les warnings en erreurs de compilation.
Avec -Werror, le code ne compile pas s'il y a le moindre warning.

2. Pourquoi utiliser -g en developpement ?
Le flag -g ajoute les informations de debug dans l'executable.
Ces informations permettent a gdb d'afficher les noms de variables,
les numeros de lignes, et de naviguer dans le code source.
L'executable est plus gros mais indispensable pour debugger.

3. Que fait le preprocesseur ?
Le preprocesseur traite le code AVANT la compilation:
- Remplace les #include par le contenu des fichiers headers
- Evalue les #define et remplace les macros
- Traite les directives conditionnelles (#ifdef, #ifndef)
- Supprime les commentaires

4. Quelle est la difference entre -O0 et -O2 ?
-O0: Aucune optimisation. Code lisible en assembleur, debug facile.
-O2: Optimisations standard. Code plus rapide mais transforme.
-O2 peut reorganiser le code, inliner des fonctions, derouler des boucles.

5. Pourquoi les fichiers .o sont utiles ?
Les fichiers objets (.o) permettent la compilation incrementale.
Si on modifie un seul fichier .c dans un gros projet,
seul ce fichier est recompile en .o, puis le linking relie tous les .o.
Cela accelere enormement la compilation sur gros projets.
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Pas de warning genere
#include <stdio.h>
int main(void) {
    printf("No warnings here\n");
    return 0;
}
// Detection: gcc -Wall ne produit pas de warning

// MUTANT 2: compile.sh non executable
// Detection: test -x compile.sh echoue

// MUTANT 3: answers.txt incomplet
// Detection: grep pour chaque question

// MUTANT 4: Pas de preprocessed.i genere
// Detection: test -f preprocessed.i

// MUTANT 5: Script avec erreurs de syntaxe
#!/bin/bash
gcc -E compilation_demo.c  # Pas de redirection
// Detection: Fichier .i non cree
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

La transformation d'un fichier `.c` en executable passe par **4 etapes distinctes**:

1. **Preprocessing** (-E) - Traitement des directives #
2. **Compilation** (-S) - C vers assembleur
3. **Assembly** (-c) - Assembleur vers code objet
4. **Linking** - Objets vers executable final

### 5.2 LDA - Traduction Litterale en Francais

```
ETAPE 1 - PREPROCESSEUR:
    LIRE le fichier source
    POUR CHAQUE ligne commencant par #:
        SI #include: INSERER le contenu du fichier
        SI #define: ENREGISTRER la macro
        SI #ifdef: EVALUER la condition
    PRODUIRE le fichier preprocesse (.i)

ETAPE 2 - COMPILATION:
    LIRE le fichier preprocesse
    ANALYSER la syntaxe (parser)
    GENERER l'arbre syntaxique
    OPTIMISER si demande (-O)
    PRODUIRE le code assembleur (.s)

ETAPE 3 - ASSEMBLAGE:
    LIRE le fichier assembleur
    CONVERTIR en code machine
    PRODUIRE le fichier objet (.o)

ETAPE 4 - LINKING:
    LIRE tous les fichiers objets
    RESOUDRE les symboles externes
    LIER avec les bibliotheques
    PRODUIRE l'executable final
```

### 5.3 Visualisation ASCII

```
                    Chaine de Compilation GCC
                    ========================

    source.c                     Fichiers Headers
        |                        /usr/include/*.h
        v                              |
   +-----------+                       |
   |PREPROCESSOR|<---------------------+
   |   gcc -E   |
   +-----------+
        |
        v
   preprocessed.i (code C expanse)
        |
        v
   +-----------+
   | COMPILER  |
   |   gcc -S  |
   +-----------+
        |
        v
   source.s (assembleur)
        |
        v
   +-----------+
   | ASSEMBLER |
   |   gcc -c  |
   +-----------+
        |
        v
   source.o (code objet)          Bibliotheques
        |                         libc.so, libm.so
        v                              |
   +-----------+                       |
   |  LINKER   |<----------------------+
   |    ld     |
   +-----------+
        |
        v
   executable (binaire final)
```

### 5.4 Les pieges en detail

#### Piege 1: Confondre -Wall et -Wextra
```bash
# -Wall n'active PAS tous les warnings!
gcc -Wall prog.c    # La plupart des warnings
gcc -Wextra prog.c  # Warnings supplementaires
gcc -Wall -Wextra prog.c  # Maximum recommande
```

#### Piege 2: Oublier que -g augmente la taille
```bash
$ gcc prog.c -o prog_normal
$ gcc -g prog.c -o prog_debug
$ ls -la prog_*
-rwxr-xr-x 1 user user  8192 prog_normal
-rwxr-xr-x 1 user user 32768 prog_debug  # 4x plus gros!
```

### 5.5 Cours Complet

#### 5.5.1 Le Preprocesseur

Le preprocesseur est un **transformateur de texte**. Il ne comprend pas le C, il manipule juste du texte.

Directives principales:
- `#include` - Inclusion de fichiers
- `#define` - Definition de macros
- `#ifdef/#ifndef/#endif` - Compilation conditionnelle
- `#pragma` - Instructions au compilateur

#### 5.5.2 Les Flags de Compilation

| Flag | Signification | Usage |
|------|---------------|-------|
| `-Wall` | Enable most warnings | Toujours utiliser |
| `-Werror` | Warnings are errors | En production |
| `-g` | Debug symbols | Developpement |
| `-O0` | No optimization | Debug |
| `-O2` | Standard optimization | Production |
| `-O3` | Aggressive optimization | Performance critique |
| `-std=c17` | C17 standard | Portabilite |

#### 5.5.3 Compilation Incrementale

```bash
# Projet avec 3 fichiers
gcc -c main.c -o main.o
gcc -c utils.c -o utils.o
gcc -c math.c -o math.o
gcc main.o utils.o math.o -o program

# Si seul utils.c change:
gcc -c utils.c -o utils.o  # Recompile seulement utils
gcc main.o utils.o math.o -o program  # Relie tout
```

### 5.8 Mnemotechniques

**"PCAL" - Les 4 etapes**
- **P**reprocesseur (texte -> texte expanse)
- **C**ompilateur (C -> assembleur)
- **A**ssembleur (asm -> objet)
- **L**inker (objets -> executable)

**"WEG-O" - Les flags essentiels**
- **W**all - Warnings
- **E**rror (W) - Erreurs strictes
- **G** - Debug
- **O** - Optimisation

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| -Wall != tous warnings | Warnings manques | Ajouter -Wextra |
| -g en production | Binaire enorme | Retirer -g |
| -O3 sans tests | Bugs subtils | Tester avec -O0 d'abord |
| Oubli -std=c17 | Code non portable | Specifier -std=c17 |

---

## SECTION 7 : QCM

### Question 1
Que fait `gcc -E source.c -o output.i` ?

A) Compile en executable
B) Compile en objet
C) Execute le preprocesseur uniquement
D) Execute le linker
E) Optimise le code
F) Ajoute les symboles debug
G) Supprime les warnings
H) Genere l'assembleur
I) Verifie la syntaxe seulement
J) Formate le code

**Reponse correcte: C**

### Question 2
Quelle option transforme les warnings en erreurs ?

A) -Wall
B) -Wextra
C) -Werror
D) -Wpedantic
E) -Wfatal
F) -Wstrict
G) -Wno-error
H) -Wmax
I) -Wstop
J) -Wdie

**Reponse correcte: C**

### Question 3
Pourquoi utiliser `-g` ?

A) Pour optimiser le code
B) Pour generer de la documentation
C) Pour ajouter les symboles de debug
D) Pour compiler plus vite
E) Pour reduire la taille du binaire
F) Pour activer les warnings
G) Pour specifier le standard C
H) Pour lier statiquement
I) Pour generer du code portable
J) Pour supprimer les commentaires

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Etape | Flag | Input | Output |
|-------|------|-------|--------|
| Preprocess | -E | .c | .i |
| Compile | -S | .i | .s |
| Assemble | -c | .s | .o |
| Link | (none) | .o | executable |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.5.2-a",
    "name": "compilation_flags",
    "module": "0.5.2",
    "phase": 0,
    "difficulty": 2,
    "xp": 150,
    "time_minutes": 120
  },
  "metadata": {
    "concepts": ["preprocessor", "compiler", "linker", "gcc_flags"],
    "prerequisites": ["0.5.1"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "submission": ["compilation_demo.c", "compile.sh", "answers.txt"],
    "test": ["test_compilation.sh"]
  },
  "grading": {
    "automated": true,
    "script_weight": 40,
    "answers_weight": 30,
    "warnings_weight": 30
  }
}
```
