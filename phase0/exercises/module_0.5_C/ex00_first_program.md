# Exercice 0.5.1-a : first_program

**Module :**
0.5.1 — Structure de Base C17

**Concept :**
a-f — #include, stdio.h, main(), return, blocs, point-virgule

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
cours_code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
Aucun

**Domaines :**
Encodage, CPU

**Duree estimee :**
60 min

**XP Base :**
100

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `first_program.c`

**Fonctions autorisees :**
- `printf()` de `<stdio.h>`

**Fonctions interdites :**
- Toute autre fonction de bibliotheque

### 1.2 Consigne

**Ghost in the Shell: Premier Boot**

Dans le monde cyberpunk de Ghost in the Shell, les cyborgs communiquent avec les machines via des interfaces neurales. Mais avant de pouvoir hacker le reseau, tu dois d'abord apprendre le langage de la Machine: le C.

Ton cerveau electronique vient d'etre initialise. Le premier test diagnostique: envoyer un signal au terminal. C'est le rituel ancestral de tout programmeur - le "Hello, World!".

**Ta mission :**

Ecrire un programme C17 qui affiche exactement:
```
Hello, C17!
Program structure: validated
```

**Entree :**
- Aucune

**Sortie :**
- Les deux lignes exactes ci-dessus sur stdout
- Code de retour: 0

**Contraintes :**
- Utiliser uniquement `<stdio.h>`
- Respecter la structure canonique: `int main(void) { ... return 0; }`
- Chaque instruction se termine par `;`
- Le code doit etre dans des blocs `{}`
- Compiler sans warnings avec `gcc -Wall -Werror -std=c17`

**Exemples :**

| Commande | Sortie |
|----------|--------|
| `./first_program` | `Hello, C17!` suivi de `Program structure: validated` |
| `echo $?` apres execution | `0` |

### 1.3 Prototype

```c
#include <stdio.h>

int main(void);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Pourquoi "Hello, World!" ?

La tradition du "Hello, World!" remonte a 1978 et au livre "The C Programming Language" de Brian Kernighan et Dennis Ritchie (les createurs du C). C'est devenu le premier programme que tout developpeur ecrit dans un nouveau langage.

### 2.2 Pourquoi C17 ?

C17 (ISO/IEC 9899:2018) est la version moderne et stable du langage C. Elle corrige les ambiguites de C11 sans ajouter de nouvelles fonctionnalites, garantissant une base solide et bien definie.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Embedded Systems Engineer**

Les ingenieurs embarques ecrivent du C quotidiennement pour:
- Firmware de microcontroleurs (Arduino, STM32, ESP32)
- Systemes critiques (avionique, medical, automobile)
- Drivers de peripheriques

**Metier : Systems Programmer**

Les programmeurs systeme utilisent C pour:
- Noyaux de systemes d'exploitation (Linux, BSD)
- Interpreters et compilateurs
- Bases de donnees (PostgreSQL, SQLite)

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o first_program first_program.c
$ ./first_program
Hello, C17!
Program structure: validated
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★☆☆☆☆☆☆☆ (3/10)

**Recompense :**
XP x2

**Time Complexity attendue :**
O(1)

**Space Complexity attendue :**
O(1)

#### 3.1.1 Consigne Bonus

**Ghost in the Shell: Diagnostic Complet**

Le Major Kusanagi te demande un diagnostic plus complet de ton systeme.

**Ta mission :**

Modifier le programme pour afficher egalement:
- La version du standard C utilise (`__STDC_VERSION__`)
- La date de compilation (`__DATE__`)
- L'heure de compilation (`__TIME__`)
- Le nom du fichier (`__FILE__`)

**Sortie attendue (exemple):**
```
Hello, C17!
Program structure: validated
C Standard: 201710
Compiled: Jan 16 2026 at 14:30:00
Source: first_program.c
```

#### 3.1.2 Prototype Bonus

```c
int main(void);  // Meme prototype, affichage etendu
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 20 |
| T02 | Execution sans crash | Success | 20 |
| T03 | Ligne 1 exacte | "Hello, C17!" | 20 |
| T04 | Ligne 2 exacte | "Program structure: validated" | 20 |
| T05 | Return code = 0 | 0 | 20 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *fp = popen("./first_program", "r");
    if (!fp) {
        printf("FAIL: Cannot execute program\n");
        return 1;
    }

    char line1[256], line2[256];
    if (!fgets(line1, sizeof(line1), fp) ||
        !fgets(line2, sizeof(line2), fp)) {
        printf("FAIL: Cannot read output\n");
        pclose(fp);
        return 1;
    }

    // Remove newlines
    line1[strcspn(line1, "\n")] = 0;
    line2[strcspn(line2, "\n")] = 0;

    int status = pclose(fp);

    if (strcmp(line1, "Hello, C17!") != 0) {
        printf("FAIL T03: Expected 'Hello, C17!' got '%s'\n", line1);
        return 1;
    }

    if (strcmp(line2, "Program structure: validated") != 0) {
        printf("FAIL T04: Expected 'Program structure: validated' got '%s'\n", line2);
        return 1;
    }

    if (WEXITSTATUS(status) != 0) {
        printf("FAIL T05: Expected return 0, got %d\n", WEXITSTATUS(status));
        return 1;
    }

    printf("All tests passed!\n");
    return 0;
}
```

### 4.3 Solution de reference

```c
/*
 * first_program.c
 * Premier programme C17 - Hello World
 * Exercice ex00_first_program
 */

#include <stdio.h>

int main(void)
{
    printf("Hello, C17!\n");
    printf("Program structure: validated\n");
    return 0;
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: puts() au lieu de printf()
#include <stdio.h>

int main(void)
{
    puts("Hello, C17!");
    puts("Program structure: validated");
    return 0;
}

// Alternative 2: Un seul printf avec tout le texte
#include <stdio.h>

int main(void)
{
    printf("Hello, C17!\nProgram structure: validated\n");
    return 0;
}

// Alternative 3: Avec return explicite EXIT_SUCCESS
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("Hello, C17!\n");
    printf("Program structure: validated\n");
    return EXIT_SUCCESS;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Pas de return
#include <stdio.h>
int main(void) {
    printf("Hello, C17!\n");
    printf("Program structure: validated\n");
}
// Raison: return 0 implicite en C99+ mais mauvaise pratique

// REFUSE 2: Mauvais prototype
#include <stdio.h>
void main() {  // ERREUR: void au lieu de int
    printf("Hello, C17!\n");
}
// Raison: main() DOIT retourner int selon le standard

// REFUSE 3: Format incorrect
#include <stdio.h>
int main(void) {
    printf("hello, c17!\n");  // Minuscules
    return 0;
}
// Raison: Sortie doit etre exacte

// REFUSE 4: Sans include
int main(void) {
    printf("Hello, C17!\n");  // Warning implicite
    return 0;
}
// Raison: Doit inclure <stdio.h> explicitement
```

### 4.6 Solution bonus de reference

```c
#include <stdio.h>

int main(void)
{
    printf("Hello, C17!\n");
    printf("Program structure: validated\n");
    printf("C Standard: %ld\n", __STDC_VERSION__);
    printf("Compiled: %s at %s\n", __DATE__, __TIME__);
    printf("Source: %s\n", __FILE__);
    return 0;
}
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.5.1-a",
  "name": "first_program",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["first_program.c"],
    "test": ["test_first_program.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "first_program"
  },
  "tests": {
    "output": [
      {"line": 1, "expected": "Hello, C17!"},
      {"line": 2, "expected": "Program structure: validated"}
    ],
    "return_code": 0
  },
  "scoring": {
    "total": 100,
    "compilation": 20,
    "execution": 20,
    "output": 40,
    "return_code": 20
  },
  "bonus": {
    "available": true,
    "multiplier": 2
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Boundary): Oubli du newline final
#include <stdio.h>
int main(void) {
    printf("Hello, C17!");  // Pas de \n
    printf("Program structure: validated");
    return 0;
}
// Detection: diff avec sortie attendue

// MUTANT 2 (Safety): Mauvais code de retour
#include <stdio.h>
int main(void) {
    printf("Hello, C17!\n");
    printf("Program structure: validated\n");
    return 1;  // Devrait etre 0
}
// Detection: Test du code de retour

// MUTANT 3 (Logic): Lignes inversees
#include <stdio.h>
int main(void) {
    printf("Program structure: validated\n");
    printf("Hello, C17!\n");
    return 0;
}
// Detection: Comparaison ligne par ligne

// MUTANT 4 (Format): Espace supplementaire
#include <stdio.h>
int main(void) {
    printf("Hello,  C17!\n");  // Double espace
    printf("Program structure: validated\n");
    return 0;
}
// Detection: Comparaison exacte de string

// MUTANT 5 (Typo): Faute de frappe
#include <stdio.h>
int main(void) {
    printf("Hello, C17!\n");
    printf("Program structure: valitated\n");  // "valitated"
    return 0;
}
// Detection: Comparaison exacte de string
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Cet exercice introduit les **6 elements fondamentaux** de tout programme C:

1. **#include** - Directive preprocesseur pour inclure des headers
2. **<stdio.h>** - Header de la bibliotheque standard d'entree/sortie
3. **int main(void)** - Point d'entree obligatoire du programme
4. **return 0** - Code de retour indiquant le succes
5. **{ }** - Blocs delimitant le corps des fonctions
6. **;** - Terminateur obligatoire de chaque instruction

### 5.2 LDA - Traduction Litterale en Francais

```
INCLURE le fichier d'en-tete stdio.h

FONCTION main() RETOURNE un entier:
DEBUT
    AFFICHER "Hello, C17!" suivi d'un saut de ligne
    AFFICHER "Program structure: validated" suivi d'un saut de ligne
    RETOURNER 0 (succes)
FIN
```

### 5.3 Visualisation ASCII

```
+------------------+     +------------------+
|  first_program.c |     |   Preprocesseur  |
|                  |     |                  |
| #include <stdio> |---->| Remplace par le  |
|                  |     | contenu de stdio |
| int main(void)   |     +------------------+
| {                |            |
|   printf(...);   |            v
|   return 0;      |     +------------------+
| }                |     |   Compilateur    |
+------------------+     |                  |
                         | .c -> .o         |
                         +------------------+
                                |
                                v
                         +------------------+
                         |     Linker       |
                         |                  |
                         | .o -> executable |
                         +------------------+
                                |
                                v
                         +------------------+
                         | ./first_program  |
                         |                  |
                         | Hello, C17!      |
                         | Program...       |
                         +------------------+
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier le point-virgule
```c
// FAUX
printf("Hello")  // error: expected ';' before '}'

// CORRECT
printf("Hello");
```

#### Piege 2: Oublier l'include
```c
// FAUX - Warning implicite
int main(void) {
    printf("test");  // printf non declare!
    return 0;
}

// CORRECT
#include <stdio.h>
int main(void) {
    printf("test");
    return 0;
}
```

#### Piege 3: Mauvais prototype de main
```c
// FAUX - Non standard
void main() { }

// CORRECT - Standard C
int main(void) { return 0; }
```

#### Piege 4: Oublier le \n
```c
// Comportement indetermine sur certains systemes
printf("Hello");  // Pas de newline final

// CORRECT
printf("Hello\n");
```

### 5.5 Cours Complet

#### 5.5.1 La directive #include

Le preprocesseur C traite le fichier source AVANT la compilation. `#include` copie litteralement le contenu d'un fichier header dans ton code.

```c
#include <stdio.h>   // Cherche dans les repertoires systeme
#include "myfile.h"  // Cherche d'abord dans le repertoire courant
```

#### 5.5.2 Le header <stdio.h>

`stdio.h` (Standard Input/Output) declare les fonctions d'E/S:
- `printf()` - Affichage formate
- `scanf()` - Lecture formatee
- `puts()` - Affiche une chaine + newline
- `getchar()`, `putchar()` - Caractere par caractere

#### 5.5.3 La fonction main()

`main()` est le **point d'entree** obligatoire de tout programme C. Le systeme d'exploitation appelle cette fonction quand tu executes ton programme.

Deux prototypes standards:
```c
int main(void);                    // Sans arguments
int main(int argc, char *argv[]);  // Avec arguments CLI
```

#### 5.5.4 Le return et les codes de sortie

Le `return` de main() renvoie un code au systeme:
- `0` ou `EXIT_SUCCESS` = Succes
- Non-zero = Erreur (par convention)

```bash
$ ./program
$ echo $?  # Affiche le code de retour
0
```

#### 5.5.5 Les blocs { }

Les accolades delimitent les blocs de code:
- Corps de fonction
- Corps de boucle/condition
- Scopes locaux

```c
int main(void)
{  // Debut du bloc main
    if (condition)
    {  // Debut du bloc if
        // Code
    }  // Fin du bloc if
}  // Fin du bloc main
```

#### 5.5.6 Le terminateur ;

Chaque instruction en C DOIT se terminer par un point-virgule. C'est une source tres frequente d'erreurs pour les debutants.

```c
int x = 5;     // OK
printf("Hi");  // OK
return 0;      // OK
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Indentation 4 espaces | Lisibilite uniforme | `    printf(...);` |
| Accolade sur nouvelle ligne | Style K&R ou Allman | Voir ci-dessus |
| main retourne int | Standard C obligatoire | `int main(void)` |
| Inclure les headers | Evite warnings implicites | `#include <stdio.h>` |

### 5.7 Simulation avec trace d'execution

```
1. Preprocesseur lit first_program.c
2. #include <stdio.h> -> insere ~1000 lignes de declarations
3. Compilateur parse int main(void) { ... }
4. Genere code machine dans first_program.o
5. Linker lie avec libc.so (printf)
6. Produit executable first_program

Execution:
1. OS charge first_program en memoire
2. OS appelle main()
3. printf("Hello, C17!\n") -> syscall write(1, "Hello, C17!\n", 12)
4. printf("Program...") -> syscall write(1, "...", 28)
5. return 0 -> OS recoit code 0
6. $ echo $? affiche 0
```

### 5.8 Mnemotechniques

**"IMRB;" - Les 5 elements de tout programme C**
- **I**nclude (les headers)
- **M**ain (le point d'entree)
- **R**eturn (le code de sortie)
- **B**locks (les accolades)
- **;** (le terminateur)

**"stdio = Standard Tool for Input/Output"**
- Tout ce qui entre/sort passe par stdio

### 5.9 Applications pratiques

1. **Scripts systeme**: Petits utilitaires Unix
2. **Firmware**: Initialisation de microcontroleurs
3. **Diagnostic**: Programmes de test hardware
4. **Bootstrap**: Premier code execute au boot

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Oubli de `;` | error: expected ';' | Ajouter `;` apres chaque instruction |
| Oubli de `#include` | warning: implicit declaration | Ajouter `#include <stdio.h>` |
| `void main()` | Non-standard | Utiliser `int main(void)` |
| Oubli de `\n` | Sortie collee | Ajouter `\n` dans printf |
| Oubli de `return 0` | Code retour indetermine | Ajouter `return 0;` |

---

## SECTION 7 : QCM

### Question 1
Que fait la directive `#include <stdio.h>` ?

A) Compile le fichier stdio.h
B) Execute le fichier stdio.h
C) Copie le contenu de stdio.h dans le code source
D) Cree un lien vers stdio.h
E) Telecharge stdio.h depuis internet
F) Supprime stdio.h
G) Renomme le fichier en stdio.h
H) Chiffre le fichier avec stdio.h
I) Compare le fichier avec stdio.h
J) Rien du tout

**Reponse correcte: C**

### Question 2
Quel est le prototype standard de main() sans arguments ?

A) `void main()`
B) `main()`
C) `int main(void)`
D) `int main()`
E) `void main(void)`
F) `static int main(void)`
G) `public int main(void)`
H) `function main(void)`
I) `def main(void)`
J) `proc main(void)`

**Reponse correcte: C**

### Question 3
Que signifie `return 0;` a la fin de main() ?

A) Le programme a echoue
B) Le programme a reussi
C) Le programme va redemarrer
D) Le programme est en pause
E) Le programme attend une entree
F) Le programme libere la memoire
G) Le programme ferme tous les fichiers
H) Le programme envoie un signal
I) Le programme se clone
J) Rien de special

**Reponse correcte: B**

### Question 4
Quel caractere termine chaque instruction en C ?

A) `.`
B) `,`
C) `:`
D) `;`
E) `!`
F) `?`
G) `\n`
H) Espace
I) Tab
J) Aucun

**Reponse correcte: D**

### Question 5
Que se passe-t-il si on oublie `#include <stdio.h>` et qu'on utilise printf() ?

A) Le programme compile et fonctionne parfaitement
B) Le programme ne compile pas du tout
C) Warning de declaration implicite, comportement indefini possible
D) Le programme affiche un message d'erreur propre
E) Le programme plante immediatement
F) Le programme entre dans une boucle infinie
G) Le programme supprime des fichiers
H) Le programme se compile mais ne s'execute pas
I) Le programme demande d'installer stdio
J) Le programme telecharge automatiquement stdio

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Element | Description | Syntaxe |
|---------|-------------|---------|
| #include | Inclure un header | `#include <header.h>` |
| stdio.h | E/S standard | `#include <stdio.h>` |
| main | Point d'entree | `int main(void)` |
| printf | Affichage formate | `printf("format", args)` |
| return | Code de sortie | `return 0;` |
| { } | Blocs de code | `{ instructions }` |
| ; | Fin d'instruction | `instruction;` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.5.1-a",
    "name": "first_program",
    "module": "0.5.1",
    "phase": 0,
    "difficulty": 2,
    "xp": 100,
    "time_minutes": 60
  },
  "metadata": {
    "concepts": ["include", "stdio", "main", "return", "blocks", "semicolon"],
    "prerequisites": [],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "first_program.c",
    "solution": "first_program_solution.c",
    "test": "test_first_program.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "compilation_weight": 20,
    "output_weight": 60,
    "return_code_weight": 20
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 3
  }
}
```
