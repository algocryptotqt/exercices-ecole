# Exercice 0.5.7-b : switch_dispatcher

**Module :**
0.5.7 — Structures Conditionnelles (switch)

**Concept :**
d-g — switch, case, default, break

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.7-a (condition_cascade)

**Domaines :**
Algo

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
- `switch_dispatcher.c`
- `switch_dispatcher.h`

### 1.2 Consigne

Creer un interpreteur de commandes simple utilisant switch.

**Ta mission :**

Implementer les fonctions suivantes:

```c
typedef enum {
    CMD_HELP = 0,
    CMD_VERSION,
    CMD_LIST,
    CMD_ADD,
    CMD_REMOVE,
    CMD_QUIT,
    CMD_UNKNOWN
} Command;

Command parse_command(const char *input);
const char *execute_command(Command cmd);
int dispatch_menu(int choice);
```

**Comportement:**

1. `parse_command(input)`:
   - "help" -> CMD_HELP
   - "version" -> CMD_VERSION
   - "list" -> CMD_LIST
   - "add" -> CMD_ADD
   - "remove" -> CMD_REMOVE
   - "quit" -> CMD_QUIT
   - autre -> CMD_UNKNOWN

2. `execute_command(cmd)`:
   - CMD_HELP -> "Displaying help..."
   - CMD_VERSION -> "Version 1.0.0"
   - CMD_LIST -> "Listing items..."
   - CMD_ADD -> "Adding item..."
   - CMD_REMOVE -> "Removing item..."
   - CMD_QUIT -> "Goodbye!"
   - CMD_UNKNOWN -> "Unknown command"

3. `dispatch_menu(choice)`:
   - 1-6: retourne 0 (succes)
   - autre: retourne -1 (erreur, case default)

**Exemples:**
```
parse_command("help")     -> CMD_HELP
parse_command("quit")     -> CMD_QUIT
parse_command("invalid")  -> CMD_UNKNOWN

execute_command(CMD_HELP) -> "Displaying help..."
execute_command(CMD_QUIT) -> "Goodbye!"

dispatch_menu(3)  -> 0
dispatch_menu(10) -> -1
```

### 1.3 Prototype

```c
// switch_dispatcher.h
#ifndef SWITCH_DISPATCHER_H
#define SWITCH_DISPATCHER_H

typedef enum {
    CMD_HELP = 0,
    CMD_VERSION,
    CMD_LIST,
    CMD_ADD,
    CMD_REMOVE,
    CMD_QUIT,
    CMD_UNKNOWN
} Command;

Command parse_command(const char *input);
const char *execute_command(Command cmd);
int dispatch_menu(int choice);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

Le switch en C est compile en "jump table" par le compilateur quand les cases sont consecutifs. C'est plus rapide qu'une chaine de if-else car l'acces est O(1) au lieu de O(n).

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Game Developer**

Le switch est utilise pour:
- State machines (etats de jeu)
- Event handlers
- Parseurs de protocoles

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o dispatcher test_main.c switch_dispatcher.c
$ ./dispatcher
parse_command("help") = CMD_HELP
execute_command(CMD_HELP) = Displaying help...
dispatch_menu(3) = 0
dispatch_menu(10) = -1
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | parse_command("help") | CMD_HELP | 10 |
| T02 | parse_command("version") | CMD_VERSION | 10 |
| T03 | parse_command("quit") | CMD_QUIT | 10 |
| T04 | parse_command("xyz") | CMD_UNKNOWN | 10 |
| T05 | execute_command(CMD_HELP) | "Displaying help..." | 10 |
| T06 | execute_command(CMD_QUIT) | "Goodbye!" | 10 |
| T07 | execute_command(CMD_UNKNOWN) | "Unknown command" | 10 |
| T08 | dispatch_menu(1) | 0 | 10 |
| T09 | dispatch_menu(6) | 0 | 10 |
| T10 | dispatch_menu(7) | -1 | 10 |

### 4.3 Solution de reference

```c
#include <string.h>
#include "switch_dispatcher.h"

Command parse_command(const char *input)
{
    if (strcmp(input, "help") == 0)
        return CMD_HELP;
    if (strcmp(input, "version") == 0)
        return CMD_VERSION;
    if (strcmp(input, "list") == 0)
        return CMD_LIST;
    if (strcmp(input, "add") == 0)
        return CMD_ADD;
    if (strcmp(input, "remove") == 0)
        return CMD_REMOVE;
    if (strcmp(input, "quit") == 0)
        return CMD_QUIT;
    return CMD_UNKNOWN;
}

const char *execute_command(Command cmd)
{
    switch (cmd)
    {
        case CMD_HELP:
            return "Displaying help...";
        case CMD_VERSION:
            return "Version 1.0.0";
        case CMD_LIST:
            return "Listing items...";
        case CMD_ADD:
            return "Adding item...";
        case CMD_REMOVE:
            return "Removing item...";
        case CMD_QUIT:
            return "Goodbye!";
        case CMD_UNKNOWN:
        default:
            return "Unknown command";
    }
}

int dispatch_menu(int choice)
{
    switch (choice)
    {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
            return 0;
        default:
            return -1;
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Oubli du break (fall-through)
const char *execute_command(Command cmd)
{
    switch (cmd)
    {
        case CMD_HELP:
            return "Displaying help...";
            // break manquant - mais return evite le probleme
        case CMD_VERSION:
            return "Version 1.0.0";
        // Si on avait des actions sans return:
        case CMD_LIST:
            printf("List");
            // Oubli break -> execute aussi CMD_ADD!
        case CMD_ADD:
            printf("Add");
            break;
    }
}

// MUTANT 2: Pas de case default
const char *execute_command(Command cmd)
{
    switch (cmd)
    {
        case CMD_HELP: return "Displaying help...";
        // Pas de default -> comportement indefini pour CMD_UNKNOWN
    }
}

// MUTANT 3: Case en dehors du range
int dispatch_menu(int choice)
{
    switch (choice)
    {
        case 1: case 2: case 3: case 4: case 5:  // Oubli du 6
            return 0;
        default:
            return -1;
    }
}

// MUTANT 4: strcmp sans == 0
Command parse_command(const char *input)
{
    if (strcmp(input, "help"))  // strcmp retourne 0 si egal!
        return CMD_HELP;
}

// MUTANT 5: Enum values hardcodes
const char *execute_command(Command cmd)
{
    switch (cmd)
    {
        case 0:  // Au lieu de CMD_HELP - fragile si enum change
            return "Displaying help...";
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **switch-case** en C:
- `switch (expression)` : evalue une expression entiere
- `case value:` : branche si expression == value
- `default:` : branche si aucun case ne correspond
- `break;` : sort du switch (obligatoire sauf fall-through voulu)

### 5.3 Visualisation ASCII

```
switch(cmd)
    |
    +--[case CMD_HELP]---> "Displaying help..." ---> break/return
    |
    +--[case CMD_VERSION]--> "Version 1.0.0" ---> break/return
    |
    +--[case CMD_LIST]---> "Listing items..." ---> break/return
    |
    +--[default]---------> "Unknown command" ---> break/return
```

### 5.5 Cours Complet

#### Fall-through intentionnel

Parfois, on veut que plusieurs cases executent le meme code:

```c
switch (choice)
{
    case 1:
    case 2:
    case 3:
        // Code execute pour 1, 2, ou 3
        printf("Choice 1-3\n");
        break;
    case 4:
    case 5:
        // Code execute pour 4 ou 5
        printf("Choice 4-5\n");
        break;
    default:
        printf("Other\n");
}
```

#### Enumeration et switch

Les enumerations sont parfaites pour switch car:
- Valeurs entieres nommees
- Le compilateur peut avertir si un case manque
- Code plus lisible que des nombres magiques

---

## SECTION 7 : QCM

### Question 1
Que se passe-t-il si on oublie `break` dans un case ?

A) Erreur de compilation
B) Le programme crash
C) Fall-through: les cases suivants s'executent aussi
D) Le switch se termine
E) Undefined behavior

**Reponse correcte: C**

### Question 2
Peut-on utiliser une chaine de caracteres dans switch(str) ?

A) Oui, directement
B) Non, seulement des entiers/enums
C) Oui avec strcmp
D) Oui avec des pointeurs
E) Oui en C99+

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.7-b",
  "name": "switch_dispatcher",
  "language": "c",
  "language_version": "c17",
  "files": ["switch_dispatcher.c", "switch_dispatcher.h"],
  "tests": {
    "parse": ["help", "version", "list", "add", "remove", "quit", "invalid"],
    "dispatch": [1, 2, 3, 4, 5, 6, 0, 7, -1, 100]
  }
}
```
