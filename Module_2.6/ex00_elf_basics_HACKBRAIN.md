# Exercice 2.6.1-a : elf_check_magic

**Module :**
2.6.1 — Object File Formats

**Concept :**
a — ELF Magic Number Validation

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
cours_code

**Tiers :**
1 — Concept isolé

**Langage :**
C (version C17)

**Prérequis :**
- Manipulation de fichiers binaires
- Lecture d'en-têtes de structures
- Pointeurs et tableaux

**Domaines :**
FS, Encodage, Électro

**Durée estimée :**
45 min

**XP Base :**
120

**Complexité :**
T1 O(1) × S1 O(1)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier à rendre :**
- `elf_check_magic.c`

**Fonctions autorisées :**
- Aucune (implémentation pure)

**Fonctions interdites :**
- Toutes les fonctions de libc

**Compilation :**
```bash
gcc -Wall -Wextra -Werror -std=c17 elf_check_magic.c main.c -o elf_validator
```

### 1.2 Consigne

**🔮 La Signature Magique — Le Sceau des Anciens**

Dans le monde des binaires ELF (Executable and Linkable Format), chaque fichier commence par une signature sacrée : `0x7F 'E' 'L' 'F'`. Cette séquence de 4 octets agit comme un sceau magique qui permet au système d'exploitation de reconnaître instantanément un fichier ELF valide.

Imagine un bibliothécaire ancien qui vérifie l'authenticité d'un grimoire en regardant son sceau de cire. Si le sceau est intact et correct, le grimoire est authentique. Sinon, c'est un faux !

**Ta mission :**

Écrire une fonction `elf_check_magic` qui vérifie si les 4 premiers octets d'un fichier correspondent au magic number ELF.

**Entrée :**
- `ident` : pointeur vers un tableau de 16 octets (l'identification ELF, e_ident)

**Sortie :**
- Retourne `1` (vrai) si les 4 premiers octets sont `0x7F 'E' 'L' 'F'`
- Retourne `0` (faux) sinon
- Retourne `0` si `ident` est `NULL`

**Contraintes :**
- Vérifier exactement 4 octets dans l'ordre
- Le premier octet DOIT être `0x7F` (127 en décimal)
- Les trois suivants DOIVENT être 'E', 'L', 'F' (ASCII)
- Gérer le cas où `ident` est NULL

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `elf_check_magic(NULL)` | `0` | Pointeur invalide |
| `elf_check_magic("\x7F" "ELF" ...)` | `1` | Magic number valide |
| `elf_check_magic("\x7F" "ELX" ...)` | `0` | 3ème caractère incorrect |
| `elf_check_magic("ELF\x7F" ...)` | `0` | Ordre inversé |
| `elf_check_magic("\x00" "ELF" ...)` | `0` | Premier octet incorrect |

### 1.2.2 Énoncé Académique

La fonction doit implémenter une validation stricte des 4 premiers octets d'un tableau représentant l'en-tête d'identification ELF. La spécification ELF (Executable and Linkable Format) définit que tout fichier ELF valide commence par la séquence : `0x7F`, suivi des caractères ASCII 'E' (0x45), 'L' (0x4C), et 'F' (0x46). La fonction doit retourner une valeur booléenne (1 pour valide, 0 pour invalide) après avoir vérifié chacun de ces octets dans l'ordre exact.

### 1.3 Prototype

```c
int elf_check_magic(const unsigned char *ident);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

Le magic number `0x7F 'E' 'L' 'F'` a été choisi en 1995 par les créateurs du format ELF pour plusieurs raisons :

1. **`0x7F`** : C'est le dernier caractère ASCII imprimable (DEL), ce qui rend le fichier non-affichable directement avec `cat` ou `less`, évitant ainsi la confusion avec des fichiers texte.

2. **'ELF'** : Acronyme évident du format (Executable and Linkable Format), facilitant l'identification visuelle avec des outils comme `hexdump`.

3. **Détection d'erreurs** : Cette séquence unique permet une détection rapide et fiable du format, évitant d'exécuter accidentellement des fichiers corrompus ou incompatibles.

4. **Compatibilité** : Le format ELF a remplacé l'ancien format a.out (assembleur output) sur Unix et Linux, devenant le standard pour les systèmes UNIX modernes (Linux, BSD, Solaris).

### SECTION 2.5 : DANS LA VRAIE VIE

**Métiers concernés :** Développeur Systèmes, Ingénieur Sécurité, Reverse Engineer

**Cas d'usage concrets :**

1. **Développeur Systèmes (Linux Kernel Developer)** : Lors de la création de loaders et d'outils comme `execve()`, le noyau Linux vérifie le magic number pour décider comment charger un fichier en mémoire.

2. **Ingénieur Sécurité (Malware Analyst)** : Analyse les binaires suspects pour identifier s'ils sont des ELF légitimes ou des malwares déguisés. Un magic number invalide peut indiquer une tentative d'obfuscation.

3. **Reverse Engineer** : Utilise cette vérification dans des outils comme IDA Pro, Ghidra ou radare2 pour parser automatiquement les binaires et extraire les sections, symboles et code.

4. **DevOps (Container Engineer)** : Les systèmes comme Docker et Kubernetes vérifient les binaires ELF lors du déploiement d'images pour s'assurer qu'ils sont exécutables sur l'architecture cible.

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
elf_check_magic.c  main.c

$ gcc -Wall -Wextra -Werror -std=c17 elf_check_magic.c main.c -o elf_validator

$ ./elf_validator /bin/ls
✓ Valid ELF magic number: 7F 45 4C 46
File is a valid ELF binary

$ ./elf_validator /etc/passwd
✗ Invalid magic number: 72 6F 6F 74
File is NOT an ELF binary

$ ./elf_validator non_existent_file
Error: Cannot read file

$ echo "Test" > fake.elf
$ ./elf_validator fake.elf
✗ Invalid magic number: 54 65 73 74
File is NOT an ELF binary
```

### 3.1 ⚡ BONUS STANDARD (OPTIONNEL)

**Difficulté Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Récompense :**
XP ×2

**Time Complexity attendue :**
O(1)

**Space Complexity attendue :**
O(1)

**Domaines Bonus :**
Encodage, Crypto

#### 3.1.1 Consigne Bonus

**🔮 Le Détecteur Universel — Au-delà d'ELF**

Maintenant que tu maîtrises la détection ELF, étend ton détecteur pour reconnaître d'autres formats binaires courants : PE (Windows), Mach-O (macOS), et même les archives ZIP.

**Ta mission :**

Écrire une fonction `detect_binary_format` qui identifie le format d'un fichier binaire basé sur son magic number.

**Entrée :**
- `data` : pointeur vers les premiers octets du fichier (minimum 16 octets)

**Sortie :**
- Retourne une chaîne constante indiquant le format :
  - `"ELF"` si `0x7F 'E' 'L' 'F'`
  - `"PE"` si `'M' 'Z'` (DOS/Windows)
  - `"Mach-O 64"` si `0xFE 0xED 0xFA 0xCF`
  - `"Mach-O 32"` si `0xFE 0xED 0xFA 0xCE`
  - `"ZIP"` si `'P' 'K' 0x03 0x04`
  - `"Unknown"` sinon
- Retourne `NULL` si `data` est `NULL`

**Contraintes :**
┌─────────────────────────────────────────┐
│  data ≠ NULL                            │
│  Vérifier minimum 4 octets              │
│  Temps limite : O(1)                    │
│  Espace limite : O(1) auxiliaire        │
└─────────────────────────────────────────┘

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `detect_binary_format(NULL)` | `NULL` | Pointeur invalide |
| `detect_binary_format("\x7FELF")` | `"ELF"` | Magic ELF |
| `detect_binary_format("MZ")` | `"PE"` | Magic PE/DOS |
| `detect_binary_format("\xFE\xED\xFA\xCF")` | `"Mach-O 64"` | Magic Mach-O 64-bit |
| `detect_binary_format("PK\x03\x04")` | `"ZIP"` | Magic ZIP/JAR |

#### 3.1.2 Prototype Bonus

```c
const char *detect_binary_format(const unsigned char *data);
```

#### 3.1.3 Ce qui change par rapport à l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Formats détectés | 1 (ELF) | 5 (ELF, PE, Mach-O 32/64, ZIP) |
| Complexité | Simple comparaison | Détection multi-formats |
| Edge cases | NULL | NULL + formats ambigus |
| Retour | int (0/1) | const char* (nom format) |

---

## ✅❌ SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test | Entrée | Sortie Attendue | Piège ? | Points |
|------|--------|-----------------|---------|--------|
| null_pointer | `NULL` | `0` | ✓ Safety | 15 |
| valid_elf | `"\x7F" "ELF"` | `1` | - | 20 |
| invalid_first_byte | `"\x7E" "ELF"` | `0` | ✓ Boundary | 15 |
| invalid_E | `"\x7F" "ALF"` | `0` | ✓ Logic | 10 |
| invalid_L | `"\x7F" "EAF"` | `0` | ✓ Logic | 10 |
| invalid_F | `"\x7F" "ELA"` | `0` | ✓ Logic | 10 |
| reversed_order | `"FLE\x7F"` | `0` | ✓ Logic | 10 |
| all_zeros | `"\x00\x00\x00\x00"` | `0` | - | 5 |
| partial_match | `"\x7F" "EL"` | `0` | ✓ Boundary | 5 |

**Total : 100 points**

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int elf_check_magic(const unsigned char *ident);

typedef struct {
    const char *name;
    const unsigned char *input;
    int expected;
} test_case_t;

int main(void) {
    test_case_t tests[] = {
        {"null_pointer", NULL, 0},
        {"valid_elf", (unsigned char*)"\x7F" "ELF\x02\x01\x01\x00", 1},
        {"invalid_first_byte", (unsigned char*)"\x7E" "ELF\x02\x01", 0},
        {"invalid_E", (unsigned char*)"\x7F" "ALF\x02\x01", 0},
        {"invalid_L", (unsigned char*)"\x7F" "EAF\x02\x01", 0},
        {"invalid_F", (unsigned char*)"\x7F" "ELA\x02\x01", 0},
        {"reversed_order", (unsigned char*)"FLE\x7F\x02\x01", 0},
        {"all_zeros", (unsigned char*)"\x00\x00\x00\x00", 0},
    };

    int total = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;

    for (int i = 0; i < total; i++) {
        int result = elf_check_magic(tests[i].input);

        if (result == tests[i].expected) {
            printf("✓ Test %s: PASS\n", tests[i].name);
            passed++;
        } else {
            printf("✗ Test %s: FAIL (got %d, expected %d)\n",
                   tests[i].name, result, tests[i].expected);
        }
    }

    printf("\nResults: %d/%d tests passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
```

### 4.3 Solution de référence

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    if (ident[0] != 0x7F)
        return (0);
    if (ident[1] != 'E')
        return (0);
    if (ident[2] != 'L')
        return (0);
    if (ident[3] != 'F')
        return (0);

    return (1);
}
```

### 4.4 Solutions alternatives acceptées

**Solution 1 : Comparaison en une ligne**

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    return (ident[0] == 0x7F && ident[1] == 'E' &&
            ident[2] == 'L' && ident[3] == 'F');
}
```

**Solution 2 : Avec constantes nommées**

```c
#define ELF_MAG0 0x7F
#define ELF_MAG1 'E'
#define ELF_MAG2 'L'
#define ELF_MAG3 'F'

int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    return (ident[0] == ELF_MAG0 && ident[1] == ELF_MAG1 &&
            ident[2] == ELF_MAG2 && ident[3] == ELF_MAG3);
}
```

### 4.5 Solutions refusées (avec explications)

**Solution refusée 1 : Pas de vérification NULL**

```c
int elf_check_magic(const unsigned char *ident)
{
    // ❌ SEGFAULT si ident == NULL
    return (ident[0] == 0x7F && ident[1] == 'E' &&
            ident[2] == 'L' && ident[3] == 'F');
}
```
**Pourquoi c'est refusé :** Pas de gestion du cas NULL, provoque un segmentation fault.

**Solution refusée 2 : Comparaison de chaîne**

```c
#include <string.h>

int elf_check_magic(const unsigned char *ident)
{
    // ❌ Utilise une fonction interdite + bug avec 0x7F
    return (strcmp((char*)ident, "\x7FELF") == 0);
}
```
**Pourquoi c'est refusé :** Utilise `strcmp` (interdit), et ne vérifie que jusqu'au premier '\0'.

**Solution refusée 3 : Conversion en entier**

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    // ❌ Problème d'endianness
    unsigned int magic = *(unsigned int*)ident;
    return (magic == 0x464C457F);
}
```
**Pourquoi c'est refusé :** Dépend de l'endianness de la machine (little vs big endian).

### 4.6 Solution bonus de référence (COMPLÈTE)

```c
const char *detect_binary_format(const unsigned char *data)
{
    if (data == NULL)
        return (NULL);

    // ELF: 0x7F 'E' 'L' 'F'
    if (data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F')
        return ("ELF");

    // PE/DOS: 'M' 'Z'
    if (data[0] == 'M' && data[1] == 'Z')
        return ("PE");

    // Mach-O 64-bit: 0xFE 0xED 0xFA 0xCF
    if (data[0] == 0xFE && data[1] == 0xED &&
        data[2] == 0xFA && data[3] == 0xCF)
        return ("Mach-O 64");

    // Mach-O 32-bit: 0xFE 0xED 0xFA 0xCE
    if (data[0] == 0xFE && data[1] == 0xED &&
        data[2] == 0xFA && data[3] == 0xCE)
        return ("Mach-O 32");

    // ZIP: 'P' 'K' 0x03 0x04
    if (data[0] == 'P' && data[1] == 'K' &&
        data[2] == 0x03 && data[3] == 0x04)
        return ("ZIP");

    return ("Unknown");
}
```

### 4.7 Solutions alternatives bonus (COMPLÈTES)

**Solution bonus alternative : Avec tableau de structures**

```c
typedef struct {
    unsigned char magic[4];
    const char *name;
} format_t;

const char *detect_binary_format(const unsigned char *data)
{
    if (data == NULL)
        return (NULL);

    static const format_t formats[] = {
        {{0x7F, 'E', 'L', 'F'}, "ELF"},
        {{'M', 'Z', 0, 0}, "PE"},
        {{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O 64"},
        {{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O 32"},
        {{'P', 'K', 0x03, 0x04}, "ZIP"},
    };

    for (int i = 0; i < 5; i++) {
        int match = 1;
        for (int j = 0; j < 4; j++) {
            if (formats[i].magic[j] != 0 && data[j] != formats[i].magic[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return (formats[i].name);
    }

    return ("Unknown");
}
```

### 4.8 Solutions refusées bonus (COMPLÈTES)

**Solution bonus refusée : Allocation dynamique inutile**

```c
#include <stdlib.h>
#include <string.h>

const char *detect_binary_format(const unsigned char *data)
{
    if (data == NULL)
        return (NULL);

    // ❌ Allocation inutile + fuite mémoire
    char *result = malloc(20);

    if (data[0] == 0x7F && data[1] == 'E')
        strcpy(result, "ELF");
    else
        strcpy(result, "Unknown");

    return (result); // ❌ Fuite mémoire !
}
```
**Pourquoi c'est refusé :** Allocation dynamique non nécessaire, fuite mémoire garantie.

### 4.9 spec.json (ENGINE v22.1 — FORMAT STRICT)

```json
{
  "name": "elf_check_magic",
  "language": "c",
  "type": "cours_code",
  "tier": 1,
  "tier_info": "Concept isolé",
  "tags": ["elf", "binary", "magic_number", "validation"],
  "passing_score": 70,

  "function": {
    "name": "elf_check_magic",
    "prototype": "int elf_check_magic(const unsigned char *ident)",
    "return_type": "int",
    "parameters": [
      {"name": "ident", "type": "const unsigned char *"}
    ]
  },

  "driver": {
    "reference": "int ref_elf_check_magic(const unsigned char *ident) { if (ident == NULL) return (0); if (ident[0] != 0x7F) return (0); if (ident[1] != 'E') return (0); if (ident[2] != 'L') return (0); if (ident[3] != 'F') return (0); return (1); }",

    "edge_cases": [
      {
        "name": "null_pointer",
        "args": [null],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "ident est NULL, doit retourner 0"
      },
      {
        "name": "valid_elf",
        "args": [[127, 69, 76, 70, 2, 1, 1, 0]],
        "expected": 1
      },
      {
        "name": "invalid_first_byte",
        "args": [[126, 69, 76, 70, 2, 1]],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Premier octet incorrect (126 au lieu de 127)"
      },
      {
        "name": "invalid_E",
        "args": [[127, 65, 76, 70, 2, 1]],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Deuxième octet incorrect (A au lieu de E)"
      },
      {
        "name": "reversed_order",
        "args": [[70, 76, 69, 127, 2, 1]],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Ordre inversé du magic number"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "array_int",
          "param_index": 0,
          "params": {
            "min_len": 16,
            "max_len": 16,
            "min_val": 0,
            "max_val": 255
          }
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": [],
    "forbidden_functions": ["strcmp", "memcmp", "strncmp"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Vérification incomplète**

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    // ❌ Ne vérifie que 3 octets au lieu de 4
    if (ident[0] != 0x7F)
        return (0);
    if (ident[1] != 'E')
        return (0);
    if (ident[2] != 'L')
        return (0);
    // ❌ Oubli de vérifier ident[3]

    return (1);
}
```
**Pourquoi c'est faux :** Ne vérifie pas le 4ème octet ('F'), accepte n'importe quel caractère à cette position.
**Ce qui était pensé :** "3 octets suffisent pour identifier ELF".

**Mutant B (Safety) : Pas de vérification NULL**

```c
int elf_check_magic(const unsigned char *ident)
{
    // ❌ Pas de vérification NULL
    if (ident[0] != 0x7F)
        return (0);
    if (ident[1] != 'E')
        return (0);
    if (ident[2] != 'L')
        return (0);
    if (ident[3] != 'F')
        return (0);

    return (1);
}
```
**Pourquoi c'est faux :** Segmentation fault si `ident` est NULL.
**Ce qui était pensé :** "Le pointeur sera toujours valide".

**Mutant C (Resource) : Utilisation de fonction interdite**

```c
#include <string.h>

int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    // ❌ Utilise memcmp (fonction interdite)
    const unsigned char magic[] = {0x7F, 'E', 'L', 'F'};
    return (memcmp(ident, magic, 4) == 0);
}
```
**Pourquoi c'est faux :** Utilise `memcmp`, fonction interdite dans l'exercice.
**Ce qui était pensé :** "memcmp est plus élégant".

**Mutant D (Logic) : Mauvaise valeur pour 0x7F**

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    // ❌ 127 en décimal au lieu de 0x7F (127 aussi, mais confusion)
    if (ident[0] != 128) // ❌ 128 au lieu de 127
        return (0);
    if (ident[1] != 'E')
        return (0);
    if (ident[2] != 'L')
        return (0);
    if (ident[3] != 'F')
        return (0);

    return (1);
}
```
**Pourquoi c'est faux :** Compare avec 128 au lieu de 127 (0x7F).
**Ce qui était pensé :** "0x7F = 128" (erreur de conversion hexadécimal).

**Mutant E (Return) : Logique inversée**

```c
int elf_check_magic(const unsigned char *ident)
{
    if (ident == NULL)
        return (0);

    if (ident[0] != 0x7F)
        return (1); // ❌ Inversé
    if (ident[1] != 'E')
        return (1); // ❌ Inversé
    if (ident[2] != 'L')
        return (1); // ❌ Inversé
    if (ident[3] != 'F')
        return (1); // ❌ Inversé

    return (0); // ❌ Inversé
}
```
**Pourquoi c'est faux :** Retourne 1 quand invalide et 0 quand valide (logique inversée).
**Ce qui était pensé :** "1 = erreur, 0 = succès" (confusion avec codes de sortie).

---

## 🧠 SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Cet exercice enseigne le concept fondamental de **magic number** en informatique, spécifiquement dans le contexte du format ELF. Tu apprends :

1. **Validation de format binaire** : Comment identifier rapidement et fiablement un type de fichier
2. **Lecture d'octets bruts** : Manipulation de données binaires non-textuelles
3. **Spécification ELF** : Premier pas dans la compréhension du format exécutable Linux
4. **Gestion d'erreurs** : Vérification de pointeurs NULL avant accès mémoire
5. **Optimisation** : Algorithme O(1) avec comparaison directe d'octets

**Compétences transférables :**
- Parser des formats binaires (images, audio, vidéo, protocoles réseau)
- Créer des outils bas-niveau (linkers, loaders, debuggers)
- Comprendre comment l'OS charge et exécute des programmes

### 5.2 LDA — Traduction littérale en français (MAJUSCULES)

```
FONCTION elf_check_magic QUI RETOURNE UN ENTIER ET PREND EN PARAMÈTRE ident QUI EST UN POINTEUR VERS UN TABLEAU D'OCTETS NON SIGNÉS CONSTANT
DÉBUT FONCTION
    SI ident EST ÉGAL À NUL ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    SI L'OCTET À LA POSITION 0 DANS ident EST DIFFÉRENT DE 0x7F ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    SI L'OCTET À LA POSITION 1 DANS ident EST DIFFÉRENT DE 'E' ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    SI L'OCTET À LA POSITION 2 DANS ident EST DIFFÉRENT DE 'L' ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    SI L'OCTET À LA POSITION 3 DANS ident EST DIFFÉRENT DE 'F' ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    RETOURNER LA VALEUR 1
FIN FONCTION
```

### 5.2.2 Style Académique Universitaire

La fonction `elf_check_magic` implémente une procédure de validation du préfixe d'identification ELF selon la spécification formelle définie par le System V Application Binary Interface.

Elle effectue une vérification séquentielle de quatre octets constitutifs de la signature ELF :
1. Vérification du pointeur pour éviter toute référence invalide (NULL pointer dereference)
2. Validation de l'octet d'échappement (0x7F) à l'offset 0
3. Validation des trois caractères ASCII formant l'acronyme "ELF" aux offsets 1, 2, et 3

La fonction retourne un booléen entier (1 pour valide, 0 pour invalide) conformément aux conventions C.

### 5.2.2.1 Logic Flow (Structured English)

```
ALGORITHM: ELF Magic Number Validation
---
1. INPUT: ident (pointer to unsigned char array)

2. GUARD CLAUSE:
   IF ident is NULL THEN
       RETURN 0 (invalid)

3. VALIDATE each byte sequentially:
   a. CHECK byte[0] == 0x7F (escape character)
      IF NOT THEN RETURN 0

   b. CHECK byte[1] == 'E' (ASCII 69)
      IF NOT THEN RETURN 0

   c. CHECK byte[2] == 'L' (ASCII 76)
      IF NOT THEN RETURN 0

   d. CHECK byte[3] == 'F' (ASCII 70)
      IF NOT THEN RETURN 0

4. ALL checks passed:
   RETURN 1 (valid ELF magic)
```

### 5.2.3 Représentation Algorithmique

```
FONCTION : elf_check_magic (ident)
---
INIT résultat = {success: False}

1. GUARD: Vérification pointeur
   |
   |-- SI ident est NULL :
   |     RETOURNER 0 (Erreur: pointeur invalide)

2. VALIDATION séquentielle des 4 octets :
   |
   |-- VÉRIFIER octet[0] == 0x7F :
   |     |
   |     |-- SI NON ÉGAL :
   |           RETOURNER 0 (Erreur: premier octet invalide)
   |
   |-- VÉRIFIER octet[1] == 'E' :
   |     |
   |     |-- SI NON ÉGAL :
   |           RETOURNER 0 (Erreur: deuxième octet invalide)
   |
   |-- VÉRIFIER octet[2] == 'L' :
   |     |
   |     |-- SI NON ÉGAL :
   |           RETOURNER 0 (Erreur: troisième octet invalide)
   |
   |-- VÉRIFIER octet[3] == 'F' :
   |     |
   |     |-- SI NON ÉGAL :
   |           RETOURNER 0 (Erreur: quatrième octet invalide)

3. TOUS LES OCTETS VALIDES :
   RETOURNER 1 (Succès: magic number ELF valide)
```

### 5.2.3.1 Diagramme Mermaid (Logique de Garde)

```mermaid
graph TD
    A[Début: elf_check_magic] --> B{ident == NULL?}
    B -- Oui --> C[RETOUR: 0 - Pointeur invalide]
    B -- Non --> D{ident[0] == 0x7F?}

    D -- Non --> E[RETOUR: 0 - Premier octet invalide]
    D -- Oui --> F{ident[1] == 'E'?}

    F -- Non --> G[RETOUR: 0 - Deuxième octet invalide]
    F -- Oui --> H{ident[2] == 'L'?}

    H -- Non --> I[RETOUR: 0 - Troisième octet invalide]
    H -- Oui --> J{ident[3] == 'F'?}

    J -- Non --> K[RETOUR: 0 - Quatrième octet invalide]
    J -- Oui --> L[RETOUR: 1 - Magic number valide]
```

### 5.3 Visualisation ASCII (adaptée au sujet)

**Structure d'un fichier ELF (premiers octets) :**

```
Offset    Hexadécimal    Décimal    ASCII    Description
┌────────┬──────────────┬──────────┬────────┬──────────────────────────┐
│ 0x00   │     7F       │   127    │  DEL   │ Magic byte 0 (escape)    │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x01   │     45       │    69    │   E    │ Magic byte 1             │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x02   │     4C       │    76    │   L    │ Magic byte 2             │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x03   │     46       │    70    │   F    │ Magic byte 3             │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x04   │     02       │     2    │        │ Class (64-bit)           │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x05   │     01       │     1    │        │ Endianness (little)      │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x06   │     01       │     1    │        │ Version                  │
├────────┼──────────────┼──────────┼────────┼──────────────────────────┤
│ 0x07   │     00       │     0    │        │ OS/ABI (UNIX System V)   │
└────────┴──────────────┴──────────┴────────┴──────────────────────────┘
```

**Flux de vérification :**

```
ident[0]     ident[1]     ident[2]     ident[3]
┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐
│ 7F  │──?───│ 45  │──?───│ 4C  │──?───│ 46  │
└──┬──┘      └──┬──┘      └──┬──┘      └──┬──┘
   │            │            │            │
   ▼            ▼            ▼            ▼
┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐
│ OK  │      │ OK  │      │ OK  │      │ OK  │
└──┬──┘      └──┬──┘      └──┬──┘      └──┬──┘
   │            │            │            │
   └────────────┴────────────┴────────────┘
                     │
                     ▼
              ┌──────────────┐
              │ RETURN 1 ✓   │
              └──────────────┘

Si UN SEUL échoue → RETURN 0 ✗
```

### 5.4 Les pièges en détail

#### Piège 1 : Oublier la vérification NULL

```c
// ❌ DANGER
int elf_check_magic(const unsigned char *ident)
{
    // Accès direct sans vérifier NULL
    return (ident[0] == 0x7F && ...);
    // → SEGFAULT si ident == NULL
}
```

**Solution :**
```c
// ✅ CORRECT
if (ident == NULL)
    return (0);
```

#### Piège 2 : Confondre 0x7F avec autre chose

```c
// ❌ ERREUR : 127 en octal = 87 en décimal
if (ident[0] != 0127)  // 0127 octal = 87 décimal ≠ 127

// ❌ ERREUR : Caractère ASCII DEL
if (ident[0] != '\x7F')  // Marche, mais moins clair

// ✅ CORRECT
if (ident[0] != 0x7F)  // Hexadécimal, clair et précis
```

#### Piège 3 : Utiliser strcmp ou memcmp

```c
// ❌ NE MARCHE PAS
strcmp((char*)ident, "\x7FELF")
// → strcmp s'arrête au premier '\0', ne compare pas 0x7F correctement

// ❌ INTERDIT (fonction interdite)
memcmp(ident, "\x7FELF", 4)
```

#### Piège 4 : Problème d'endianness avec conversion entier

```c
// ❌ DÉPEND DE L'ARCHITECTURE
unsigned int magic = *(unsigned int*)ident;
if (magic == 0x464C457F)  // Marche sur x86 (little-endian)
                          // Échoue sur ARM big-endian (0x7F454C46)
```

**Solution :** Comparer octet par octet, pas en bloc.

#### Piège 5 : Ordre des octets

```c
// ❌ ORDRE INVERSÉ
if (ident[0] == 'F' && ident[1] == 'L' &&
    ident[2] == 'E' && ident[3] == 0x7F)
// → "FLE\x7F" au lieu de "\x7FELF"
```

### 5.5 Cours Complet (VRAI cours, pas un résumé)

#### Chapitre 1 : Les Magic Numbers en Informatique

Un **magic number** (nombre magique) est une séquence de bytes constante placée au début d'un fichier pour identifier son format. C'est comme une signature ou un sceau.

**Pourquoi utiliser des magic numbers ?**

1. **Détection rapide du format** : En lisant seulement les premiers octets, on sait quel type de fichier on a.
2. **Sécurité** : Empêche d'ouvrir un fichier avec le mauvais programme (ex : ouvrir une image avec un éditeur texte).
3. **Robustesse** : Détecte les fichiers corrompus ou mal formés.
4. **Compatibilité** : Permet de supporter plusieurs versions d'un format.

**Exemples de magic numbers courants :**

| Format | Magic Number | Hex | Description |
|--------|--------------|-----|-------------|
| ELF | `0x7F` 'E' 'L' 'F' | `7F 45 4C 46` | Exécutables Linux |
| PE | 'M' 'Z' | `4D 5A` | Exécutables Windows |
| PNG | `0x89` 'P' 'N' 'G' | `89 50 4E 47` | Images PNG |
| JPEG | `0xFF` `0xD8` `0xFF` | `FF D8 FF` | Images JPEG |
| ZIP | 'P' 'K' `0x03` `0x04` | `50 4B 03 04` | Archives ZIP |
| PDF | '%' 'P' 'D' 'F' | `25 50 44 46` | Documents PDF |

#### Chapitre 2 : Le Format ELF (Executable and Linkable Format)

**Histoire :**
- Créé en 1995 par Unix System Laboratories
- Remplace l'ancien format a.out
- Standard sur Linux, BSD, Solaris

**Structure d'un fichier ELF :**

```
┌─────────────────────────────────────┐
│      ELF Header (52 ou 64 bytes)    │  ← Notre exercice se concentre ici
├─────────────────────────────────────┤
│      Program Headers (segments)     │
├─────────────────────────────────────┤
│      Sections (.text, .data, etc.)  │
├─────────────────────────────────────┤
│      Section Headers                │
└─────────────────────────────────────┘
```

**ELF Header (e_ident - 16 premiers octets) :**

```c
unsigned char e_ident[16];
```

| Offset | Champ | Valeur | Description |
|--------|-------|--------|-------------|
| 0-3 | Magic | `7F 45 4C 46` | Identification ELF |
| 4 | Class | `01` ou `02` | 32-bit ou 64-bit |
| 5 | Data | `01` ou `02` | Little ou Big Endian |
| 6 | Version | `01` | Version ELF (toujours 1) |
| 7 | OS/ABI | `00-FF` | OS cible |
| 8 | ABI Version | `00` | Version ABI |
| 9-15 | Padding | `00...` | Réservé (zéros) |

#### Chapitre 3 : Pourquoi 0x7F pour ELF ?

**Choix stratégique :**

1. **0x7F = DEL en ASCII** : C'est le dernier caractère de la table ASCII (127 en décimal).
2. **Non-imprimable** : Si tu fais `cat /bin/ls`, tu verras des caractères bizarres, pas du texte lisible.
3. **Détection automatique** : Les outils comme `file` peuvent identifier un ELF instantanément.

**Comparaison avec d'autres formats :**

```
ELF:   0x7F E L F  → Commence par un octet non-ASCII
PE:    M Z         → Commence par des caractères ASCII (Mark Zbikowski)
PNG:   0x89 P N G  → Mélange (0x89 non-ASCII, puis ASCII)
```

#### Chapitre 4 : Implémentation de la Vérification

**Algorithme :**

1. **Vérifier NULL** : Toujours vérifier qu'un pointeur n'est pas NULL avant de le déréférencer.
2. **Comparer octet par octet** : Ne pas utiliser `strcmp` (s'arrête au '\0') ni `memcmp` (interdit).
3. **Ordre strict** : `0x7F` en premier, puis 'E', 'L', 'F'.
4. **Retour booléen** : 1 si valide, 0 sinon.

**Complexité :**
- **Temps** : O(1) - Toujours 4 comparaisons maximum
- **Espace** : O(1) - Pas d'allocation dynamique

#### Chapitre 5 : Cas d'usage dans le monde réel

**1. Le noyau Linux (`execve` syscall)**

Quand tu exécutes un programme avec `./mon_programme`, le noyau :
1. Ouvre le fichier
2. Lit les 4 premiers octets
3. Vérifie le magic number
4. Si c'est ELF, charge le binaire en mémoire
5. Sinon, retourne une erreur `Exec format error`

**2. Les outils de debugging (GDB, LLDB)**

```bash
$ gdb /bin/ls
Reading symbols from /bin/ls...
# GDB vérifie le magic ELF pour parser le binaire
```

**3. Les analyseurs de malware**

Les analystes vérifient si un fichier suspect :
- A un magic number valide (binaire légitime)
- A un magic number modifié (tentative d'obfuscation)
- N'a pas de magic number (fichier corrompu ou shellcode brut)

**4. Les conteneurs Docker**

Docker vérifie que les binaires dans les images sont des ELF valides pour l'architecture cible (x86_64, ARM, etc.).

### 5.6 Normes avec explications pédagogiques

┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (compile, mais interdit)                          │
├─────────────────────────────────────────────────────────────────┤
│ int elf_check_magic(const unsigned char *ident) {              │
│     if(!ident)return 0;                                         │
│     return ident[0]==0x7F&&ident[1]=='E'&&ident[2]=='L'&&ident[3]=='F'; │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ int elf_check_magic(const unsigned char *ident)                │
│ {                                                               │
│     if (ident == NULL)                                          │
│         return (0);                                             │
│                                                                 │
│     if (ident[0] != 0x7F)                                       │
│         return (0);                                             │
│     if (ident[1] != 'E')                                        │
│         return (0);                                             │
│     if (ident[2] != 'L')                                        │
│         return (0);                                             │
│     if (ident[3] != 'F')                                        │
│         return (0);                                             │
│                                                                 │
│     return (1);                                                 │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Espaces : `if (` au lieu de `if(` → Distingue mots-clés       │
│ • Retour : `return (0)` au lieu de `return 0` → Cohérence       │
│ • Accolades : Sur lignes séparées → Lecture visuelle            │
│ • Lisibilité : Une vérification par ligne → Debug facile        │
│ • Maintenabilité : Code clair = moins de bugs                   │
└─────────────────────────────────────────────────────────────────┘

**Règle spécifique : `const` sur les pointeurs**

| ❌ Hors Norme | ✅ Conforme | 📖 Pourquoi |
|--------------|-------------|-------------|
| `unsigned char *ident` | `const unsigned char *ident` | Indique qu'on ne modifie pas les données |

### 5.7 Simulation avec trace d'exécution

**Exemple : Vérification d'un fichier ELF valide**

```c
unsigned char test[] = {0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
int result = elf_check_magic(test);
```

**Trace d'exécution :**

```
┌───────┬────────────────────────────────────────┬────────┬─────────────────────┐
│ Étape │ Instruction                            │ Retour │ Explication         │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   1   │ Entrée dans la fonction                │   —    │ ident pointe vers   │
│       │                                        │        │ test                │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   2   │ SI ident EST ÉGAL À NUL ?              │   —    │ FAUX, ident = &test │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   3   │ SI ident[0] DIFFÉRENT DE 0x7F ?        │   —    │ FAUX, ident[0]=0x7F │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   4   │ SI ident[1] DIFFÉRENT DE 'E' ?         │   —    │ FAUX, ident[1]='E'  │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   5   │ SI ident[2] DIFFÉRENT DE 'L' ?         │   —    │ FAUX, ident[2]='L'  │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   6   │ SI ident[3] DIFFÉRENT DE 'F' ?         │   —    │ FAUX, ident[3]='F'  │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   7   │ RETOURNER LA VALEUR 1                  │   1    │ Magic number valide │
└───────┴────────────────────────────────────────┴────────┴─────────────────────┘
```

**Exemple : Fichier invalide (PNG au lieu d'ELF)**

```c
unsigned char png[] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
int result = elf_check_magic(png);
```

**Trace d'exécution :**

```
┌───────┬────────────────────────────────────────┬────────┬─────────────────────┐
│ Étape │ Instruction                            │ Retour │ Explication         │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   1   │ Entrée dans la fonction                │   —    │ ident pointe vers   │
│       │                                        │        │ png                 │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   2   │ SI ident EST ÉGAL À NUL ?              │   —    │ FAUX, ident = &png  │
├───────┼────────────────────────────────────────┼────────┼─────────────────────┤
│   3   │ SI ident[0] DIFFÉRENT DE 0x7F ?        │   0    │ VRAI, ident[0]=0x89 │
│       │                                        │        │ ≠ 0x7F              │
│       │ RETOURNER LA VALEUR 0                  │        │ → Sortie immédiate  │
└───────┴────────────────────────────────────────┴────────┴─────────────────────┘
```

**Visualisation mémoire :**

```
Mémoire : test (ELF valide)

Offset :     0      1      2      3      4      5      6      7
           ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
Hex :      │ 7F   │ 45   │ 4C   │ 46   │ 02   │ 01   │ 01   │ 00   │
           ├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
ASCII :    │ DEL  │  E   │  L   │  F   │      │      │      │      │
           └──┬───┴──┬───┴──┬───┴──┬───┴──────┴──────┴──────┴──────┘
              │      │      │      │
              ✓      ✓      ✓      ✓  → Tous valides → RETURN 1


Mémoire : png (PNG, pas ELF)

Offset :     0      1      2      3      4      5      6      7
           ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
Hex :      │ 89   │ 50   │ 4E   │ 47   │ 0D   │ 0A   │ 1A   │ 0A   │
           ├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
ASCII :    │      │  P   │  N   │  G   │      │      │      │      │
           └──┬───┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
              │
              ✗  89 ≠ 7F → Échec immédiat → RETURN 0
```

### 5.8 Mnémotechniques (MEME obligatoire)

#### 🔮 MEME : "Show me your ID" — Le Videur de Boîte de Nuit

Imagine un videur de boîte de nuit (le kernel Linux) qui vérifie les cartes d'identité (magic numbers) à l'entrée.

**Scénario :**

- **Bon ID (ELF)** : "Ah, 0x7F-E-L-F, parfait ! Entre, tu es un exécutable légitime."
- **Faux ID (PNG)** : "0x89-P-N-G ? Désolé, c'est une boîte pour binaires, pas pour images. Dehors !"
- **Pas d'ID (NULL)** : "Pas de carte ? SEGFAULT, appelle la sécurité !"

```c
int elf_check_magic(const unsigned char *ident)
{
    // 🚪 Le videur demande à voir l'ID
    if (ident == NULL)
        return (0);  // "Pas d'ID ? Dégage !"

    // 🔍 Vérification de chaque caractère de l'ID
    if (ident[0] != 0x7F)
        return (0);  // "Premier caractère faux, c'est un fake !"
    if (ident[1] != 'E')
        return (0);  // "Deuxième caractère ? Non, c'est pas bon."
    if (ident[2] != 'L')
        return (0);  // "Troisième ? Nope."
    if (ident[3] != 'F')
        return (0);  // "Quatrième ? Faux ID !"

    return (1);  // "ID vérifié, entre dans le club ELF !"
}
```

---

#### 🎮 MEME : "Konami Code" — La Séquence Secrète

Le magic number ELF, c'est comme le Konami Code des jeux vidéo : ↑ ↑ ↓ ↓ ← → ← → B A.

Si tu entres la séquence EXACTE, tu déverrouilles le niveau. Si tu te trompes d'une touche ? Rien ne se passe.

**Magic ELF = Konami Code des binaires :**

```
0x7F  →  'E'  →  'L'  →  'F'
  ↑       ↑       ↑       ↑
Première Deuxième Troisième Quatrième touche

UN SEUL FAUX MOUVEMENT → GAME OVER (return 0)
SÉQUENCE PARFAITE → LEVEL UNLOCKED (return 1)
```

---

#### 📜 MEME : "Le Sceau de Dumbledore" — Harry Potter

Dans Harry Potter, les lettres de Poudlard ont le sceau de cire avec le blason de l'école. Si le sceau est brisé ou absent, la lettre n'est pas authentique.

Le magic number ELF, c'est pareil : `0x7F 'E' 'L' 'F'` est le sceau qui prouve qu'un fichier vient bien du monde des exécutables ELF.

**Analogie :**

```
Sceau de Poudlard     Magic Number ELF
┌─────────────┐       ┌─────────────┐
│   🦁 🦅     │       │  0x7F 'ELF' │
│   🦡 🐍     │       │             │
└─────────────┘       └─────────────┘
  Authentique            Authentique
```

Sans sceau → Faux courrier
Sans magic → Faux binaire

---

#### 💀 MEME : "Password Incorrect" — Login Screen

Tu connais ce moment frustrant où tu entres ton mot de passe et ça affiche "Password Incorrect" ?

La fonction `elf_check_magic` fait EXACTEMENT la même chose :
- Mot de passe attendu : `0x7F E L F`
- Tu entres : `0x89 P N G`
- Résultat : ❌ ACCESS DENIED (return 0)

```
┌────────────────────────────────────┐
│  SYSTEM LOGIN                      │
│                                    │
│  Password: ****                    │
│                                    │
│  Expected: 0x7F E L F              │
│  Entered:  0x89 P N G              │
│                                    │
│  ❌ ACCESS DENIED                  │
│  return (0);                       │
└────────────────────────────────────┘
```

### 5.9 Applications pratiques

#### Application 1 : Créer un détecteur de format de fichier

Tu peux étendre cette fonction pour créer un outil comme `file` sous Linux :

```c
void detect_file_type(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    unsigned char magic[16];
    fread(magic, 1, 16, fp);

    if (elf_check_magic(magic))
        printf("%s: ELF executable\n", filename);
    else if (magic[0] == 0x89 && magic[1] == 'P')
        printf("%s: PNG image\n", filename);
    else if (magic[0] == 'M' && magic[1] == 'Z')
        printf("%s: Windows PE executable\n", filename);
    else
        printf("%s: Unknown format\n", filename);

    fclose(fp);
}
```

#### Application 2 : Vérifier l'intégrité avant exécution

Dans un système embarqué ou un bootloader, tu dois vérifier que le binaire à charger est valide :

```c
int load_and_execute(const char *path)
{
    unsigned char header[16];

    // Lire l'en-tête
    read_file_header(path, header, 16);

    // Vérifier le magic
    if (!elf_check_magic(header)) {
        printf("Error: Not a valid ELF file\n");
        return -1;
    }

    // Charger et exécuter
    load_elf(path);
    return 0;
}
```

#### Application 3 : Analyse de malware

Les analystes de sécurité utilisent cette vérification pour détecter des binaires modifiés :

```c
void analyze_binary(const char *file)
{
    unsigned char magic[4];
    read_bytes(file, magic, 4);

    if (!elf_check_magic(magic)) {
        printf("WARNING: Invalid or modified ELF header!\n");
        printf("Possible malware or corrupted file.\n");
        // Analyse approfondie...
    }
}
```

#### Application 4 : Parser d'ELF custom

Pour créer ton propre debugger ou linker, tu commences toujours par vérifier le magic :

```c
typedef struct {
    unsigned char ident[16];
    // ... autres champs
} elf_header_t;

int parse_elf(const char *path, elf_header_t *header)
{
    // Lire l'en-tête
    read_elf_header(path, header);

    // Vérifier le magic
    if (!elf_check_magic(header->ident)) {
        return -1;  // Erreur
    }

    // Parser le reste...
    parse_sections(path);
    parse_symbols(path);
    return 0;
}
```

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

| Piège | Description | Conséquence | Solution |
|-------|-------------|-------------|----------|
| **NULL non vérifié** | Accès direct à `ident[0]` | SEGFAULT | `if (ident == NULL) return (0);` |
| **Ordre inversé** | Vérifier 'FLE\x7F' | Faux négatif | Ordre strict : 0x7F, E, L, F |
| **strcmp/memcmp** | Utiliser fonctions interdites | Ne compile pas | Comparaison manuelle |
| **Endianness** | Conversion en `int` | Bug sur ARM/MIPS | Comparer octet par octet |
| **Vérification partielle** | Oublier un des 4 octets | Faux positif | Vérifier les 4 octets |
| **Confusion 0x7F** | Utiliser 128 au lieu de 127 | Faux négatif | Toujours 0x7F en hexa |

---

## 📝 SECTION 7 : QCM

**Question 1 : Quel est le magic number d'un fichier ELF ?**

A. `0x7F 'E' 'L' 'F'`
B. `'E' 'L' 'F' 0x7F`
C. `0x45 0x4C 0x46 0x7F`
D. `'M' 'Z'`
E. `0x89 'P' 'N' 'G'`
F. `0xFF 0xD8 0xFF`
G. `'E' 'L' 'F' '\0'`
H. `0x00 'E' 'L' 'F'`
I. `0x7E 'E' 'L' 'F'`
J. `'\x7F' "ELF"`

**Réponse correcte :** A

**Explication :** Le magic number ELF est toujours `0x7F` suivi des caractères ASCII 'E', 'L', 'F'.

---

**Question 2 : Pourquoi utilise-t-on 0x7F comme premier octet ?**

A. C'est le caractère DEL (non-imprimable)
B. C'est le caractère NULL
C. C'est un caractère aléatoire
D. C'est plus rapide à vérifier
E. C'est le premier caractère ASCII
F. C'est un nombre premier
G. C'est 128 en décimal
H. C'est le caractère '\0'
I. C'est un octet de padding
J. C'est le début de l'UTF-8

**Réponse correcte :** A

**Explication :** 0x7F = DEL (127), dernier caractère ASCII, non-imprimable. Empêche la confusion avec des fichiers texte.

---

**Question 3 : Que se passe-t-il si on oublie de vérifier NULL ?**

A. Segmentation fault si ident == NULL
B. Retourne toujours 0
C. Retourne toujours 1
D. Comportement indéfini
E. Erreur de compilation
F. Le programme plante au démarrage
G. Fuite mémoire
H. Boucle infinie
I. Rien, le compilateur optimise
J. Warning uniquement

**Réponse correcte :** A

**Explication :** Déréférencer un pointeur NULL (`ident[0]`) provoque un segmentation fault.

---

**Question 4 : Quelle est la complexité temporelle de elf_check_magic ?**

A. O(1)
B. O(n)
C. O(log n)
D. O(n²)
E. O(n log n)
F. O(2^n)
G. O(n!)
H. O(√n)
I. O(4)
J. O(∞)

**Réponse correcte :** A

**Explication :** Toujours exactement 4 comparaisons maximum, indépendamment de la taille du fichier.

---

**Question 5 : Pourquoi ne pas utiliser memcmp pour comparer ?**

A. Fonction interdite dans l'exercice
B. memcmp est plus lent
C. memcmp ne marche pas avec des octets
D. memcmp n'existe pas en C
E. memcmp fait des allocations
F. memcmp a un bug avec 0x7F
G. memcmp s'arrête au '\0'
H. memcmp dépend de l'endianness
I. memcmp est deprecated
J. memcmp nécessite malloc

**Réponse correcte :** A

**Explication :** L'exercice interdit explicitement les fonctions de libc, dont `memcmp`. Il faut implémenter la comparaison manuellement.

---

**Question 6 : Quel format utilise 'M' 'Z' comme magic number ?**

A. PE (Windows executables)
B. ELF (Linux executables)
C. Mach-O (macOS executables)
D. PNG (images)
E. JPEG (images)
F. ZIP (archives)
G. PDF (documents)
H. MP3 (audio)
I. AVI (video)
J. TAR (archives)

**Réponse correcte :** A

**Explication :** 'MZ' sont les initiales de Mark Zbikowski, créateur du format MS-DOS/PE.

---

**Question 7 : Quelle valeur retourne la fonction si le fichier est un PNG ?**

A. 0 (invalide)
B. 1 (valide)
C. -1 (erreur)
D. NULL
E. 0x89 (premier octet PNG)
F. 2 (format inconnu)
G. 255
H. Comportement indéfini
I. Segfault
J. EOF

**Réponse correcte :** A

**Explication :** PNG commence par `0x89 'P' 'N' 'G'`, différent de `0x7F 'E' 'L' 'F'`. La fonction retourne 0.

---

**Question 8 : Combien d'octets faut-il vérifier pour valider le magic ELF ?**

A. 4
B. 2
C. 8
D. 16
E. 1
F. 3
G. 32
H. 64
I. Tout le fichier
J. Dépend du fichier

**Réponse correcte :** A

**Explication :** Le magic number ELF est composé de exactement 4 octets : `0x7F`, 'E', 'L', 'F'.

---

**Question 9 : Que signifie "const unsigned char *ident" ?**

A. Pointeur vers données non-modifiables
B. Pointeur non-modifiable
C. Pointeur constant vers données constantes
D. Variable constante
E. Aucune différence avec "unsigned char *"
F. Allocation dynamique
G. Tableau statique
H. Chaîne de caractères
I. Pointeur NULL
J. Pointeur void

**Réponse correcte :** A

**Explication :** `const unsigned char *` signifie que les données pointées ne peuvent pas être modifiées via ce pointeur.

---

**Question 10 : Quel outil Linux utilise la vérification du magic number ?**

A. file
B. ls
C. cat
D. grep
E. sed
F. awk
G. find
H. chmod
I. chown
J. mkdir

**Réponse correcte :** A

**Explication :** La commande `file` identifie le type de fichier en lisant son magic number.

---

## 📊 SECTION 8 : RÉCAPITULATIF

**Ce que tu as appris :**

✅ Comprendre le concept de magic number en informatique
✅ Lire et interpréter des octets bruts
✅ Valider le format ELF par vérification du magic number
✅ Gérer les cas d'erreur (pointeur NULL)
✅ Comparer des octets sans fonctions externes
✅ Optimiser avec un algorithme O(1)

**Compétences acquises :**

- Manipulation de données binaires bas-niveau
- Gestion de la mémoire et des pointeurs
- Validation de formats de fichiers
- Compréhension des standards ELF
- Création d'outils système

**Prochaines étapes :**

1. **Ex01** : Parser les sections et segments ELF
2. **Ex02** : Lire la table des symboles
3. **Ex03** : Gérer les relocations
4. **Projet final** : Créer un mini-linker ELF

---

## 📦 SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "2.6.1-a-elf-check-magic",
    "generated_at": "2026-01-15 00:00:00",

    "metadata": {
      "exercise_id": "2.6.1-a",
      "exercise_name": "elf_check_magic",
      "module": "2.6.1",
      "module_name": "Object File Formats",
      "concept": "a",
      "concept_name": "ELF Magic Number Validation",
      "type": "cours_code",
      "tier": 1,
      "tier_info": "Concept isolé",
      "phase": 2,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "c",
      "duration_minutes": 45,
      "xp_base": 120,
      "xp_bonus_multiplier": 2,
      "bonus_tier": "STANDARD",
      "bonus_icon": "⚡",
      "complexity_time": "T1 O(1)",
      "complexity_space": "S1 O(1)",
      "prerequisites": ["binary_files", "pointers", "structures"],
      "domains": ["FS", "Encodage", "Électro"],
      "domains_bonus": ["Encodage", "Crypto"],
      "tags": ["elf", "binary", "magic_number", "validation", "format"],
      "meme_reference": "Show me your ID - Le Videur de Boîte de Nuit"
    },

    "files": {
      "spec.json": "Section 4.9",
      "references/ref_elf_check_magic.c": "Section 4.3",
      "references/ref_detect_binary_format.c": "Section 4.6",
      "alternatives/alt_oneliner.c": "Section 4.4 - Solution 1",
      "alternatives/alt_constants.c": "Section 4.4 - Solution 2",
      "alternatives/alt_struct_table.c": "Section 4.7",
      "mutants/mutant_a_incomplete.c": "Section 4.10 - Boundary",
      "mutants/mutant_b_no_null.c": "Section 4.10 - Safety",
      "mutants/mutant_c_memcmp.c": "Section 4.10 - Resource",
      "mutants/mutant_d_wrong_value.c": "Section 4.10 - Logic",
      "mutants/mutant_e_inverted.c": "Section 4.10 - Return",
      "tests/main.c": "Section 4.2"
    },

    "validation": {
      "expected_pass": [
        "references/ref_elf_check_magic.c",
        "references/ref_detect_binary_format.c",
        "alternatives/alt_oneliner.c",
        "alternatives/alt_constants.c",
        "alternatives/alt_struct_table.c"
      ],
      "expected_fail": [
        "mutants/mutant_a_incomplete.c",
        "mutants/mutant_b_no_null.c",
        "mutants/mutant_c_memcmp.c",
        "mutants/mutant_d_wrong_value.c",
        "mutants/mutant_e_inverted.c"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference": "python3 hackbrain_engine_v22.py -s spec.json -f references/ref_elf_check_magic.c",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ref_elf_check_magic.c -s spec.json --validate"
    }
  }
}
```

---

**FIN DE L'EXERCICE 2.6.1-a : elf_check_magic**

*HACKBRAIN v5.5.2 — "L'excellence pédagogique ne se négocie pas"*
