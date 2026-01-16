# Exercice 2.8.0-a : boot_sequence_analyzer

**Module :**
2.8.0 — Boot Process Overview

**Concept :**
a — PC Boot Sequence

**Difficulté :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
cours_code

**Tiers :**
1 — Concept isolé

**Langage :**
C (C17)

**Prérequis :**
- Manipulation de structures en C
- Lecture de fichiers binaires
- Compréhension du système de fichiers

**Domaines :**
CPU, FS, Encodage

**Durée estimée :**
180 min

**XP Base :**
150

**Complexité :**
T1 O(1) × S1 O(1)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier à rendre :**
- `boot_sequence_analyzer.c`
- `boot_sequence_analyzer.h`

**Fonctions autorisées :**
- `malloc`, `free`
- `printf`, `fprintf`
- `fopen`, `fread`, `fclose`
- `memcpy`, `memset`

**Fonctions interdites :**
- Aucune bibliothèque système spécifique (pas de libsystemd, etc.)

### 1.2 Consigne

**🎮 CONTEXTE : La Matrice du Boot — L'Éveil de la Machine**

Dans *Matrix*, lorsque Neo se réveille dans le monde réel, il découvre que la réalité est construite couche par couche. De même, ton PC démarre en plusieurs étapes bien définies : du BIOS/UEFI jusqu'au système d'exploitation, chaque composant "charge" le suivant comme un relais.

Ta mission est de comprendre et d'analyser ce processus de boot, en détectant si le système utilise le Legacy BIOS ou l'UEFI moderne, et en affichant les différentes étapes du démarrage.

**Ta mission :**

Écrire une fonction `analyze_boot_sequence` qui :
1. Détecte le type de firmware (BIOS ou UEFI)
2. Affiche les étapes du boot dans l'ordre
3. Lit et valide la signature MBR (0xAA55) si applicable
4. Affiche les informations du vecteur de reset

**Entrée :**
- Aucun paramètre (analyse le système actuel)

**Sortie :**
- Affiche sur stdout les informations de boot
- Retourne 0 en cas de succès, -1 en cas d'erreur

**Contraintes :**
- Détecter le firmware en vérifiant `/sys/firmware/efi`
- Lire le MBR du disque principal si accessible
- Gérer les cas où l'accès au disque est refusé (permissions)
- Afficher les étapes dans l'ordre chronologique

**Exemples :**

| Cas | Résultat | Explication |
|-----|----------|-------------|
| Système UEFI | Firmware: UEFI | Le répertoire `/sys/firmware/efi` existe |
| Système BIOS | Firmware: Legacy BIOS | Le répertoire n'existe pas |
| MBR valide | Signature MBR: 0xAA55 ✓ | Les 2 derniers octets du secteur 0 sont 0x55 0xAA |

### 1.3 Prototype

```c
int analyze_boot_sequence(void);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

Le processus de boot d'un PC moderne est une danse complexe entre matériel et logiciel qui se déroule en quelques secondes. Quand vous appuyez sur le bouton power, voici ce qui se passe réellement :

1. **Power-On** : L'alimentation envoie un signal "Power Good" à la carte mère
2. **Reset Vector** : Le CPU démarre à l'adresse 0xFFFFFFF0 (16 octets sous 4GB)
3. **Firmware** : Le BIOS/UEFI prend le contrôle
4. **POST** : Tests matériels (RAM, CPU, périphériques)
5. **Boot Device** : Sélection du disque de démarrage
6. **Bootloader** : GRUB/Windows Boot Manager se charge
7. **Kernel** : Le noyau du système d'exploitation démarre
8. **Init** : Premier processus utilisateur (systemd/SysV)

Le **Reset Vector** est crucial : c'est la première instruction que le CPU exécute. Sur x86, cette adresse pointe vers la ROM du BIOS qui contient un saut vers le code principal du firmware.

### 2.5 DANS LA VRAIE VIE

**Métiers concernés :**
- **Développeur de firmware** : Créer/maintenir le code BIOS/UEFI
- **Ingénieur système embarqué** : Boot sur hardware custom
- **Expert en sécurité** : Analyser les bootkits et rootkits
- **DevOps** : Automatiser le déploiement via PXE boot

**Cas d'usage concrets :**
- **Secure Boot** : Vérifier les signatures numériques du bootloader
- **PXE Network Boot** : Démarrer des machines sans disque local
- **Dual Boot** : Gérer plusieurs OS sur une même machine
- **Recovery** : Restaurer un système qui ne boot plus

---

## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
boot_sequence_analyzer.c  boot_sequence_analyzer.h  main.c

$ gcc -Wall -Wextra -Werror boot_sequence_analyzer.c main.c -o boot_analyzer

$ ./boot_analyzer
=== PC Boot Sequence Analysis ===

Firmware Type: UEFI
Reset Vector: 0xFFFFFFF0

Boot Stages:
  1. Power On       → Hardware initialization
  2. Reset Vector   → CPU starts at 0xFFFFFFF0
  3. POST           → Hardware tests
  4. Boot Device    → Disk selection
  5. Bootloader     → GRUB/systemd-boot
  6. Kernel         → Linux kernel
  7. Init           → systemd (PID 1)
  8. User Space     → Login manager

ESP Partition: /dev/nvme0n1p1 (512 MB, FAT32)
Secure Boot: Enabled

$ sudo ./boot_analyzer
MBR Read: /dev/sda
Signature: 0xAA55 ✓
Partition 1: Active (0x80), Type 0xEF (EFI System)
```

---

## ✅❌ SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette (tableau des tests)

| Test | Entrée | Sortie Attendue | Points |
|------|--------|-----------------|--------|
| Détection UEFI | Système UEFI | "Firmware: UEFI" | 15 |
| Détection BIOS | Système BIOS | "Firmware: Legacy BIOS" | 15 |
| Affichage étapes | - | 8 étapes dans l'ordre | 20 |
| Lecture MBR | /dev/sda | Signature 0xAA55 | 20 |
| Reset vector | - | Adresse 0xFFFFFFF0 | 10 |
| Gestion erreurs | Pas de perms | Message d'erreur propre | 10 |
| Détection ESP | Système UEFI | Info partition ESP | 10 |

### 4.2 main.c de test

```c
#include "boot_sequence_analyzer.h"
#include <stdio.h>

int main(void)
{
    int result;

    printf("=== Boot Sequence Analyzer Test ===\n\n");

    result = analyze_boot_sequence();

    if (result == 0)
        printf("\n✓ Analysis completed successfully\n");
    else
        printf("\n✗ Analysis failed\n");

    return result;
}
```

### 4.3 Solution de référence

```c
#include "boot_sequence_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#define RESET_VECTOR 0xFFFFFFF0UL

typedef struct {
    uint8_t boot_code[446];
    uint8_t partition_table[64];
    uint16_t signature;
} __attribute__((packed)) mbr_t;

static bool is_uefi_system(void)
{
    struct stat st;
    return (stat("/sys/firmware/efi", &st) == 0);
}

static void print_boot_stages(void)
{
    const char *stages[] = {
        "Power On       → Hardware initialization",
        "Reset Vector   → CPU starts at 0xFFFFFFF0",
        "POST           → Hardware tests",
        "Boot Device    → Disk selection",
        "Bootloader     → GRUB/systemd-boot/Windows BM",
        "Kernel         → OS kernel loading",
        "Init           → First process (systemd/init)",
        "User Space     → Desktop/services"
    };

    printf("Boot Stages:\n");
    for (int i = 0; i < 8; i++) {
        printf("  %d. %s\n", i + 1, stages[i]);
    }
}

static int read_mbr_signature(const char *device)
{
    FILE *fp;
    mbr_t mbr;

    fp = fopen(device, "rb");
    if (!fp) {
        fprintf(stderr, "Warning: Cannot read %s (permission denied)\n", device);
        return -1;
    }

    if (fread(&mbr, 1, sizeof(mbr), fp) != sizeof(mbr)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    printf("\nMBR Analysis:\n");
    printf("  Device: %s\n", device);
    printf("  Signature: 0x%04X %s\n", mbr.signature,
           (mbr.signature == 0xAA55) ? "✓" : "✗ INVALID");

    return 0;
}

int analyze_boot_sequence(void)
{
    bool is_uefi;

    printf("=== PC Boot Sequence Analysis ===\n\n");

    /* Detect firmware type */
    is_uefi = is_uefi_system();
    printf("Firmware Type: %s\n", is_uefi ? "UEFI" : "Legacy BIOS");
    printf("Reset Vector: 0x%lX\n\n", RESET_VECTOR);

    /* Print boot stages */
    print_boot_stages();

    /* Try to read MBR if root */
    if (geteuid() == 0) {
        read_mbr_signature("/dev/sda");
    } else {
        printf("\nNote: Run with sudo to analyze MBR\n");
    }

    return 0;
}
```

### 4.4 Solutions alternatives acceptées

```c
/* Alternative 1 : Avec analyse ESP pour UEFI */
int analyze_boot_sequence_with_esp(void)
{
    bool is_uefi = is_uefi_system();

    printf("Firmware: %s\n", is_uefi ? "UEFI" : "Legacy BIOS");

    if (is_uefi) {
        /* Chercher la partition ESP */
        FILE *fp = fopen("/proc/mounts", "r");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "/boot/efi")) {
                printf("ESP Found: %s\n", line);
                break;
            }
        }
        fclose(fp);
    }

    print_boot_stages();
    return 0;
}
```

### 4.5 Solutions refusées

```c
/* REFUSÉ : Hardcoder le type de firmware */
int bad_analyze_boot_sequence(void)
{
    printf("Firmware: UEFI\n"); /* Toujours UEFI ? Non ! */
    return 0;
}
// Pourquoi c'est faux : Ne détecte pas réellement le firmware

/* REFUSÉ : Pas de vérification d'erreur */
int bad_read_mbr(void)
{
    FILE *fp = fopen("/dev/sda", "rb"); /* Peut être NULL ! */
    mbr_t mbr;
    fread(&mbr, 1, sizeof(mbr), fp); /* Crash si fp == NULL */
    fclose(fp);
    return 0;
}
// Pourquoi c'est faux : Crash si permissions insuffisantes
```

### 4.6 Solution bonus de référence

*(Bonus non applicable pour cet exercice Tiers 1)*

### 4.9 spec.json

```json
{
  "name": "boot_sequence_analyzer",
  "language": "c",
  "type": "cours_code",
  "tier": 1,
  "tier_info": "Concept isolé",
  "tags": ["boot", "bios", "uefi", "firmware", "hardware"],
  "passing_score": 70,

  "function": {
    "name": "analyze_boot_sequence",
    "prototype": "int analyze_boot_sequence(void)",
    "return_type": "int",
    "parameters": []
  },

  "driver": {
    "reference": "int ref_analyze_boot_sequence(void) { struct stat st; int is_uefi = (stat(\"/sys/firmware/efi\", &st) == 0); printf(\"Firmware: %s\\n\", is_uefi ? \"UEFI\" : \"Legacy BIOS\"); printf(\"Reset Vector: 0x%lX\\n\", 0xFFFFFFF0UL); return 0; }",

    "edge_cases": [
      {
        "name": "uefi_system",
        "args": [],
        "expected": 0,
        "is_trap": false,
        "trap_explanation": "Système UEFI standard"
      },
      {
        "name": "bios_system",
        "args": [],
        "expected": 0,
        "is_trap": false,
        "trap_explanation": "Système BIOS legacy"
      },
      {
        "name": "no_root_access",
        "args": [],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Sans sudo, doit afficher un message mais ne pas crasher"
      }
    ],

    "fuzzing": {
      "enabled": false,
      "iterations": 0
    }
  },

  "norm": {
    "allowed_functions": ["malloc", "free", "printf", "fprintf", "fopen", "fread", "fclose", "stat", "geteuid"],
    "forbidden_functions": [],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

```c
/* Mutant A (Boundary) : Lecture MBR sans vérifier la taille */
int mutant_a_boundary(void)
{
    FILE *fp = fopen("/dev/sda", "rb");
    if (!fp) return -1;

    uint8_t buffer[512];
    fread(buffer, 1, 600, fp); /* Lit plus que 512 ! */
    fclose(fp);
    return 0;
}
// Pourquoi c'est faux : Buffer overflow potentiel
// Ce qui était pensé : "Plus c'est gros, mieux c'est"

/* Mutant B (Safety) : Pas de vérification NULL */
int mutant_b_safety(void)
{
    FILE *fp = fopen("/dev/sda", "rb");
    uint8_t buffer[512];
    fread(buffer, 1, 512, fp); /* fp peut être NULL ! */
    fclose(fp);
    return 0;
}
// Pourquoi c'est faux : Crash si fopen échoue
// Ce qui était pensé : "fopen marche toujours"

/* Mutant C (Resource) : Oubli de fermer le fichier */
int mutant_c_resource(void)
{
    FILE *fp = fopen("/dev/sda", "rb");
    if (!fp) return -1;

    uint8_t buffer[512];
    fread(buffer, 1, 512, fp);
    /* Pas de fclose ! */
    return 0;
}
// Pourquoi c'est faux : Fuite de descripteur de fichier
// Ce qui était pensé : "Le système le fermera"

/* Mutant D (Logic) : Détection UEFI inversée */
int mutant_d_logic(void)
{
    struct stat st;
    int exists = (stat("/sys/firmware/efi", &st) == 0);
    printf("Firmware: %s\n", exists ? "Legacy BIOS" : "UEFI"); /* Inversé ! */
    return 0;
}
// Pourquoi c'est faux : Logique inversée
// Ce qui était pensé : Confusion dans la condition

/* Mutant E (Return) : Retourne toujours succès */
int mutant_e_return(void)
{
    FILE *fp = fopen("/dev/sda", "rb");
    if (!fp) {
        fprintf(stderr, "Error\n");
        return 0; /* Devrait retourner -1 ! */
    }
    fclose(fp);
    return 0;
}
// Pourquoi c'est faux : Masque les erreurs
// Ce qui était pensé : "Au moins ça compile"
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Cet exercice vous apprend à :
- Comprendre le processus de boot d'un PC moderne
- Différencier BIOS et UEFI
- Lire des structures binaires (MBR)
- Détecter la configuration système
- Gérer les permissions et erreurs d'accès

### 5.2 LDA — Traduction en français

```
FONCTION analyze_boot_sequence QUI RETOURNE UN ENTIER ET NE PREND AUCUN PARAMÈTRE
DÉBUT FONCTION
    DÉCLARER is_uefi COMME BOOLÉEN
    DÉCLARER st COMME STRUCTURE stat

    AFFICHER "=== PC Boot Sequence Analysis ==="

    SI stat DU CHEMIN "/sys/firmware/efi" DANS st EST ÉGAL À 0 ALORS
        AFFECTER VRAI À is_uefi
    SINON
        AFFECTER FAUX À is_uefi
    FIN SI

    SI is_uefi EST VRAI ALORS
        AFFICHER "Firmware Type: UEFI"
    SINON
        AFFICHER "Firmware Type: Legacy BIOS"
    FIN SI

    AFFICHER "Reset Vector: 0xFFFFFFF0"

    APPELER print_boot_stages

    SI geteuid EST ÉGAL À 0 ALORS
        APPELER read_mbr_signature AVEC "/dev/sda"
    SINON
        AFFICHER "Note: Run with sudo to analyze MBR"
    FIN SI

    RETOURNER 0
FIN FONCTION
```

### 5.3 Visualisation ASCII

```
                    PROCESSUS DE BOOT PC
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  1. POWER ON                                             │
│     │ PSU envoie "Power Good"                           │
│     ▼                                                    │
│  2. RESET VECTOR (0xFFFFFFF0)                           │
│     │ CPU saute à cette adresse                         │
│     ▼                                                    │
│  3. FIRMWARE (BIOS/UEFI)                                │
│     │ Code en ROM                                        │
│     ▼                                                    │
│  4. POST (Power-On Self Test)                           │
│     │ Test RAM, CPU, périphériques                      │
│     ▼                                                    │
│  5. BOOT DEVICE SELECTION                               │
│     │ Trouve le disque bootable                         │
│     ▼                                                    │
│  6. BOOTLOADER                                          │
│     │ GRUB / Windows Boot Manager                       │
│     ▼                                                    │
│  7. KERNEL                                              │
│     │ Linux / Windows NT                                │
│     ▼                                                    │
│  8. INIT (PID 1)                                        │
│     │ systemd / SysV init                               │
│     ▼                                                    │
│  9. USER SPACE                                          │
│     └─ Login / Desktop Environment                      │
│                                                          │
└──────────────────────────────────────────────────────────┘

        BIOS vs UEFI
┌────────────────┬───────────────────┐
│     BIOS       │       UEFI        │
├────────────────┼───────────────────┤
│ 16-bit         │ 32/64-bit         │
│ MBR (512B)     │ GPT + ESP         │
│ Max 2TB        │ Max 9.4ZB         │
│ Texte only     │ GUI possible      │
│ Pas Secure Boot│ Secure Boot       │
└────────────────┴───────────────────┘
```

### 5.4 Les pièges en détail

**Piège 1 : Ne pas vérifier si fopen a réussi**
```c
FILE *fp = fopen("/dev/sda", "rb");
fread(buffer, 1, 512, fp); /* BOOM si fp == NULL ! */
```
Solution : Toujours vérifier `if (!fp) return -1;`

**Piège 2 : Oublier de fermer le fichier**
```c
FILE *fp = fopen("/dev/sda", "rb");
if (!fp) return -1;
fread(...);
return 0; /* Fuite ! */
```
Solution : `fclose(fp);` avant chaque return

**Piège 3 : Supposer qu'on a toujours les permissions root**
```c
FILE *fp = fopen("/dev/sda", "rb"); /* Échoue si pas root */
```
Solution : Vérifier `geteuid() == 0` ou gérer l'échec gracieusement

**Piège 4 : Lire plus de 512 octets du MBR**
```c
uint8_t buffer[512];
fread(buffer, 1, 600, fp); /* Buffer overflow ! */
```
Solution : Ne jamais dépasser la taille du buffer

### 5.5 Cours Complet

#### Le Processus de Boot d'un PC

Quand vous appuyez sur le bouton power de votre ordinateur, une séquence précise d'événements se produit. Comprendre cette séquence est essentiel pour diagnostiquer les problèmes de démarrage, créer des systèmes embarqués, ou travailler sur la sécurité système.

##### Étape 1 : Power-On

L'alimentation (PSU) reçoit le signal du bouton power et génère les tensions nécessaires (3.3V, 5V, 12V). Une fois stable, elle envoie le signal **Power Good** à la carte mère. Ce signal indique que l'alimentation est prête.

##### Étape 2 : Reset Vector

Le CPU reçoit le signal RESET. Il initialise ses registres et saute à une adresse prédéfinie : le **Reset Vector**. Sur architecture x86, cette adresse est **0xFFFFFFF0** (16 octets sous la limite 4GB).

À cette adresse se trouve un **JMP** (saut) vers le code du firmware (BIOS/UEFI) stocké en ROM/Flash. C'est la première instruction exécutée par le CPU.

```
Adresse          Contenu
0xFFFFFFF0    →  JMP FAR  F000:E05B   (vers BIOS)
```

##### Étape 3 : Firmware (BIOS ou UEFI)

Le firmware prend le contrôle. Il existe deux types principaux :

**BIOS (Basic Input/Output System)**
- Ancien standard (années 1980)
- Mode 16-bit (real mode)
- Stocké en ROM/Flash
- Interface texte uniquement
- Limite : disques de 2TB max

**UEFI (Unified Extensible Firmware Interface)**
- Standard moderne (années 2000)
- Mode 32-bit ou 64-bit
- Interface graphique possible
- Support réseau intégré
- Support de disques > 2TB (via GPT)
- Secure Boot (vérification signatures)

Pour détecter le type de firmware sous Linux :
```c
struct stat st;
if (stat("/sys/firmware/efi", &st) == 0) {
    /* Système UEFI */
} else {
    /* Système BIOS legacy */
}
```

##### Étape 4 : POST (Power-On Self Test)

Le firmware exécute une série de tests matériels :
1. Test du CPU (registres, flags)
2. Test de la RAM (base + étendue)
3. Détection des périphériques (clavier, vidéo, disques)
4. Initialisation des contrôleurs (DMA, PIT, PIC)

Si un test échoue, le POST émet des **bips** sonores (beep codes) pour indiquer le problème.

##### Étape 5 : Sélection du Boot Device

Le firmware cherche un périphérique bootable selon un ordre défini (boot order) :
- CD/DVD
- USB
- Disque dur
- Réseau (PXE)

**Sur BIOS** : Le firmware lit le premier secteur (512 octets) de chaque disque. Si les 2 derniers octets valent **0x55 0xAA** (little-endian : 0xAA55), c'est un MBR valide.

**Sur UEFI** : Le firmware lit la partition ESP (EFI System Partition) en FAT32 et charge un fichier .efi (ex: `/EFI/BOOT/BOOTX64.EFI`).

##### Étape 6 : Bootloader

Le bootloader (GRUB, systemd-boot, Windows Boot Manager) :
- Affiche un menu de sélection d'OS
- Charge le noyau en mémoire
- Passe les paramètres au noyau
- Saute à l'adresse d'entrée du kernel

##### Étape 7 : Kernel

Le noyau du système d'exploitation prend le contrôle :
- Configure la mémoire virtuelle (paging)
- Initialise les drivers
- Monte le système de fichiers racine
- Lance le processus init

##### Étape 8 : Init (Premier Processus Utilisateur)

Le processus **init** (PID 1) démarre :
- **systemd** (Linux moderne)
- **SysV init** (Linux ancien)
- **Windows Session Manager**

Il lance tous les services système et finalement le gestionnaire de login.

#### Le Master Boot Record (MBR)

Le MBR est une structure de 512 octets située au tout début d'un disque (LBA 0) :

```
Offset    Taille    Description
0x000     446       Code de boot
0x1BE     16        Partition 1
0x1CE     16        Partition 2
0x1DE     16        Partition 3
0x1EE     16        Partition 4
0x1FE     2         Signature (0x55 0xAA)
```

La signature **0xAA55** (little-endian) est vérifiée par le BIOS pour confirmer que c'est un disque bootable.

#### Sécurité : Secure Boot

Sur UEFI, **Secure Boot** vérifie que le bootloader est signé numériquement avec une clé approuvée. Cela empêche le chargement de bootloaders malveillants (bootkits).

Bases de données de clés :
- **PK** (Platform Key) : Clé du propriétaire
- **KEK** (Key Exchange Key) : Clés intermédiaires
- **db** : Signatures autorisées
- **dbx** : Signatures révoquées

### 5.6 Normes

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (compile, mais interdit)                          │
├─────────────────────────────────────────────────────────────────┤
│ FILE *fp=fopen("/dev/sda","rb");                                │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ FILE *fp = fopen("/dev/sda", "rb");                             │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Espaces autour du = pour la lisibilité                        │
│ • Espace après les virgules dans les paramètres                 │
│ • Code plus aéré = plus facile à lire                           │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'exécution

```
Appel : analyze_boot_sequence()

┌──────┬────────────────────────────────────────┬──────────┬──────────────────┐
│ Étape│ Instruction                            │ is_uefi  │ Explication      │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  1   │ APPELER stat("/sys/firmware/efi", &st)│ ?        │ Test existence   │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  2   │ stat RETOURNE 0                        │ ?        │ Le répertoire    │
│      │                                        │          │ existe           │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  3   │ AFFECTER VRAI À is_uefi                │ true     │ C'est UEFI       │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  4   │ AFFICHER "Firmware Type: UEFI"         │ true     │ Confirmation     │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  5   │ AFFICHER "Reset Vector: 0xFFFFFFF0"    │ true     │ Info CPU         │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  6   │ APPELER print_boot_stages()            │ true     │ Liste les étapes │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  7   │ SI geteuid() == 0                      │ true     │ On est root ?    │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  8   │ FAUX (uid=1000)                        │ true     │ Pas root         │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  9   │ AFFICHER "Note: Run with sudo..."      │ true     │ Message aide     │
├──────┼────────────────────────────────────────┼──────────┼──────────────────┤
│  10  │ RETOURNER 0                            │ true     │ Succès           │
└──────┴────────────────────────────────────────┴──────────┴──────────────────┘
```

### 5.8 Mnémotechniques

#### 🎬 MEME : "The Matrix - Red Pill" — Comprendre le Boot

Dans Matrix, Morpheus offre à Neo le choix entre la pilule bleue (rester dans l'ignorance) et la pilule rouge (voir la vérité). Comprendre le boot, c'est prendre la pilule rouge : vous voyez comment la machine "se réveille" vraiment.

Chaque couche du boot charge la suivante, comme les couches de la Matrice :
- Reset Vector → BIOS/UEFI (couche 1)
- BIOS/UEFI → Bootloader (couche 2)
- Bootloader → Kernel (couche 3)
- Kernel → Init → User Space (réalité finale)

```c
/* Ne restez pas dans l'ignorance du boot ! */
if (is_uefi_system()) {
    printf("You took the red pill - UEFI revealed\n");
} else {
    printf("Legacy BIOS - the old Matrix\n");
}
```

#### 🔥 MEME : "This is fine" — Ignorer le code d'erreur

Comme le chien dans le meme "This is fine" qui ignore que tout brûle autour de lui, ne pas vérifier si `fopen()` a réussi mène au désastre.

```c
FILE *fp = fopen("/dev/sda", "rb");
/* Si fp == NULL et qu'on continue... 🔥 This is fine 🔥 */
fread(buffer, 1, 512, fp); /* BOOM */
```

**Solution** : Toujours vérifier !
```c
FILE *fp = fopen("/dev/sda", "rb");
if (!fp) {
    fprintf(stderr, "Error: Cannot open device\n");
    return -1; /* It's NOT fine! */
}
```

#### 🧠 MEME : "Expanding Brain" — Niveaux de compréhension du boot

```
🧠 Small brain  : "J'appuie sur le bouton, ça boot"
🧠 Normal brain : "Le BIOS charge GRUB qui charge Linux"
🧠 Big brain    : "Reset Vector → POST → MBR → Bootloader → Kernel"
🧠 Galaxy brain : "0xFFFFFFF0 JMP F000:E05B → INT 0x19 → LBA 0 signature 0xAA55..."
```

### 5.9 Applications pratiques

1. **Dual Boot** : Installer Linux à côté de Windows
   - Comprendre ESP et GRUB
   - Configurer l'ordre de boot

2. **Recovery** : Réparer un système qui ne boot plus
   - Booter sur USB live
   - Réparer GRUB ou Windows Boot Manager

3. **PXE Boot** : Déployer des machines en réseau
   - Configurer un serveur TFTP
   - Créer des images netboot

4. **Sécurité** : Analyser des bootkits
   - Vérifier l'intégrité du MBR
   - Activer Secure Boot

---

## ⚠️ SECTION 6 : PIÈGES — RÉCAPITULATIF

1. **Ne jamais utiliser fopen sans vérifier le retour**
2. **Toujours fermer les fichiers ouverts (fclose)**
3. **Gérer le cas où on n'a pas les permissions root**
4. **Ne pas dépasser la taille des buffers (512 octets pour MBR)**
5. **Vérifier que stat() a réussi avant d'utiliser la structure stat**

---

## 📝 SECTION 7 : QCM

**Question 1** : Quelle est l'adresse du Reset Vector sur x86 ?
A) 0x00000000
B) 0x000FFFF0
C) 0xFFFFFFF0 ✓
D) 0xFFFFFFFF

**Question 2** : Quelle est la signature MBR valide ?
A) 0xAA55 ✓
B) 0x55AA
C) 0xFF00
D) 0x0000

**Question 3** : Comment détecter un système UEFI sous Linux ?
A) Lire /proc/cpuinfo
B) Vérifier /sys/firmware/efi ✓
C) Lire /dev/mem
D) Appeler ioctl()

**Question 4** : Quelle est la taille du MBR ?
A) 256 octets
B) 512 octets ✓
C) 1024 octets
D) 4096 octets

**Question 5** : Que fait le POST ?
A) Charge le kernel
B) Teste le matériel ✓
C) Formate le disque
D) Crée les partitions

**Question 6** : Sur UEFI, où se trouve le bootloader ?
A) Dans le MBR
B) Dans la partition ESP ✓
C) Dans /boot
D) Dans la ROM

**Question 7** : Quel processus a le PID 1 ?
A) bash
B) kernel
C) init/systemd ✓
D) login

**Question 8** : Que signifie 0x80 dans le statut d'une partition MBR ?
A) Partition vide
B) Partition active/bootable ✓
C) Partition étendue
D) Partition swap

**Question 9** : Quelle fonction vérifie les permissions root en C ?
A) isroot()
B) geteuid() ✓
C) getpid()
D) sudo()

**Question 10** : Que contient le Reset Vector ?
A) Le kernel
B) Un saut vers le BIOS ✓
C) La table des partitions
D) Le bootloader

---

## 📊 SECTION 8 : RÉCAPITULATIF

**Concepts maîtrisés** :
- Processus de boot PC (8 étapes)
- Différence BIOS vs UEFI
- Reset Vector et son adresse
- Structure du MBR
- Détection du firmware
- Lecture de structures binaires
- Gestion des permissions système

**Points clés** :
- Le boot est une séquence précise et ordonnée
- Le Reset Vector (0xFFFFFFF0) est la première adresse exécutée
- UEFI est le successeur moderne du BIOS
- Le MBR fait 512 octets avec signature 0xAA55
- Toujours vérifier les erreurs d'I/O
- Gérer gracieusement les permissions insuffisantes

**Compétences acquises** :
- Analyser le type de firmware
- Lire des structures système
- Manipuler des fichiers binaires
- Gérer les erreurs proprement

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "2.8.0-a-boot-sequence-analyzer",
    "generated_at": "2025-01-15 12:00:00",

    "metadata": {
      "exercise_id": "2.8.0-a",
      "exercise_name": "boot_sequence_analyzer",
      "module": "2.8.0",
      "module_name": "Boot Process Overview",
      "concept": "a",
      "concept_name": "PC Boot Sequence",
      "type": "cours_code",
      "tier": 1,
      "tier_info": "Concept isolé",
      "phase": 2,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": "c",
      "duration_minutes": 180,
      "xp_base": 150,
      "xp_bonus_multiplier": 0,
      "complexity_time": "T1 O(1)",
      "complexity_space": "S1 O(1)",
      "prerequisites": ["structures_c", "file_io"],
      "domains": ["CPU", "FS", "Encodage"],
      "tags": ["boot", "bios", "uefi", "firmware", "mbr", "reset-vector"],
      "meme_reference": "The Matrix - Red Pill"
    },

    "files": {
      "spec.json": "Section 4.9",
      "references/boot_sequence_analyzer.c": "Section 4.3",
      "alternatives/boot_analyzer_with_esp.c": "Section 4.4",
      "mutants/mutant_a_boundary.c": "Section 4.10",
      "mutants/mutant_b_safety.c": "Section 4.10",
      "mutants/mutant_c_resource.c": "Section 4.10",
      "mutants/mutant_d_logic.c": "Section 4.10",
      "mutants/mutant_e_return.c": "Section 4.10",
      "tests/main.c": "Section 4.2"
    },

    "validation": {
      "expected_pass": [
        "references/boot_sequence_analyzer.c",
        "alternatives/boot_analyzer_with_esp.c"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.c",
        "mutants/mutant_b_safety.c",
        "mutants/mutant_c_resource.c",
        "mutants/mutant_d_logic.c",
        "mutants/mutant_e_return.c"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference": "python3 hackbrain_engine_v22.py -s spec.json -f references/boot_sequence_analyzer.c"
    }
  }
}
```
