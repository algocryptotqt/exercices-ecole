# ex02: Bootloaders & GRUB

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.6: Bootloader Basics (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Bootloader purpose | Load kernel |
| b | Stage 1 | In MBR, loads stage 2 |
| c | Stage 2 | Full bootloader |
| d | GRUB | Grand Unified Bootloader |
| e | GRUB 2 | Modern version |
| f | grub.cfg | Configuration |
| g | Chainloading | Load another bootloader |
| h | Menu | Boot selection |

### 2.8.7: GRUB (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | GRUB stages | boot.img, core.img |
| b | Modules | Filesystem, etc. |
| c | grub-install | Install GRUB |
| d | grub-mkconfig | Generate config |
| e | /etc/default/grub | Config source |
| f | /boot/grub | GRUB files |
| g | GRUB commands | ls, linux, initrd, boot |
| h | Recovery | GRUB rescue |

---

## Sujet

Comprendre les bootloaders et maitriser GRUB.

### Structures

```c
// GRUB menu entry
typedef struct {
    const char *title;
    const char *kernel_path;
    const char *kernel_options;
    const char *initrd_path;
    bool is_default;
    int index;
} grub_menu_entry_t;

// GRUB configuration
typedef struct {
    int timeout;
    const char *default_entry;
    bool hidden_timeout;
    const char *background;
    const char *theme;
    bool quiet;
} grub_config_t;
```

### API

```c
// Bootloader basics
void explain_bootloader_stages(void);
void explain_chainloading(void);

// GRUB operations
int parse_grub_cfg(const char *path, grub_menu_entry_t **entries, int *count);
int get_grub_config(grub_config_t *config);
void print_grub_menu(void);

// GRUB commands
void show_grub_commands(void);
void explain_grub_rescue(void);
```

---

## Exemple

```c
#include "bootloaders.h"

int main(void) {
    // 2.8.6: Bootloader basics
    printf("=== Bootloader Basics ===\n");
    explain_bootloader_stages();
    /*
    Stage 1 (MBR): 446 bytes
      - Loaded by BIOS from MBR
      - Loads stage 1.5 or stage 2

    Stage 1.5 (core.img):
      - Filesystem drivers
      - Located after MBR

    Stage 2: Full bootloader
      - Menu, kernel loading
      - Located in /boot/grub
    */

    // 2.8.7: GRUB
    printf("\n=== GRUB ===\n");
    printf("GRUB files:\n");
    printf("  /boot/grub/grub.cfg - Main config\n");
    printf("  /etc/default/grub - User settings\n");
    printf("  /etc/grub.d/ - Config scripts\n");

    print_grub_menu();
    show_grub_commands();
    /*
    GRUB Commands:
      ls (hd0,1)/        - List directory
      set root=(hd0,1)   - Set root partition
      linux /vmlinuz     - Load kernel
      initrd /initrd.img - Load initramfs
      boot               - Boot kernel
    */

    return 0;
}
```

---

## Fichiers

```
ex02/
├── bootloaders.h
├── bootloader.c
├── grub.c
├── grub_config.c
└── Makefile
```
