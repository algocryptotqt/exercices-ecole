# ex06: Kernel Entry & VGA Text Mode

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.17: Kernel Entry Point (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Entry | First kernel code |
| b | Stack setup | Initialize stack |
| c | BSS clear | Zero BSS section |
| d | Constructors | Global constructors |
| e | Call main | kernel_main() |
| f | Architecture init | CPU, GDT, IDT |
| g | Memory init | Page allocator |
| h | Never return | Halt or loop |

### 2.8.18: VGA Text Mode (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Text buffer | 0xB8000 |
| b | Character format | Char + attribute |
| c | Attributes | Color, blink |
| d | Dimensions | 80×25 |
| e | Cursor | Hardware cursor |
| f | Scrolling | Move memory |
| g | Printf | Implement |

---

## Sujet

Implementer le point d'entree du noyau et le driver VGA text.

### Structures

```c
// VGA character entry
typedef struct {
    uint8_t character;
    uint8_t attribute;
} __attribute__((packed)) vga_char_t;

// VGA color
typedef enum {
    VGA_BLACK = 0,
    VGA_BLUE = 1,
    VGA_GREEN = 2,
    VGA_CYAN = 3,
    VGA_RED = 4,
    VGA_MAGENTA = 5,
    VGA_BROWN = 6,
    VGA_LIGHT_GRAY = 7,
    VGA_DARK_GRAY = 8,
    VGA_LIGHT_BLUE = 9,
    VGA_LIGHT_GREEN = 10,
    VGA_LIGHT_CYAN = 11,
    VGA_LIGHT_RED = 12,
    VGA_LIGHT_MAGENTA = 13,
    VGA_YELLOW = 14,
    VGA_WHITE = 15
} vga_color_t;

// VGA state
typedef struct {
    vga_char_t *buffer;   // 0xB8000
    int width;            // 80
    int height;           // 25
    int cursor_x;
    int cursor_y;
    uint8_t color;
} vga_state_t;
```

### API

```c
// Kernel entry
void kernel_entry(void);      // Assembly entry point
void kernel_main(void);       // C entry point
void clear_bss(void);
void call_constructors(void);
void halt(void);

// VGA text mode
void vga_init(void);
void vga_clear(void);
void vga_putchar(char c);
void vga_puts(const char *s);
void vga_set_color(vga_color_t fg, vga_color_t bg);
void vga_set_cursor(int x, int y);
void vga_scroll(void);
int vga_printf(const char *fmt, ...);

// Hardware cursor
void vga_enable_cursor(int start, int end);
void vga_disable_cursor(void);
void vga_update_cursor(int x, int y);
```

---

## Exemple

```c
#include "kernel_entry_vga.h"

// Assembly entry point (boot.asm)
/*
[BITS 32]
section .multiboot
    dd 0x1BADB002      ; magic
    dd 0x00            ; flags
    dd -(0x1BADB002)   ; checksum

section .bss
    resb 16384         ; 16KB stack
stack_top:

section .text
global _start
extern kernel_main

_start:
    mov esp, stack_top
    call kernel_main
    cli
.hang:
    hlt
    jmp .hang
*/

void kernel_main(void) {
    // 2.8.17: Kernel initialization

    // Clear BSS
    clear_bss();

    // Initialize VGA
    vga_init();
    vga_clear();

    // Print welcome
    vga_set_color(VGA_LIGHT_GREEN, VGA_BLACK);
    vga_puts("ODYSSEY Mini Kernel\n");
    vga_set_color(VGA_WHITE, VGA_BLACK);
    vga_puts("Kernel initialized successfully!\n\n");

    // Test printf
    vga_printf("VGA: %dx%d text mode\n", 80, 25);
    vga_printf("Buffer at: 0x%X\n", 0xB8000);

    // Test colors
    for (int i = 0; i < 16; i++) {
        vga_set_color(i, VGA_BLACK);
        vga_printf("Color %d ", i);
    }

    // 2.8.17.h: Never return
    vga_puts("\n\nSystem halted.");
    halt();
}

// 2.8.18: VGA implementation
static vga_state_t vga;

void vga_init(void) {
    vga.buffer = (vga_char_t*)0xB8000;
    vga.width = 80;
    vga.height = 25;
    vga.cursor_x = 0;
    vga.cursor_y = 0;
    vga.color = 0x07;  // Light gray on black
    vga_enable_cursor(14, 15);
}

void vga_putchar(char c) {
    if (c == '\n') {
        vga.cursor_x = 0;
        vga.cursor_y++;
    } else if (c >= ' ') {
        int offset = vga.cursor_y * vga.width + vga.cursor_x;
        vga.buffer[offset].character = c;
        vga.buffer[offset].attribute = vga.color;
        vga.cursor_x++;
    }

    if (vga.cursor_x >= vga.width) {
        vga.cursor_x = 0;
        vga.cursor_y++;
    }

    if (vga.cursor_y >= vga.height) {
        vga_scroll();
    }

    vga_update_cursor(vga.cursor_x, vga.cursor_y);
}
```

---

## Fichiers

```
ex06/
├── kernel_entry_vga.h
├── boot.asm
├── kernel.c
├── vga.c
├── printf.c
└── Makefile
```
