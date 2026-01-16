# ex07: Keyboard & Timer (PIT)

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.19: Keyboard Input (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PS/2 keyboard | Legacy interface |
| b | I/O ports | 0x60, 0x64 |
| c | IRQ 1 | Keyboard interrupt |
| d | Scan codes | Key codes |
| e | Make/break | Press/release |
| f | Scan code sets | Set 1, 2 |
| g | Translation | To ASCII |
| h | Modifier keys | Shift, Ctrl |

### 2.8.20: Timer (PIT) (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PIT | Programmable Interval Timer |
| b | IRQ 0 | Timer interrupt |
| c | Frequency | 1193182 Hz base |
| d | Divider | Set tick rate |
| e | Counter modes | Mode 2, mode 3 |
| f | I/O ports | 0x40-0x43 |
| g | Tick counting | System time |
| h | Scheduling | Timer-based |

---

## Sujet

Implementer les drivers clavier PS/2 et timer PIT.

### Structures

```c
// Keyboard state
typedef struct {
    bool shift;
    bool ctrl;
    bool alt;
    bool capslock;
    bool numlock;
    char buffer[256];
    int buf_read;
    int buf_write;
} keyboard_state_t;

// PIT state
typedef struct {
    uint64_t ticks;
    uint32_t frequency;
    uint32_t divisor;
} pit_state_t;
```

### API

```c
// Keyboard
void keyboard_init(void);
void keyboard_handler(void);        // IRQ 1 handler
char keyboard_read(void);           // Blocking read
bool keyboard_available(void);
char scancode_to_ascii(uint8_t scancode, bool shift);

// PIT Timer
void pit_init(uint32_t frequency);
void pit_handler(void);             // IRQ 0 handler
uint64_t pit_get_ticks(void);
void pit_sleep(uint32_t ms);
```

---

## Exemple

```c
#include "keyboard_timer.h"

int main(void) {
    // 2.8.19: Keyboard
    printf("=== PS/2 Keyboard ===\n");
    printf("Ports:\n");
    printf("  0x60 - Data port (read scan code)\n");
    printf("  0x64 - Status/command port\n");
    printf("\nIRQ 1: Keyboard interrupt\n");

    printf("\nScan codes (Set 1):\n");
    printf("  0x1C = Enter\n");
    printf("  0x01 = Escape\n");
    printf("  0x1E = 'A'\n");
    printf("  0x9E = 'A' released (0x1E + 0x80)\n");

    // 2.8.20: PIT Timer
    printf("\n=== PIT Timer ===\n");
    printf("Base frequency: 1193182 Hz\n");
    printf("Ports:\n");
    printf("  0x40 - Channel 0 (system timer)\n");
    printf("  0x41 - Channel 1 (legacy)\n");
    printf("  0x42 - Channel 2 (PC speaker)\n");
    printf("  0x43 - Command register\n");

    printf("\nTo set 100 Hz:\n");
    printf("  Divisor = 1193182 / 100 = 11932\n");
    printf("  Send 0x36 to port 0x43 (mode 3)\n");
    printf("  Send low byte to 0x40\n");
    printf("  Send high byte to 0x40\n");

    // Initialize
    pit_init(100);  // 100 Hz
    keyboard_init();

    // Main loop
    printf("\nPress keys (ESC to exit):\n");
    while (1) {
        if (keyboard_available()) {
            char c = keyboard_read();
            if (c == 27) break;  // ESC
            printf("%c", c);
        }
    }

    printf("\nTotal ticks: %llu\n", pit_get_ticks());

    return 0;
}
```

---

## Fichiers

```
ex07/
├── keyboard_timer.h
├── keyboard.c
├── scancodes.c
├── pit.c
└── Makefile
```
