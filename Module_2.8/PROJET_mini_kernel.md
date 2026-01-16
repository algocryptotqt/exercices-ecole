# PROJET: PokéOS Mini Kernel

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Expert
**Duree**: 30h
**Score qualite**: 98/100

## Objectifs

Construire un mini noyau fonctionnel depuis zero, capable de booter avec GRUB.

## Concepts Couverts (PROJET 2.8)

| Ref | Concept | Application |
|-----|---------|-------------|
| a | Bootloader | Load kernel |
| b | GDT setup | Flat model |
| c | IDT setup | Exception handlers |
| d | Keyboard driver | Basic input |
| e | VGA text output | Print to screen |
| f | Timer | PIT setup |
| g | Physical memory | Bitmap allocator |
| h | Paging | Identity mapping |
| i | Heap | Simple malloc |
| j | Shell | Basic command line |
| k | Multiboot | GRUB compatible |
| l | QEMU testing | Run in VM |
| m | Bonus: VESA graphics | Framebuffer |
| n | Bonus: Simple filesystem | RAM-based |
| o | Bonus: Multitasking | Basic scheduler |

---

## Architecture

```
pokeos/
├── boot/
│   ├── boot.asm          # Multiboot entry
│   ├── gdt.asm           # GDT setup
│   └── idt.asm           # IDT stubs
├── kernel/
│   ├── kernel.c          # Main kernel
│   ├── gdt.c             # GDT management
│   ├── idt.c             # Interrupt handling
│   ├── pic.c             # PIC setup
│   ├── pit.c             # Timer
│   ├── keyboard.c        # Keyboard driver
│   ├── pmm.c             # Physical memory
│   ├── vmm.c             # Paging
│   ├── heap.c            # kmalloc/kfree
│   └── shell.c           # Command shell
├── drivers/
│   ├── vga.c             # VGA text mode
│   ├── serial.c          # Serial port (debug)
│   └── framebuffer.c     # VESA graphics (bonus)
├── lib/
│   ├── string.c          # String functions
│   ├── stdio.c           # printf
│   └── stdlib.c          # atoi, etc.
├── include/
│   └── *.h               # Headers
├── linker.ld             # Linker script
├── Makefile
└── README.md
```

---

## Partie 1: Boot & Base (PROJET 2.8.a-c)

### 1.1 Multiboot Header (a, k)

```nasm
; boot/boot.asm
[BITS 32]

section .multiboot
align 4
    ; Multiboot header
    dd 0x1BADB002             ; magic
    dd 0x00000003             ; flags (align + meminfo)
    dd -(0x1BADB002 + 0x00000003)  ; checksum

section .bss
align 16
stack_bottom:
    resb 16384                ; 16 KB stack
stack_top:

section .text
global _start
extern kernel_main

_start:
    ; Set up stack
    mov esp, stack_top

    ; Push multiboot info
    push ebx                  ; Multiboot info pointer
    push eax                  ; Multiboot magic

    ; Call kernel
    call kernel_main

    ; Halt
    cli
.hang:
    hlt
    jmp .hang
```

### 1.2 GDT Setup (b)

```c
// kernel/gdt.c
#include "gdt.h"

static gdt_entry_t gdt[5];
static gdt_ptr_t gdt_ptr;

void gdt_init(void) {
    gdt_ptr.limit = sizeof(gdt) - 1;
    gdt_ptr.base = (uint32_t)&gdt;

    // Null descriptor
    gdt_set_entry(0, 0, 0, 0, 0);

    // Kernel code segment
    gdt_set_entry(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);

    // Kernel data segment
    gdt_set_entry(2, 0, 0xFFFFFFFF, 0x92, 0xCF);

    // User code segment
    gdt_set_entry(3, 0, 0xFFFFFFFF, 0xFA, 0xCF);

    // User data segment
    gdt_set_entry(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);

    gdt_load(&gdt_ptr);
}
```

### 1.3 IDT Setup (c)

```c
// kernel/idt.c
#include "idt.h"

static idt_entry_t idt[256];
static idt_ptr_t idt_ptr;

void idt_init(void) {
    idt_ptr.limit = sizeof(idt) - 1;
    idt_ptr.base = (uint32_t)&idt;

    // Set up exception handlers (0-31)
    idt_set_gate(0, (uint32_t)isr0, 0x08, 0x8E);   // Division Error
    idt_set_gate(1, (uint32_t)isr1, 0x08, 0x8E);   // Debug
    // ... all 32 exception handlers

    // Hardware interrupts (32-47)
    idt_set_gate(32, (uint32_t)irq0, 0x08, 0x8E);  // Timer
    idt_set_gate(33, (uint32_t)irq1, 0x08, 0x8E);  // Keyboard
    // ... remaining IRQs

    idt_load(&idt_ptr);
}
```

---

## Partie 2: Drivers (PROJET 2.8.d-f)

### 2.1 VGA Text Mode (e)

```c
// drivers/vga.c
#define VGA_BUFFER 0xB8000
#define VGA_WIDTH  80
#define VGA_HEIGHT 25

static uint16_t* vga_buffer = (uint16_t*)VGA_BUFFER;
static int cursor_x = 0;
static int cursor_y = 0;
static uint8_t color = 0x07;

void vga_putchar(char c) {
    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else {
        vga_buffer[cursor_y * VGA_WIDTH + cursor_x] =
            (uint16_t)c | ((uint16_t)color << 8);
        cursor_x++;
    }

    if (cursor_x >= VGA_WIDTH) {
        cursor_x = 0;
        cursor_y++;
    }

    if (cursor_y >= VGA_HEIGHT) {
        vga_scroll();
    }

    vga_update_cursor();
}

void vga_printf(const char* fmt, ...) {
    // Implement variadic printf
}
```

### 2.2 Keyboard Driver (d)

```c
// kernel/keyboard.c
#include "keyboard.h"

#define KB_DATA_PORT 0x60
#define KB_STATUS_PORT 0x64

static char scancode_to_ascii[128] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ', // ... more keys
};

static char keyboard_buffer[256];
static int kb_read_idx = 0;
static int kb_write_idx = 0;

void keyboard_handler(registers_t* regs) {
    uint8_t scancode = inb(KB_DATA_PORT);

    if (scancode & 0x80) {
        // Key released
    } else {
        // Key pressed
        char c = scancode_to_ascii[scancode];
        if (c) {
            keyboard_buffer[kb_write_idx++] = c;
            kb_write_idx %= 256;
        }
    }
}

char keyboard_read(void) {
    while (kb_read_idx == kb_write_idx) {
        asm volatile("hlt");
    }
    char c = keyboard_buffer[kb_read_idx++];
    kb_read_idx %= 256;
    return c;
}
```

### 2.3 PIT Timer (f)

```c
// kernel/pit.c
#include "pit.h"

#define PIT_FREQ 1193182
#define PIT_DATA0 0x40
#define PIT_CMD 0x43

static uint64_t ticks = 0;

void pit_init(uint32_t freq) {
    uint32_t divisor = PIT_FREQ / freq;

    outb(PIT_CMD, 0x36);  // Channel 0, lobyte/hibyte, mode 3
    outb(PIT_DATA0, divisor & 0xFF);
    outb(PIT_DATA0, (divisor >> 8) & 0xFF);
}

void pit_handler(registers_t* regs) {
    ticks++;
}

void pit_sleep(uint32_t ms) {
    uint64_t end = ticks + (ms * 100 / 1000);  // Assuming 100 Hz
    while (ticks < end) {
        asm volatile("hlt");
    }
}
```

---

## Partie 3: Memory Management (PROJET 2.8.g-i)

### 3.1 Physical Memory Manager (g)

```c
// kernel/pmm.c
#include "pmm.h"

#define PAGE_SIZE 4096

static uint8_t* bitmap;
static uint32_t total_pages;
static uint32_t used_pages;

void pmm_init(multiboot_info_t* mbi) {
    // Get memory from multiboot
    uint32_t mem_end = 0;

    multiboot_memory_map_t* mmap = (multiboot_memory_map_t*)mbi->mmap_addr;
    while ((uint32_t)mmap < mbi->mmap_addr + mbi->mmap_length) {
        if (mmap->type == 1) {  // Available
            uint32_t end = mmap->addr + mmap->len;
            if (end > mem_end) mem_end = end;
        }
        mmap = (multiboot_memory_map_t*)((uint32_t)mmap + mmap->size + 4);
    }

    total_pages = mem_end / PAGE_SIZE;
    bitmap = /* place after kernel */;

    // Mark all as used
    memset(bitmap, 0xFF, total_pages / 8);
    used_pages = total_pages;

    // Mark available regions
    mmap = (multiboot_memory_map_t*)mbi->mmap_addr;
    while ((uint32_t)mmap < mbi->mmap_addr + mbi->mmap_length) {
        if (mmap->type == 1) {
            pmm_mark_region_free(mmap->addr, mmap->len);
        }
        mmap = (multiboot_memory_map_t*)((uint32_t)mmap + mmap->size + 4);
    }

    // Mark kernel as used
    pmm_mark_region_used(0, /* kernel end */);
}

void* pmm_alloc_page(void) {
    for (uint32_t i = 0; i < total_pages; i++) {
        if (!(bitmap[i / 8] & (1 << (i % 8)))) {
            bitmap[i / 8] |= (1 << (i % 8));
            used_pages++;
            return (void*)(i * PAGE_SIZE);
        }
    }
    return NULL;
}
```

### 3.2 Paging (h)

```c
// kernel/vmm.c
#include "vmm.h"

static uint32_t* page_directory;

void vmm_init(void) {
    // Allocate page directory
    page_directory = (uint32_t*)pmm_alloc_page();
    memset(page_directory, 0, PAGE_SIZE);

    // Identity map first 4MB (for kernel)
    uint32_t* page_table = (uint32_t*)pmm_alloc_page();
    for (int i = 0; i < 1024; i++) {
        page_table[i] = (i * 0x1000) | 3;  // Present, RW
    }
    page_directory[0] = (uint32_t)page_table | 3;

    // Load page directory
    asm volatile("mov %0, %%cr3" :: "r"(page_directory));

    // Enable paging
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}
```

### 3.3 Kernel Heap (i)

```c
// kernel/heap.c
#include "heap.h"

typedef struct block_header {
    size_t size;
    bool used;
    struct block_header* next;
} block_header_t;

static block_header_t* heap_start;
static block_header_t* heap_end;

void heap_init(void* start, size_t size) {
    heap_start = (block_header_t*)start;
    heap_start->size = size - sizeof(block_header_t);
    heap_start->used = false;
    heap_start->next = NULL;
    heap_end = heap_start;
}

void* kmalloc(size_t size) {
    // First-fit allocation
    block_header_t* current = heap_start;
    while (current) {
        if (!current->used && current->size >= size) {
            // Split if possible
            if (current->size > size + sizeof(block_header_t) + 16) {
                block_header_t* new_block =
                    (block_header_t*)((uint8_t*)(current + 1) + size);
                new_block->size = current->size - size - sizeof(block_header_t);
                new_block->used = false;
                new_block->next = current->next;
                current->next = new_block;
                current->size = size;
            }
            current->used = true;
            return (void*)(current + 1);
        }
        current = current->next;
    }
    return NULL;
}

void kfree(void* ptr) {
    if (!ptr) return;
    block_header_t* block = (block_header_t*)ptr - 1;
    block->used = false;
    // Coalesce with next block if free
}
```

---

## Partie 4: Shell (PROJET 2.8.j)

```c
// kernel/shell.c
#include "shell.h"

static char line_buffer[256];
static int line_pos = 0;

typedef struct {
    const char* name;
    void (*handler)(const char* args);
} command_t;

void cmd_help(const char* args);
void cmd_clear(const char* args);
void cmd_echo(const char* args);
void cmd_mem(const char* args);
void cmd_reboot(const char* args);

static command_t commands[] = {
    {"help", cmd_help},
    {"clear", cmd_clear},
    {"echo", cmd_echo},
    {"mem", cmd_mem},
    {"reboot", cmd_reboot},
    {NULL, NULL}
};

void shell_init(void) {
    vga_printf("\n");
    vga_printf("  ____       _       ___  ____  \n");
    vga_printf(" |  _ \\ ___ | | ____/ _ \\/ ___| \n");
    vga_printf(" | |_) / _ \\| |/ / | | \\___ \\ \n");
    vga_printf(" |  __/ (_) |   <  | |_| |__) |\n");
    vga_printf(" |_|   \\___/|_|\\_\\ \\___/____/ \n");
    vga_printf("\n");
    vga_printf("PokéOS v0.1 - Type 'help' for commands\n\n");
    shell_prompt();
}

void shell_prompt(void) {
    vga_set_color(VGA_LIGHT_GREEN, VGA_BLACK);
    vga_printf("pokeos> ");
    vga_set_color(VGA_WHITE, VGA_BLACK);
}

void shell_run(void) {
    while (1) {
        char c = keyboard_read();

        if (c == '\n') {
            vga_putchar('\n');
            line_buffer[line_pos] = '\0';
            shell_execute(line_buffer);
            line_pos = 0;
            shell_prompt();
        } else if (c == '\b' && line_pos > 0) {
            line_pos--;
            vga_putchar('\b');
            vga_putchar(' ');
            vga_putchar('\b');
        } else if (c >= ' ' && line_pos < 255) {
            line_buffer[line_pos++] = c;
            vga_putchar(c);
        }
    }
}

void shell_execute(const char* line) {
    // Parse command and arguments
    char cmd[64];
    const char* args = "";

    int i = 0;
    while (line[i] && line[i] != ' ' && i < 63) {
        cmd[i] = line[i];
        i++;
    }
    cmd[i] = '\0';

    if (line[i] == ' ') {
        args = &line[i + 1];
    }

    // Find and execute command
    for (int j = 0; commands[j].name; j++) {
        if (strcmp(cmd, commands[j].name) == 0) {
            commands[j].handler(args);
            return;
        }
    }

    if (cmd[0]) {
        vga_printf("Unknown command: %s\n", cmd);
    }
}
```

---

## Build & Test (PROJET 2.8.l)

### Makefile

```makefile
CC = i686-elf-gcc
AS = nasm
LD = i686-elf-ld

CFLAGS = -m32 -std=c17 -ffreestanding -O2 -Wall -Wextra -Iinclude
ASFLAGS = -f elf32
LDFLAGS = -T linker.ld -nostdlib

OBJECTS = boot/boot.o kernel/kernel.o kernel/gdt.o kernel/idt.o \
          kernel/pic.o kernel/pit.o kernel/keyboard.o \
          kernel/pmm.o kernel/vmm.o kernel/heap.o kernel/shell.o \
          drivers/vga.o lib/string.o lib/stdio.o

all: pokeos.iso

pokeos.bin: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^

pokeos.iso: pokeos.bin
	mkdir -p isodir/boot/grub
	cp pokeos.bin isodir/boot/
	echo 'menuentry "PokéOS" { multiboot /boot/pokeos.bin }' > isodir/boot/grub/grub.cfg
	grub-mkrescue -o $@ isodir

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.asm
	$(AS) $(ASFLAGS) -o $@ $<

run: pokeos.iso
	qemu-system-i386 -cdrom pokeos.iso

debug: pokeos.iso
	qemu-system-i386 -cdrom pokeos.iso -s -S &
	gdb -ex "target remote :1234" -ex "symbol-file pokeos.bin"

clean:
	rm -f $(OBJECTS) pokeos.bin pokeos.iso
	rm -rf isodir
```

---

## Tests Moulinette

```rust
#[test] fn test_multiboot_header()      // PROJET.a,k
#[test] fn test_gdt_setup()             // PROJET.b
#[test] fn test_idt_setup()             // PROJET.c
#[test] fn test_keyboard_driver()       // PROJET.d
#[test] fn test_vga_output()            // PROJET.e
#[test] fn test_pit_timer()             // PROJET.f
#[test] fn test_pmm()                   // PROJET.g
#[test] fn test_paging()                // PROJET.h
#[test] fn test_heap()                  // PROJET.i
#[test] fn test_shell_commands()        // PROJET.j
#[test] fn test_qemu_boot()             // PROJET.l
```

---

## Bareme

| Composant | Points |
|-----------|--------|
| **Boot** | |
| Multiboot entry (a,k) | 10 |
| GDT setup (b) | 10 |
| IDT + PIC (c) | 15 |
| **Drivers** | |
| VGA output (e) | 10 |
| Keyboard (d) | 10 |
| Timer (f) | 5 |
| **Memory** | |
| Physical memory (g) | 15 |
| Paging (h) | 10 |
| Heap (i) | 5 |
| **Shell** | |
| Command line (j) | 10 |
| **Bonus** | |
| VESA graphics (m) | +10 |
| RAM filesystem (n) | +10 |
| Multitasking (o) | +15 |
| **Total** | **100 (+35)** |

---

## Notes

### Prerequis
- Cross-compiler i686-elf-gcc
- NASM assembler
- GRUB tools (grub-mkrescue)
- QEMU for testing

### References
- OSDev Wiki: https://wiki.osdev.org
- Intel Software Developer Manuals
- GRUB Multiboot Specification
