# ex15: Debugging & Analysis Tools

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.28: Debugging and Analysis Tools (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | GDB | GNU Debugger |
| b | GDB commands | break, run, step, next, print |
| c | GDB examine | x/10x $rsp |
| d | pwndbg | GDB enhancement |
| e | GEF | GDB enhancement |
| f | peda | GDB enhancement |
| g | strace | System call trace |
| h | ltrace | Library call trace |
| i | objdump | Disassembly |
| j | radare2 | Reverse engineering |
| k | Ghidra | Decompiler |

### 2.9.29: GDB Advanced Usage (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Conditional breakpoints | break if condition |
| b | Watchpoints | watch variable |
| c | Catchpoints | catch syscall |
| d | GDB scripting | Python API |
| e | Hooks | Run on events |
| f | Reverse debugging | record, reverse-step |
| g | Remote debugging | gdbserver |
| h | Core dump analysis | gdb program core |
| i | Symbol files | Separate debug info |

---

## Sujet

Maitriser les outils de debogage et d'analyse pour l'exploitation binaire.

### Commandes essentielles

```bash
# GDB basics
gdb ./program
gdb -q ./program           # Quiet mode
gdb -p PID                 # Attach to process
gdb ./program core         # Analyze core dump

# GDB startup
set disassembly-flavor intel
set pagination off
```

---

## Exemple

```c
#include "analysis_tools.h"

int main(void) {
    printf("=== Debugging & Analysis Tools ===\n\n");

    // GDB Basics
    printf("=== GDB (GNU Debugger) ===\n\n");

    printf("Starting GDB:\n");
    printf("  gdb ./program           # Debug executable\n");
    printf("  gdb -q ./program        # Quiet mode (no banner)\n");
    printf("  gdb -p <pid>            # Attach to running process\n");
    printf("  gdb ./program core      # Analyze core dump\n");

    printf("\n\nEssential GDB Commands:\n");
    printf("  +---------------+----------------------------------------+\n");
    printf("  | Command       | Description                            |\n");
    printf("  +---------------+----------------------------------------+\n");
    printf("  | run [args]    | Start program with arguments           |\n");
    printf("  | r             | Short for run                          |\n");
    printf("  | break main    | Set breakpoint at main                 |\n");
    printf("  | b *0x401234   | Breakpoint at address                  |\n");
    printf("  | continue      | Continue execution                     |\n");
    printf("  | c             | Short for continue                     |\n");
    printf("  | step          | Step into function                     |\n");
    printf("  | s             | Short for step                         |\n");
    printf("  | next          | Step over function                     |\n");
    printf("  | n             | Short for next                         |\n");
    printf("  | stepi/si      | Step one instruction                   |\n");
    printf("  | nexti/ni      | Next instruction (over calls)          |\n");
    printf("  | finish        | Run until function returns             |\n");
    printf("  | info reg      | Show registers                         |\n");
    printf("  | info break    | List breakpoints                       |\n");
    printf("  | delete N      | Delete breakpoint N                    |\n");
    printf("  | quit          | Exit GDB                               |\n");
    printf("  +---------------+----------------------------------------+\n");

    // Examining memory
    printf("\n\nExamining Memory (x command):\n");
    printf("  x/FMT ADDRESS\n");
    printf("  FMT = [count][format][size]\n");
    printf("\n  Formats:\n");
    printf("    x - hex          d - decimal\n");
    printf("    s - string       i - instruction\n");
    printf("    c - char         a - address\n");
    printf("\n  Sizes:\n");
    printf("    b - byte (1)     h - halfword (2)\n");
    printf("    w - word (4)     g - giant (8)\n");

    printf("\n  Examples:\n");
    printf("    x/20x $rsp        # 20 hex words from stack\n");
    printf("    x/10i $rip        # 10 instructions from RIP\n");
    printf("    x/s 0x404000      # String at address\n");
    printf("    x/16gx $rsp       # 16 quad-words (64-bit)\n");
    printf("    x/100bx buf       # 100 bytes from buf\n");

    // Print command
    printf("\n\nPrint Command:\n");
    printf("  print expr          # Evaluate expression\n");
    printf("  p/x var             # Print in hex\n");
    printf("  p (char*)0x404000   # Cast and print\n");
    printf("  p $rax              # Print register\n");
    printf("  set var = value     # Modify variable\n");
    printf("  set $rax = 0x41     # Modify register\n");

    // GDB enhancements
    printf("\n\n=== GDB Enhancements ===\n\n");

    printf("pwndbg (Recommended for CTF/pwn):\n");
    printf("  https://github.com/pwndbg/pwndbg\n");
    printf("  Features:\n");
    printf("  - Automatic context display (regs, stack, code)\n");
    printf("  - Heap visualization (heap, bins, vis)\n");
    printf("  - ROP gadget search\n");
    printf("  - checksec command\n");
    printf("  - vmmap - memory mappings\n");
    printf("  - telescope - smart pointer dereferencing\n");

    printf("\n  pwndbg commands:\n");
    printf("    vmmap            # Memory map\n");
    printf("    heap             # Heap overview\n");
    printf("    bins             # Free list bins\n");
    printf("    telescope 20     # Dereference stack\n");
    printf("    checksec         # Security flags\n");
    printf("    rop              # Find gadgets\n");
    printf("    cyclic 100       # Pattern generation\n");
    printf("    cyclic -l 0x6161 # Find pattern offset\n");

    printf("\nGEF (GDB Enhanced Features):\n");
    printf("  https://github.com/hugsy/gef\n");
    printf("  Similar to pwndbg, different style\n");
    printf("  Good documentation\n");

    printf("\npeda (Python Exploit Dev Assistance):\n");
    printf("  https://github.com/longld/peda\n");
    printf("  Older but still useful\n");

    // 2.9.29: Advanced GDB
    printf("\n\n=== Advanced GDB Usage ===\n\n");

    printf("Conditional Breakpoints:\n");
    printf("  break func if arg > 100\n");
    printf("  break *0x401234 if $rax == 0\n");
    printf("  condition 1 x > 5        # Add condition to bp 1\n");

    printf("\n\nWatchpoints (Break on memory change):\n");
    printf("  watch var               # Break when var changes\n");
    printf("  watch *0x404040         # Watch memory address\n");
    printf("  rwatch var              # Break on read\n");
    printf("  awatch var              # Break on read or write\n");
    printf("  info watchpoints        # List watchpoints\n");

    printf("\n\nCatchpoints:\n");
    printf("  catch syscall           # Break on any syscall\n");
    printf("  catch syscall write     # Break on write()\n");
    printf("  catch signal SIGSEGV    # Break on segfault\n");
    printf("  catch throw             # Break on C++ exception\n");

    printf("\n\nGDB Python Scripting:\n");
    printf("  (gdb) python print(gdb.parse_and_eval('$rsp'))\n");
    printf("  (gdb) source script.py\n");
    printf("\n  script.py:\n");
    printf("    import gdb\n");
    printf("    class MyCommand(gdb.Command):\n");
    printf("        def __init__(self):\n");
    printf("            super().__init__('mycommand', gdb.COMMAND_USER)\n");
    printf("        def invoke(self, arg, from_tty):\n");
    printf("            rsp = gdb.parse_and_eval('$rsp')\n");
    printf("            print(f'RSP = {rsp}')\n");
    printf("    MyCommand()\n");

    printf("\n\nReverse Debugging:\n");
    printf("  record                  # Start recording\n");
    printf("  reverse-step            # Step backward\n");
    printf("  reverse-continue        # Continue backward\n");
    printf("  reverse-nexti           # Next instruction backward\n");
    printf("  record stop             # Stop recording\n");
    printf("  Note: Slow, high memory usage\n");

    printf("\n\nRemote Debugging:\n");
    printf("  # On target:\n");
    printf("  gdbserver :1234 ./program\n");
    printf("  \n");
    printf("  # On host:\n");
    printf("  gdb ./program\n");
    printf("  (gdb) target remote target_ip:1234\n");

    printf("\n\nCore Dump Analysis:\n");
    printf("  ulimit -c unlimited     # Enable core dumps\n");
    printf("  ./program               # Crash creates core\n");
    printf("  gdb ./program core      # Analyze\n");
    printf("  (gdb) bt                # Backtrace\n");
    printf("  (gdb) info reg          # Registers at crash\n");
    printf("  (gdb) x/10i $rip        # Code at crash\n");

    // Other tools
    printf("\n\n=== Other Analysis Tools ===\n\n");

    printf("strace (System call trace):\n");
    printf("  strace ./program        # Trace all syscalls\n");
    printf("  strace -e open,read     # Filter syscalls\n");
    printf("  strace -p PID           # Attach to process\n");
    printf("  strace -f ./program     # Follow forks\n");

    printf("\nltrace (Library call trace):\n");
    printf("  ltrace ./program        # Trace library calls\n");
    printf("  ltrace -e malloc+free   # Filter functions\n");

    printf("\n\nobjdump (Disassembly):\n");
    printf("  objdump -d program      # Disassemble .text\n");
    printf("  objdump -D program      # Disassemble all\n");
    printf("  objdump -M intel -d p   # Intel syntax\n");
    printf("  objdump -t program      # Symbol table\n");
    printf("  objdump -R program      # Relocations (GOT)\n");

    printf("\n\nreadelf:\n");
    printf("  readelf -h program      # ELF header\n");
    printf("  readelf -S program      # Sections\n");
    printf("  readelf -s program      # Symbols\n");
    printf("  readelf -l program      # Program headers\n");

    printf("\n\nradare2 (r2):\n");
    printf("  r2 ./program            # Open binary\n");
    printf("  aaa                     # Analyze all\n");
    printf("  afl                     # List functions\n");
    printf("  pdf @ main              # Disassemble main\n");
    printf("  VV                      # Visual graph mode\n");
    printf("  px 100 @ 0x404000       # Hexdump\n");
    printf("  /R pop rdi              # Search gadgets\n");

    printf("\n\nGhidra (NSA Decompiler):\n");
    printf("  Free, powerful decompiler\n");
    printf("  Generates C-like pseudocode\n");
    printf("  Good for understanding binary logic\n");
    printf("  Java-based GUI application\n");

    printf("\n\nIDA Pro (Industry Standard):\n");
    printf("  Commercial, expensive\n");
    printf("  Best disassembler/decompiler\n");
    printf("  IDA Free available (limited)\n");

    // Workflow
    printf("\n\n=== Typical Analysis Workflow ===\n\n");
    printf("1. Initial recon:\n");
    printf("   file program           # File type\n");
    printf("   checksec program       # Protections\n");
    printf("   strings program        # Embedded strings\n");
    printf("\n");
    printf("2. Static analysis:\n");
    printf("   objdump -d program     # Quick disassembly\n");
    printf("   Ghidra/IDA             # Decompile\n");
    printf("   Understand program flow\n");
    printf("\n");
    printf("3. Dynamic analysis:\n");
    printf("   gdb ./program          # Debug\n");
    printf("   strace/ltrace          # Trace calls\n");
    printf("   Find vulnerability\n");
    printf("\n");
    printf("4. Exploit development:\n");
    printf("   pwntools script        # Automate exploit\n");
    printf("   Test and refine\n");

    return 0;
}
```

---

## Fichiers

```
ex15/
├── analysis_tools.h
├── gdb_basics.c
├── gdb_advanced.c
├── gdb_scripts/
│   ├── heap_analysis.py
│   └── rop_helper.py
└── Makefile
```
