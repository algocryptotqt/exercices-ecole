# ex16: Binary Analysis & Reverse Engineering

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.30: Binary Analysis (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Static analysis | Without execution |
| b | Dynamic analysis | During execution |
| c | Disassembly | Code to assembly |
| d | Decompilation | Assembly to C-like |
| e | Control flow graph | Visual representation |
| f | Cross-references | Where used |
| g | Strings | Embedded text |
| h | Imports/exports | External dependencies |
| i | Symbols | Function names |

### 2.9.31: Reverse Engineering (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Purpose | Understand binary |
| b | Ghidra | NSA decompiler |
| c | IDA Pro | Industry standard |
| d | Binary Ninja | Modern tool |
| e | Function identification | Recognize patterns |
| f | Data structure recovery | Structs from usage |
| g | Algorithm analysis | Understand logic |
| h | Anti-reversing | Obfuscation |

---

## Sujet

Maitriser l'analyse et la retro-ingenierie de binaires.

---

## Exemple

```c
#include "binary_reversing.h"

int main(void) {
    printf("=== Binary Analysis ===\n\n");

    // Static vs Dynamic
    printf("Analysis Approaches:\n\n");

    printf("Static Analysis:\n");
    printf("  Examine binary WITHOUT running it\n");
    printf("  + Safe (no execution)\n");
    printf("  + See all code paths\n");
    printf("  - Can be obfuscated/packed\n");
    printf("  - Missing runtime information\n");

    printf("\nDynamic Analysis:\n");
    printf("  Examine binary WHILE running\n");
    printf("  + See actual values\n");
    printf("  + Bypass some obfuscation\n");
    printf("  - Only see executed paths\n");
    printf("  - Risk if malware\n");

    // Disassembly
    printf("\n\n=== Disassembly ===\n\n");

    printf("Converting machine code to assembly:\n");
    printf("  48 89 e5 -> mov rbp, rsp\n");
    printf("  48 83 ec 20 -> sub rsp, 0x20\n");

    printf("\n  Linear sweep:\n");
    printf("    Decode sequentially from start\n");
    printf("    Can be fooled by data in .text\n");

    printf("\n  Recursive descent:\n");
    printf("    Follow control flow\n");
    printf("    More accurate, may miss code\n");

    // Decompilation
    printf("\n\n=== Decompilation ===\n\n");

    printf("Assembly to C-like pseudocode:\n");
    printf("\n  Assembly:\n");
    printf("    push rbp\n");
    printf("    mov rbp, rsp\n");
    printf("    sub rsp, 0x10\n");
    printf("    mov DWORD PTR [rbp-4], edi\n");
    printf("    cmp DWORD PTR [rbp-4], 0\n");
    printf("    jle .L2\n");
    printf("    mov eax, DWORD PTR [rbp-4]\n");
    printf("    add eax, 1\n");
    printf("    jmp .L3\n");
    printf("    .L2:\n");
    printf("    mov eax, 0\n");
    printf("    .L3:\n");
    printf("    leave\n");
    printf("    ret\n");

    printf("\n  Decompiled:\n");
    printf("    int func(int arg) {\n");
    printf("        if (arg > 0)\n");
    printf("            return arg + 1;\n");
    printf("        return 0;\n");
    printf("    }\n");

    // Control flow graph
    printf("\n\n=== Control Flow Graph (CFG) ===\n\n");

    printf("Visual representation of code flow:\n");
    printf("\n  +--------+\n");
    printf("  | Entry  |\n");
    printf("  +---+----+\n");
    printf("      |\n");
    printf("      v\n");
    printf("  +--------+     no\n");
    printf("  | if(x>0)|--------+\n");
    printf("  +---+----+        |\n");
    printf("      | yes         |\n");
    printf("      v             v\n");
    printf("  +--------+   +--------+\n");
    printf("  | ret x+1|   | ret 0  |\n");
    printf("  +--------+   +--------+\n");

    printf("\n  Useful for:\n");
    printf("  - Understanding program logic\n");
    printf("  - Finding all paths\n");
    printf("  - Identifying loops/branches\n");

    // Cross-references
    printf("\n\n=== Cross-References (XREF) ===\n\n");

    printf("Track where functions/data are used:\n");
    printf("\n  func_A:\n");
    printf("    XREF from main+0x15\n");
    printf("    XREF from func_B+0x42\n");
    printf("\n  global_var:\n");
    printf("    XREF (read) from func_A+0x10\n");
    printf("    XREF (write) from func_C+0x30\n");

    printf("\n  Useful for:\n");
    printf("  - Finding callers of function\n");
    printf("  - Tracking data usage\n");
    printf("  - Understanding dependencies\n");

    // Strings
    printf("\n\n=== String Analysis ===\n\n");

    printf("Embedded strings reveal:\n");
    printf("  - Error messages\n");
    printf("  - Debug info\n");
    printf("  - File paths\n");
    printf("  - URLs/IPs\n");
    printf("  - Passwords (if hardcoded!)\n");

    printf("\n  $ strings binary | head\n");
    printf("  /lib64/ld-linux-x86-64.so.2\n");
    printf("  libc.so.6\n");
    printf("  printf\n");
    printf("  Usage: %%s <password>\n");
    printf("  Correct!\n");
    printf("  Wrong password\n");

    // Imports/Exports
    printf("\n\n=== Imports/Exports ===\n\n");

    printf("Imports: External functions used\n");
    printf("  printf, malloc, strcmp, ...\n");
    printf("  Reveal functionality\n");
    printf("  Found in GOT/PLT\n");

    printf("\nExports: Functions provided\n");
    printf("  Library public API\n");
    printf("  Entry points\n");

    printf("\n  $ readelf -s binary | grep FUNC\n");

    // Reverse Engineering
    printf("\n\n=== Reverse Engineering ===\n\n");

    printf("Purpose:\n");
    printf("  - Understand undocumented software\n");
    printf("  - Find vulnerabilities\n");
    printf("  - Analyze malware\n");
    printf("  - Recover lost source\n");
    printf("  - Interoperability\n");

    // Tools
    printf("\n\n=== RE Tools ===\n\n");

    printf("Ghidra (NSA, free):\n");
    printf("  - Excellent decompiler\n");
    printf("  - Good for beginners\n");
    printf("  - Scriptable (Java/Python)\n");
    printf("  - Multi-architecture\n");

    printf("\nIDA Pro (commercial):\n");
    printf("  - Industry standard\n");
    printf("  - Best disassembler\n");
    printf("  - Hex-Rays decompiler (extra)\n");
    printf("  - Extensive plugins\n");
    printf("  - IDA Free for non-commercial\n");

    printf("\nBinary Ninja:\n");
    printf("  - Modern, fast\n");
    printf("  - Clean UI\n");
    printf("  - Good API\n");
    printf("  - Commercial (free cloud version)\n");

    printf("\nradare2/Cutter:\n");
    printf("  - Free, open source\n");
    printf("  - Command line powerful\n");
    printf("  - Cutter = GUI for r2\n");
    printf("  - Steep learning curve\n");

    // RE Techniques
    printf("\n\n=== RE Techniques ===\n\n");

    printf("Function Identification:\n");
    printf("  - Function prologue: push rbp; mov rbp, rsp\n");
    printf("  - Epilogue: leave; ret\n");
    printf("  - Signature matching (FLIRT in IDA)\n");
    printf("  - Library function recognition\n");

    printf("\nData Structure Recovery:\n");
    printf("  Infer struct from usage:\n");
    printf("    mov eax, [rbx]      ; field at offset 0\n");
    printf("    mov ecx, [rbx+8]    ; field at offset 8\n");
    printf("    mov rdx, [rbx+0x10] ; field at offset 16\n");
    printf("\n  Suggests:\n");
    printf("    struct {\n");
    printf("        int field_0;     // +0\n");
    printf("        int pad;         // +4 (alignment)\n");
    printf("        long field_8;    // +8\n");
    printf("        void *field_10;  // +16\n");
    printf("    };\n");

    printf("\nAlgorithm Analysis:\n");
    printf("  - Recognize patterns\n");
    printf("  - Loop analysis (for, while)\n");
    printf("  - Mathematical operations\n");
    printf("  - Crypto primitives (S-boxes, rotations)\n");

    // Anti-reversing
    printf("\n\n=== Anti-Reversing Techniques ===\n\n");

    printf("Obfuscation:\n");
    printf("  - Control flow flattening\n");
    printf("  - Dead code insertion\n");
    printf("  - String encryption\n");
    printf("  - Symbol stripping\n");

    printf("\nPacking:\n");
    printf("  - UPX, Themida, VMProtect\n");
    printf("  - Compressed/encrypted code\n");
    printf("  - Unpacks at runtime\n");
    printf("  - Must dump after unpack\n");

    printf("\nAnti-debugging:\n");
    printf("  - IsDebuggerPresent()\n");
    printf("  - Timing checks\n");
    printf("  - INT3 scanning\n");
    printf("  - Parent process check\n");

    printf("\nVM detection:\n");
    printf("  - CPUID checks\n");
    printf("  - VM-specific artifacts\n");
    printf("  - MAC address prefixes\n");

    // Practical workflow
    printf("\n\n=== RE Workflow ===\n\n");

    printf("1. Initial assessment:\n");
    printf("   file, strings, checksec\n");
    printf("\n");
    printf("2. Load in Ghidra/IDA:\n");
    printf("   Let auto-analysis run\n");
    printf("\n");
    printf("3. Start from entry point:\n");
    printf("   main() or entry stub\n");
    printf("\n");
    printf("4. Identify key functions:\n");
    printf("   Follow interesting calls\n");
    printf("   Name and annotate\n");
    printf("\n");
    printf("5. Analyze data structures:\n");
    printf("   Create struct definitions\n");
    printf("\n");
    printf("6. Document findings:\n");
    printf("   Comments, renamed vars\n");
    printf("\n");
    printf("7. Dynamic verification:\n");
    printf("   Confirm with debugging\n");

    return 0;
}
```

---

## Fichiers

```
ex16/
├── binary_reversing.h
├── static_analysis.c
├── dynamic_analysis.c
├── pattern_recognition.c
└── Makefile
```
