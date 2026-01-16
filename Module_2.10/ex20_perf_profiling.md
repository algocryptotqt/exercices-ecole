# ex20: Advanced Debugging - perf

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.37: Advanced Debugging - perf (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | perf | Performance analysis |
| b | perf stat | Basic counters |
| c | perf record | Profile |
| d | perf report | Analyze profile |
| e | perf top | Live view |
| f | Hardware counters | CPU cycles, cache misses |
| g | Flame graphs | Visualization |
| h | perf probe | Dynamic tracing |

---

## Sujet

Maitriser perf pour l'analyse de performance et le profiling.

---

## Exemple

```c
#include "perf_debug.h"
#include <stdio.h>
#include <stdlib.h>

void explain_perf(void) {
    printf("=== perf (Performance Analysis) ===\n\n");

    printf("perf is Linux's built-in profiling tool:\n");
    printf("  - Uses hardware performance counters\n");
    printf("  - Statistical sampling (low overhead)\n");
    printf("  - Kernel and userspace profiling\n");
    printf("  - Part of linux-tools package\n");

    printf("\nInstall:\n");
    printf("  apt install linux-tools-generic     # Ubuntu\n");
    printf("  yum install perf                    # RHEL/CentOS\n");
}

void show_perf_stat(void) {
    printf("\n=== perf stat ===\n\n");

    printf("Count hardware/software events:\n");
    printf("  perf stat ls\n");
    printf("\n");
    printf("Output:\n");
    printf("  Performance counter stats for 'ls':\n");
    printf("            1.23 msec task-clock           # 0.543 CPUs\n");
    printf("               3      context-switches     #   2.439 K/sec\n");
    printf("               0      cpu-migrations       #   0.000 /sec\n");
    printf("             112      page-faults          #  91.057 K/sec\n");
    printf("       3,456,789      cycles               #   2.811 GHz\n");
    printf("       2,345,678      instructions         #   0.68  per cycle\n");
    printf("         456,789      branches             # 371.373 M/sec\n");
    printf("          12,345      branch-misses        #   2.70%% of branches\n");

    printf("\nSpecific events:\n");
    printf("  perf stat -e cycles,instructions,cache-misses ls\n");

    printf("\nRepeat measurement:\n");
    printf("  perf stat -r 10 ls     # Run 10 times, show stats\n");

    printf("\nGroup events:\n");
    printf("  perf stat -e '{cycles,instructions}' ls\n");

    printf("\nPer-core stats:\n");
    printf("  perf stat -a -A sleep 1    # All CPUs\n");

    printf("\nEvent list:\n");
    printf("  perf list               # Show all events\n");
    printf("  perf list cache         # Cache events\n");
}

void show_perf_record(void) {
    printf("\n=== perf record ===\n\n");

    printf("Sample profiling:\n");
    printf("  perf record ./myprogram\n");
    printf("  perf record -g ./myprogram    # With call graphs\n");
    printf("  # Creates perf.data file\n");

    printf("\nFrequency/period:\n");
    printf("  perf record -F 99 ./myprogram    # 99 Hz sampling\n");
    printf("  perf record -c 10000 ./myprogram # Every 10000 events\n");

    printf("\nProfile system-wide:\n");
    printf("  perf record -a sleep 5     # All CPUs for 5 seconds\n");
    printf("  perf record -a -g sleep 5  # With call graphs\n");

    printf("\nProfile existing process:\n");
    printf("  perf record -p $(pgrep nginx) sleep 10\n");

    printf("\nSpecific events:\n");
    printf("  perf record -e cache-misses ./myprogram\n");
    printf("  perf record -e 'sched:*' sleep 1  # Scheduler tracepoints\n");
}

void show_perf_report(void) {
    printf("\n=== perf report ===\n\n");

    printf("Analyze perf.data:\n");
    printf("  perf report\n");
    printf("  perf report --stdio          # Text output\n");
    printf("  perf report -n               # Show sample counts\n");

    printf("\nOutput:\n");
    printf("  Overhead  Command  Shared Object     Symbol\n");
    printf("  ========  =======  ================  ====================\n");
    printf("    25.00%%  myapp    myapp             [.] compute_heavy\n");
    printf("    15.00%%  myapp    libc.so           [.] malloc\n");
    printf("    10.00%%  myapp    myapp             [.] process_data\n");
    printf("     8.00%%  myapp    [kernel.kallsyms] [k] copy_user\n");

    printf("\nSort options:\n");
    printf("  perf report --sort comm,dso,symbol\n");
    printf("  perf report --sort cpu\n");

    printf("\nFilter:\n");
    printf("  perf report --dsos myapp    # Only myapp binary\n");
    printf("  perf report --comms nginx   # Only nginx process\n");
}

void show_perf_top(void) {
    printf("\n=== perf top ===\n\n");

    printf("Live view (like top for CPU):\n");
    printf("  perf top\n");
    printf("  perf top -g      # With call graph\n");
    printf("  perf top -p PID  # Specific process\n");

    printf("\nOutput:\n");
    printf("  PerfTop:    1000 irqs/sec  kernel:60%% us:40%%\n");
    printf("  ------------------------------------------------------\n");
    printf("   12.50%%  [kernel]       [k] native_write_msr\n");
    printf("    8.30%%  libc-2.31.so   [.] __memcpy_avx2\n");
    printf("    5.20%%  myapp          [.] hot_function\n");

    printf("\nInteractive controls:\n");
    printf("  E: Expand/collapse call graph\n");
    printf("  +: Expand selected entry\n");
    printf("  s: Show source (if available)\n");
    printf("  q: Quit\n");
}

void show_flame_graphs(void) {
    printf("\n=== Flame Graphs ===\n\n");

    printf("Visual representation of profiles:\n");
    printf("  - Width = time spent\n");
    printf("  - Height = call stack depth\n");
    printf("  - Color = random (for differentiation)\n");

    printf("\nGenerate flame graph:\n");
    printf("  # Record with call graphs\n");
    printf("  perf record -g ./myprogram\n");
    printf("\n");
    printf("  # Convert to text\n");
    printf("  perf script > out.perf\n");
    printf("\n");
    printf("  # Generate flame graph (using Brendan Gregg's tools)\n");
    printf("  git clone https://github.com/brendangregg/FlameGraph\n");
    printf("  ./FlameGraph/stackcollapse-perf.pl out.perf > out.folded\n");
    printf("  ./FlameGraph/flamegraph.pl out.folded > flame.svg\n");

    printf("\nOpen in browser:\n");
    printf("  firefox flame.svg\n");

    printf("\nInteractive:\n");
    printf("  - Click to zoom in on function\n");
    printf("  - Search for function names\n");
}

void show_perf_probe(void) {
    printf("\n=== perf probe (Dynamic Tracing) ===\n\n");

    printf("Add probes to kernel/userspace:\n");

    printf("\nKernel probe:\n");
    printf("  perf probe --add tcp_sendmsg\n");
    printf("  perf record -e probe:tcp_sendmsg -a sleep 5\n");
    printf("  perf probe --del tcp_sendmsg\n");

    printf("\nWith arguments:\n");
    printf("  perf probe --add 'tcp_sendmsg size=%%dx'\n");
    printf("  # Capture 'size' (in dx register)\n");

    printf("\nUserspace probe (uprobe):\n");
    printf("  perf probe -x /bin/bash --add 'readline'\n");
    printf("  perf record -e probe_bash:readline -a sleep 5\n");

    printf("\nList probes:\n");
    printf("  perf probe --list\n");

    printf("\nShow available variables:\n");
    printf("  perf probe -x ./myapp --vars func_name\n");
}

void show_hardware_counters(void) {
    printf("\n=== Hardware Performance Counters ===\n\n");

    printf("Common counters:\n");
    printf("  cycles          CPU clock cycles\n");
    printf("  instructions    Instructions executed\n");
    printf("  cache-references  Cache accesses\n");
    printf("  cache-misses      Cache misses\n");
    printf("  branches          Branch instructions\n");
    printf("  branch-misses     Branch mispredictions\n");
    printf("  L1-dcache-loads   L1 data cache loads\n");
    printf("  L1-dcache-load-misses  L1 data cache misses\n");
    printf("  LLC-loads         Last level cache loads\n");
    printf("  LLC-load-misses   LLC misses\n");

    printf("\nExample analysis:\n");
    printf("  perf stat -e cycles,instructions,cache-misses ./myprogram\n");
    printf("\n");
    printf("  IPC (Instructions Per Cycle):\n");
    printf("    > 1.0: Good utilization\n");
    printf("    < 0.5: Memory bound or stalled\n");
    printf("\n");
    printf("  Cache miss ratio:\n");
    printf("    < 2%%: Good cache usage\n");
    printf("    > 10%%: Memory access problem\n");
}

void show_practical_examples(void) {
    printf("\n=== Practical Examples ===\n\n");

    printf("Find CPU hotspots:\n");
    printf("  perf record -g ./slow_program\n");
    printf("  perf report --stdio | head -20\n");

    printf("\nProfile specific function:\n");
    printf("  perf probe --add 'myfunc'\n");
    printf("  perf stat -e probe:myfunc ./myprogram\n");

    printf("\nCache analysis:\n");
    printf("  perf stat -e cache-misses,cache-references ./myprogram\n");
    printf("  echo \"Miss ratio: misses/references\"\n");

    printf("\nScheduling latency:\n");
    printf("  perf sched record ./myprogram\n");
    printf("  perf sched latency\n");

    printf("\nLock contention:\n");
    printf("  perf lock record ./myprogram\n");
    printf("  perf lock report\n");

    printf("\nOff-CPU analysis (what's blocking):\n");
    printf("  perf record -e sched:sched_switch -a sleep 10\n");
    printf("  perf script  # See what caused switches\n");
}

int main(void) {
    explain_perf();
    show_perf_stat();
    show_perf_record();
    show_perf_report();
    show_perf_top();
    show_flame_graphs();
    show_perf_probe();
    show_hardware_counters();
    show_practical_examples();

    printf("\n=== Quick Reference ===\n\n");
    printf("  perf stat cmd        # Count events\n");
    printf("  perf record cmd      # Sample profile\n");
    printf("  perf report          # Analyze samples\n");
    printf("  perf top             # Live view\n");
    printf("  perf list            # Available events\n");
    printf("  perf probe           # Dynamic tracing\n");

    return 0;
}
```

---

## Fichiers

```
ex20/
├── perf_debug.h
├── perf_stat.c
├── perf_record.c
├── flame_graphs.c
├── hardware_counters.c
└── Makefile
```
