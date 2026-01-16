# ex22: System Performance Analysis

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.40: System Performance (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | USE Method | Utilization, Saturation, Errors |
| b | Utilization | Percentage busy |
| c | Saturation | Queue length |
| d | Errors | Error count |
| e | CPU analysis | top, mpstat, pidstat |
| f | Memory analysis | free, vmstat, slabtop |
| g | Disk analysis | iostat, iotop |
| h | Network analysis | sar, ss, netstat |
| i | Performance methodology | Systematic approach |

---

## Sujet

Maitriser l'analyse de performance systeme avec la methode USE.

---

## Exemple

```c
#include "performance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================
// USE Method
// ============================================

void explain_use_method(void) {
    printf("=== USE Method ===\n\n");

    printf("USE = Utilization, Saturation, Errors\n");
    printf("Created by Brendan Gregg\n\n");

    printf("For every resource, check:\n");
    printf("  U - Utilization: %% time resource was busy\n");
    printf("  S - Saturation:  Degree of queueing\n");
    printf("  E - Errors:      Error count\n");

    printf("\nResources to check:\n");
    printf("  - CPUs\n");
    printf("  - Memory\n");
    printf("  - Storage devices\n");
    printf("  - Network interfaces\n");
    printf("  - Controllers (storage, network)\n");
    printf("  - Interconnects (buses)\n");

    printf("\nBenefits:\n");
    printf("  - Systematic approach\n");
    printf("  - Covers common bottlenecks\n");
    printf("  - Quick to perform\n");
    printf("  - Works for any resource\n");

    printf("\nUSE Method flowchart:\n");
    printf("  For each resource:\n");
    printf("  1. Check errors -> High? Investigate!\n");
    printf("  2. Check utilization -> 100%%? Bottleneck!\n");
    printf("  3. Check saturation -> Queueing? Bottleneck!\n");
}

// ============================================
// CPU Analysis
// ============================================

void explain_cpu_use(void) {
    printf("\n=== CPU - USE Analysis ===\n\n");

    printf("Utilization:\n");
    printf("  - Per-CPU: mpstat -P ALL 1\n");
    printf("  - Per-process: top, pidstat 1\n");
    printf("  - System-wide: vmstat 1\n");

    printf("\nSaturation:\n");
    printf("  - Run queue length: vmstat 1 (r column)\n");
    printf("  - Load average: uptime, /proc/loadavg\n");
    printf("  - Scheduler latency: perf sched\n");

    printf("\nErrors:\n");
    printf("  - Machine check exceptions: dmesg | grep -i mce\n");
    printf("  - CPU throttling: dmesg | grep -i throttl\n");
}

void show_cpu_tools(void) {
    printf("\n=== CPU Tools ===\n\n");

    printf("top:\n");
    printf("  Interactive process viewer\n");
    printf("  Press '1' to show per-CPU stats\n");
    printf("  Press 'H' to show threads\n");

    printf("\nmpstat -P ALL 1:\n");
    printf("  CPU    %%usr   %%sys %%iowait   %%irq  %%soft  %%idle\n");
    printf("  all    25.0    5.0     2.0    0.5    0.2   67.3\n");
    printf("    0    30.0    6.0     3.0    1.0    0.3   59.7\n");
    printf("    1    20.0    4.0     1.0    0.0    0.1   74.9\n");

    printf("\npidstat 1:\n");
    printf("  PID    %%usr  %%system  %%CPU   Command\n");
    printf("  1234   45.0     5.0  50.0   myapp\n");

    printf("\nvmstat 1:\n");
    printf("  procs  memory        swap      io     system      cpu\n");
    printf("  r  b   swpd   free    si  so   bi  bo   in   cs  us sy id wa\n");
    printf("  2  0      0  10000    0   0   10   5  200  400  25  5 68  2\n");
    printf("  │\n");
    printf("  └─ r = run queue (saturation!)\n");

    printf("\nuptime:\n");
    printf("  load average: 2.50, 2.00, 1.50\n");
    printf("  │      │      │\n");
    printf("  │      │      └─ 15 min average\n");
    printf("  │      └─ 5 min average\n");
    printf("  └─ 1 min average\n");
    printf("\n");
    printf("  Load > CPU count = saturation\n");
}

// ============================================
// Memory Analysis
// ============================================

void explain_memory_use(void) {
    printf("\n=== Memory - USE Analysis ===\n\n");

    printf("Utilization:\n");
    printf("  - free -m\n");
    printf("  - vmstat 1 (free column)\n");
    printf("  - /proc/meminfo\n");

    printf("\nSaturation:\n");
    printf("  - Swapping: vmstat 1 (si, so columns)\n");
    printf("  - Page scanning: sar -B 1 (pgscank, pgscand)\n");
    printf("  - OOM killer: dmesg | grep -i oom\n");
    printf("  - Memory pressure: /proc/pressure/memory\n");

    printf("\nErrors:\n");
    printf("  - Hardware errors: dmesg | grep -i memory\n");
    printf("  - Allocation failures: dmesg | grep -i 'out of memory'\n");
}

void show_memory_tools(void) {
    printf("\n=== Memory Tools ===\n\n");

    printf("free -m:\n");
    printf("              total   used   free  shared  buffers  cached\n");
    printf("  Mem:        16000  12000   4000     200      500    6000\n");
    printf("  Swap:        8000     50   7950\n");
    printf("\n");
    printf("  Available = free + buffers + cached (mostly)\n");

    printf("\nvmstat 1 (memory columns):\n");
    printf("  swpd   free   buff  cache   si   so\n");
    printf("     0  4000   500   6000    0    0   <- Good\n");
    printf("  1000  1000   100    500  100  200   <- Bad (swapping)\n");

    printf("\n/proc/meminfo:\n");
    printf("  MemTotal, MemFree, MemAvailable\n");
    printf("  Buffers, Cached, SwapCached\n");
    printf("  Active, Inactive, Dirty\n");

    printf("\nslabtop:\n");
    printf("  Kernel slab allocator usage\n");
    printf("  Shows memory used by kernel caches\n");

    printf("\nPressure Stall Information (PSI):\n");
    printf("  cat /proc/pressure/memory\n");
    printf("  some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
    printf("  full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
    printf("  │\n");
    printf("  └─ some: at least one task waiting\n");
    printf("     full: all non-idle tasks waiting\n");
}

// ============================================
// Disk/Storage Analysis
// ============================================

void explain_disk_use(void) {
    printf("\n=== Storage - USE Analysis ===\n\n");

    printf("Utilization:\n");
    printf("  - iostat -x 1 (%%util column)\n");
    printf("  - Per-device: /sys/block/<dev>/stat\n");

    printf("\nSaturation:\n");
    printf("  - Wait time: iostat -x 1 (avgqu-sz, await)\n");
    printf("  - I/O wait: vmstat 1 (wa column)\n");
    printf("  - Queue depth: /sys/block/<dev>/stat\n");

    printf("\nErrors:\n");
    printf("  - Device errors: dmesg | grep -i 'I/O error'\n");
    printf("  - SMART: smartctl -a /dev/sda\n");
    printf("  - Filesystem: dmesg | grep -i 'ext4\\|xfs'\n");
}

void show_disk_tools(void) {
    printf("\n=== Storage Tools ===\n\n");

    printf("iostat -x 1:\n");
    printf("  Device   r/s    w/s  rkB/s  wkB/s await  %%util\n");
    printf("  sda     10.0   20.0  100.0  200.0   5.0   50.0\n");
    printf("  nvme0n1 500.0  200.0 2000.0 1000.0  0.5   80.0\n");
    printf("\n");
    printf("  await: average I/O wait time (ms)\n");
    printf("  %%util: device utilization\n");
    printf("  r/s, w/s: reads/writes per second\n");

    printf("\niotop:\n");
    printf("  Interactive I/O monitor (per-process)\n");
    printf("  sudo iotop -o  # Only show processes doing I/O\n");

    printf("\nOutput:\n");
    printf("  TID  PRIO  USER  DISK READ  DISK WRITE  COMMAND\n");
    printf("  123  be/4  root    10M/s       5M/s     backup\n");

    printf("\ndfstat (df for I/O stats):\n");
    printf("  df -h           # Space utilization\n");
    printf("  df -i           # Inode utilization\n");

    printf("\nI/O wait in vmstat:\n");
    printf("  wa column shows CPU waiting for I/O\n");
    printf("  High wa + low %%util = I/O subsystem problem\n");
}

// ============================================
// Network Analysis
// ============================================

void explain_network_use(void) {
    printf("\n=== Network - USE Analysis ===\n\n");

    printf("Utilization:\n");
    printf("  - sar -n DEV 1\n");
    printf("  - ip -s link\n");
    printf("  - /proc/net/dev\n");
    printf("  - Compare to link speed\n");

    printf("\nSaturation:\n");
    printf("  - Drops: netstat -s | grep -i drop\n");
    printf("  - Retransmits: ss -ti | grep retrans\n");
    printf("  - Socket queues: ss -l (Recv-Q, Send-Q)\n");
    printf("  - Ring buffer overruns: ethtool -S eth0\n");

    printf("\nErrors:\n");
    printf("  - Interface errors: ip -s link\n");
    printf("  - TCP errors: netstat -s\n");
    printf("  - Driver errors: ethtool -S eth0\n");
}

void show_network_tools(void) {
    printf("\n=== Network Tools ===\n\n");

    printf("sar -n DEV 1:\n");
    printf("  IFACE   rxpck/s  txpck/s   rxkB/s   txkB/s\n");
    printf("  eth0    1000.0    500.0   1000.0    200.0\n");
    printf("  lo       100.0    100.0     50.0     50.0\n");

    printf("\nip -s link show eth0:\n");
    printf("  RX: bytes packets errors dropped\n");
    printf("      1.5G   1000K     0       0\n");
    printf("  TX: bytes packets errors dropped\n");
    printf("      500M   500K      0       0\n");

    printf("\nss -s (socket statistics):\n");
    printf("  Total: 500\n");
    printf("  TCP:   200 (estab 150, closed 10, orphaned 0)\n");
    printf("  UDP:   50\n");

    printf("\nss -ti (TCP internal info):\n");
    printf("  Shows retransmits, RTT, cwnd, etc.\n");
    printf("  retrans:0/5  # 5 retransmits = saturation\n");

    printf("\nnetstat -s | grep -i retrans:\n");
    printf("  123456 segments retransmitted\n");
    printf("  Watch rate, not absolute number\n");

    printf("\nethtool -S eth0:\n");
    printf("  rx_errors: 0\n");
    printf("  tx_errors: 0\n");
    printf("  rx_dropped: 0\n");
    printf("  rx_over_errors: 0   <- Ring buffer overflow\n");
}

// ============================================
// System-Wide Tools
// ============================================

void show_sar(void) {
    printf("\n=== sar (System Activity Reporter) ===\n\n");

    printf("sar collects and reports system statistics:\n");

    printf("\nCPU: sar -u 1\n");
    printf("  %%user  %%nice  %%system  %%iowait  %%idle\n");
    printf("   25.0    0.0      5.0      2.0   68.0\n");

    printf("\nMemory: sar -r 1\n");
    printf("  kbmemfree  kbmemused  %%memused  kbbuffers  kbcached\n");
    printf("    4000000   12000000     75.00     500000   6000000\n");

    printf("\nDisk: sar -d 1\n");
    printf("  DEV       tps  rd_sec/s  wr_sec/s\n");
    printf("  sda      30.0    200.0     400.0\n");

    printf("\nNetwork: sar -n DEV 1\n");
    printf("  IFACE  rxpck/s  txpck/s  rxkB/s  txkB/s\n");
    printf("  eth0    1000.0    500.0  1000.0   200.0\n");

    printf("\nHistorical data:\n");
    printf("  sar -f /var/log/sa/sa15  # Day 15\n");
    printf("  sar -s 09:00 -e 17:00    # Time range\n");
}

void show_dstat(void) {
    printf("\n=== dstat / nmon / glances ===\n\n");

    printf("dstat (combines vmstat, iostat, netstat):\n");
    printf("  dstat -cdngy\n");
    printf("  ----cpu---- -dsk/total- -net/total- ---paging-- ---system--\n");
    printf("  usr sys idl| read  writ| recv  send|  in   out | int   csw\n");
    printf("   25   5  68| 100k  200k| 1.0M  200k|   0     0 | 500  1000\n");

    printf("\nnmon:\n");
    printf("  Interactive all-in-one monitor\n");
    printf("  Press 'c' for CPU, 'm' for memory, 'd' for disk\n");

    printf("\nglances:\n");
    printf("  Modern Python-based monitoring\n");
    printf("  glances\n");
    printf("  glances -w  # Web interface\n");
}

// ============================================
// Performance Methodology
// ============================================

void explain_methodology(void) {
    printf("\n=== Performance Analysis Methodology ===\n\n");

    printf("1. Problem Statement:\n");
    printf("   - What is the actual problem?\n");
    printf("   - What are the symptoms?\n");
    printf("   - When did it start?\n");
    printf("   - What changed recently?\n");

    printf("\n2. USE Method:\n");
    printf("   - Check all resources systematically\n");
    printf("   - Identify bottlenecks quickly\n");

    printf("\n3. Drill Down:\n");
    printf("   - Once bottleneck identified\n");
    printf("   - Use specific tools (perf, strace, etc.)\n");
    printf("   - Find root cause\n");

    printf("\n4. Workload Characterization:\n");
    printf("   - Who is generating load?\n");
    printf("   - What type of workload?\n");
    printf("   - When does it happen?\n");

    printf("\n5. Hypothesis and Test:\n");
    printf("   - Form hypothesis about cause\n");
    printf("   - Test hypothesis\n");
    printf("   - Validate fix\n");
}

void show_use_checklist(void) {
    printf("\n=== USE Method Checklist ===\n\n");

    printf("CPU:\n");
    printf("  U: mpstat -P ALL 1, top\n");
    printf("  S: vmstat 1 (r column), uptime\n");
    printf("  E: dmesg | grep -i mce\n");

    printf("\nMemory:\n");
    printf("  U: free -m, vmstat 1\n");
    printf("  S: vmstat 1 (si/so), dmesg | grep oom\n");
    printf("  E: dmesg | grep -i memory\n");

    printf("\nStorage:\n");
    printf("  U: iostat -x 1 (%%util)\n");
    printf("  S: iostat -x 1 (avgqu-sz, await)\n");
    printf("  E: smartctl, dmesg | grep -i error\n");

    printf("\nNetwork:\n");
    printf("  U: sar -n DEV 1, ip -s link\n");
    printf("  S: ss -ti, netstat -s | grep retrans\n");
    printf("  E: ip -s link, ethtool -S\n");

    printf("\n/proc/pressure/ (PSI):\n");
    printf("  CPU: /proc/pressure/cpu\n");
    printf("  Memory: /proc/pressure/memory\n");
    printf("  I/O: /proc/pressure/io\n");
}

void show_quick_check(void) {
    printf("\n=== 60-Second Analysis ===\n\n");

    printf("Run these commands in first 60 seconds:\n\n");

    printf("1. uptime\n");
    printf("   Check load averages, recent changes\n");

    printf("\n2. dmesg -T | tail\n");
    printf("   Kernel errors, OOM, hardware issues\n");

    printf("\n3. vmstat 1 5\n");
    printf("   CPU, memory, swap, I/O quick view\n");

    printf("\n4. mpstat -P ALL 1 5\n");
    printf("   Per-CPU utilization, imbalance\n");

    printf("\n5. pidstat 1 5\n");
    printf("   Per-process CPU usage\n");

    printf("\n6. iostat -xz 1 5\n");
    printf("   Disk I/O stats\n");

    printf("\n7. free -m\n");
    printf("   Memory usage\n");

    printf("\n8. sar -n DEV 1 5\n");
    printf("   Network interface stats\n");

    printf("\n9. sar -n TCP,ETCP 1 5\n");
    printf("   TCP stats, retransmits\n");

    printf("\n10. top\n");
    printf("    Overall view, identify hot processes\n");
}

// ============================================
// Practical Examples
// ============================================

void show_practical_examples(void) {
    printf("\n=== Practical Performance Scenarios ===\n\n");

    printf("Scenario 1: High CPU\n");
    printf("  Symptoms: System slow, high load\n");
    printf("  Check:\n");
    printf("    mpstat -P ALL 1     # Which CPU?\n");
    printf("    pidstat 1           # Which process?\n");
    printf("    perf top -p PID     # Which function?\n");

    printf("\nScenario 2: Memory Pressure\n");
    printf("  Symptoms: System slow, OOM messages\n");
    printf("  Check:\n");
    printf("    free -m             # How much free?\n");
    printf("    vmstat 1            # Swapping (si/so)?\n");
    printf("    ps aux --sort=-rss  # Top memory users\n");
    printf("    slabtop             # Kernel memory?\n");

    printf("\nScenario 3: Disk Bottleneck\n");
    printf("  Symptoms: High I/O wait, slow response\n");
    printf("  Check:\n");
    printf("    iostat -x 1         # Which device? %%util?\n");
    printf("    iotop               # Which process?\n");
    printf("    lsof | grep PID     # What files?\n");

    printf("\nScenario 4: Network Issues\n");
    printf("  Symptoms: Connection timeouts, drops\n");
    printf("  Check:\n");
    printf("    sar -n DEV 1        # Bandwidth?\n");
    printf("    ss -s               # Socket states?\n");
    printf("    netstat -s          # Retransmits?\n");
    printf("    ethtool -S eth0     # Driver errors?\n");

    printf("\nScenario 5: Application Latency\n");
    printf("  Symptoms: Slow response time\n");
    printf("  Check:\n");
    printf("    strace -T -p PID    # Syscall latency?\n");
    printf("    perf record -g -p PID  # Where is time?\n");
    printf("    lsof -p PID         # What is it waiting on?\n");
}

int main(void) {
    explain_use_method();

    explain_cpu_use();
    show_cpu_tools();

    explain_memory_use();
    show_memory_tools();

    explain_disk_use();
    show_disk_tools();

    explain_network_use();
    show_network_tools();

    show_sar();
    show_dstat();

    explain_methodology();
    show_use_checklist();
    show_quick_check();
    show_practical_examples();

    printf("\n=== Quick Reference ===\n\n");
    printf("USE = Utilization, Saturation, Errors\n");
    printf("  CPU: mpstat, vmstat, uptime\n");
    printf("  MEM: free, vmstat, /proc/meminfo\n");
    printf("  DISK: iostat, iotop\n");
    printf("  NET: sar -n, ss, netstat\n");

    return 0;
}
```

---

## Fichiers

```
ex22/
├── performance.h
├── use_method.c
├── cpu_analysis.c
├── memory_analysis.c
├── disk_analysis.c
├── network_analysis.c
├── methodology.c
└── Makefile
```

