# ex21: eBPF - Extended Berkeley Packet Filter

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Avance
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.10.38: eBPF Overview (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | eBPF | Extended BPF |
| b | In-kernel VM | Safe execution |
| c | Verifier | Safety checks |
| d | JIT | Native compilation |
| e | Maps | Data structures |
| f | Helper functions | Kernel interaction |
| g | Program types | kprobe, tracepoint, XDP |
| h | CO-RE | Compile Once Run Everywhere |

### 2.10.39: eBPF Tools (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | bcc | BPF Compiler Collection |
| b | bpftrace | High-level tracing |
| c | libbpf | C library |
| d | bpftool | Inspection |
| e | Common tools | execsnoop, opensnoop |
| f | Custom programs | Write eBPF |
| g | Use cases | Tracing, networking, security |

---

## Sujet

Comprendre eBPF et ses applications en tracing, networking et securite.

---

## Exemple

```c
#include "ebpf_intro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <stdint.h>

// ============================================
// eBPF Overview
// ============================================

void explain_ebpf(void) {
    printf("=== eBPF (Extended Berkeley Packet Filter) ===\n\n");

    printf("eBPF allows running sandboxed programs in the Linux kernel:\n");
    printf("  - No kernel module compilation needed\n");
    printf("  - Safe: verified before execution\n");
    printf("  - Fast: JIT compiled to native code\n");
    printf("  - Flexible: attach to many hook points\n");

    printf("\nHistory:\n");
    printf("  BPF (1992): Packet filtering (tcpdump)\n");
    printf("  eBPF (2014): Extended for general purpose\n");

    printf("\neBPF Architecture:\n");
    printf("  +------------------+\n");
    printf("  | User Program     |\n");
    printf("  +--------+---------+\n");
    printf("           | bpf() syscall\n");
    printf("  +--------v---------+\n");
    printf("  | eBPF Verifier    |  Safety checks\n");
    printf("  +--------+---------+\n");
    printf("           |\n");
    printf("  +--------v---------+\n");
    printf("  | JIT Compiler     |  Native code\n");
    printf("  +--------+---------+\n");
    printf("           |\n");
    printf("  +--------v---------+\n");
    printf("  | Kernel Execution |  At hook points\n");
    printf("  +------------------+\n");
}

void explain_verifier(void) {
    printf("\n=== eBPF Verifier ===\n\n");

    printf("The verifier ensures eBPF programs are safe:\n");

    printf("\nChecks performed:\n");
    printf("  1. DAG (Directed Acyclic Graph)\n");
    printf("     - No loops (bounded execution)\n");
    printf("     - All paths reach exit\n");
    printf("\n");
    printf("  2. Register tracking\n");
    printf("     - Track value ranges\n");
    printf("     - Prevent out-of-bounds access\n");
    printf("\n");
    printf("  3. Memory access\n");
    printf("     - Bounds checking\n");
    printf("     - Proper alignment\n");
    printf("\n");
    printf("  4. Helper function calls\n");
    printf("     - Correct arguments\n");
    printf("     - Appropriate permissions\n");

    printf("\nVerifier limits:\n");
    printf("  - Max instructions: 1 million\n");
    printf("  - Max complexity: ~10 million\n");
    printf("  - Stack size: 512 bytes\n");
    printf("  - Tail calls: 33 max depth\n");

    printf("\nCommon verifier errors:\n");
    printf("  'R1 invalid mem access' - Out of bounds\n");
    printf("  'back-edge from insn' - Loop detected\n");
    printf("  'unreachable insn' - Dead code\n");
}

void explain_jit(void) {
    printf("\n=== JIT Compilation ===\n\n");

    printf("eBPF bytecode is JIT compiled to native code:\n");

    printf("\neBPF registers (11 total):\n");
    printf("  R0:  Return value\n");
    printf("  R1-R5: Function arguments\n");
    printf("  R6-R9: Callee-saved\n");
    printf("  R10: Stack pointer (read-only)\n");

    printf("\neBPF instruction format:\n");
    printf("  struct bpf_insn {\n");
    printf("      __u8  code;     // opcode\n");
    printf("      __u8  dst_reg:4; // destination register\n");
    printf("      __u8  src_reg:4; // source register\n");
    printf("      __s16 off;      // offset\n");
    printf("      __s32 imm;      // immediate value\n");
    printf("  };\n");

    printf("\nJIT status:\n");
    printf("  cat /proc/sys/net/core/bpf_jit_enable\n");
    printf("  # 0 = disabled, 1 = enabled, 2 = debug\n");

    printf("\nEnable JIT:\n");
    printf("  echo 1 > /proc/sys/net/core/bpf_jit_enable\n");
}

// ============================================
// eBPF Maps
// ============================================

void explain_maps(void) {
    printf("\n=== eBPF Maps ===\n\n");

    printf("Maps are key-value stores shared between:\n");
    printf("  - eBPF programs (kernel)\n");
    printf("  - User space programs\n");

    printf("\nCommon map types:\n");
    printf("  BPF_MAP_TYPE_HASH        - Hash table\n");
    printf("  BPF_MAP_TYPE_ARRAY       - Array (fast lookup)\n");
    printf("  BPF_MAP_TYPE_PROG_ARRAY  - Tail call programs\n");
    printf("  BPF_MAP_TYPE_PERF_EVENT_ARRAY - Perf events\n");
    printf("  BPF_MAP_TYPE_RINGBUF     - Ring buffer (efficient)\n");
    printf("  BPF_MAP_TYPE_STACK_TRACE - Stack traces\n");
    printf("  BPF_MAP_TYPE_LRU_HASH    - LRU hash\n");
    printf("  BPF_MAP_TYPE_PERCPU_HASH - Per-CPU hash\n");
    printf("  BPF_MAP_TYPE_PERCPU_ARRAY - Per-CPU array\n");

    printf("\nMap operations:\n");
    printf("  bpf_map_lookup_elem()  - Read value\n");
    printf("  bpf_map_update_elem()  - Write/update\n");
    printf("  bpf_map_delete_elem()  - Delete entry\n");

    printf("\nMap definition (libbpf):\n");
    printf("  struct {\n");
    printf("      __uint(type, BPF_MAP_TYPE_HASH);\n");
    printf("      __uint(max_entries, 1024);\n");
    printf("      __type(key, u32);\n");
    printf("      __type(value, u64);\n");
    printf("  } my_map SEC(\".maps\");\n");
}

void explain_helper_functions(void) {
    printf("\n=== Helper Functions ===\n\n");

    printf("eBPF programs call kernel helpers:\n");

    printf("\nCommon helpers:\n");
    printf("  bpf_map_lookup_elem()   - Map lookup\n");
    printf("  bpf_map_update_elem()   - Map update\n");
    printf("  bpf_probe_read()        - Safe kernel read\n");
    printf("  bpf_probe_read_user()   - Safe user read\n");
    printf("  bpf_ktime_get_ns()      - Current time\n");
    printf("  bpf_get_current_pid_tgid() - PID/TID\n");
    printf("  bpf_get_current_comm()  - Process name\n");
    printf("  bpf_get_current_uid_gid() - UID/GID\n");
    printf("  bpf_perf_event_output() - Send to userspace\n");
    printf("  bpf_ringbuf_output()    - Ring buffer output\n");
    printf("  bpf_trace_printk()      - Debug print\n");

    printf("\nNetworking helpers:\n");
    printf("  bpf_skb_load_bytes()    - Load packet data\n");
    printf("  bpf_skb_store_bytes()   - Modify packet\n");
    printf("  bpf_redirect()          - Redirect packet\n");
    printf("  bpf_xdp_adjust_head()   - Adjust XDP head\n");

    printf("\nHelper availability depends on program type\n");
}

// ============================================
// Program Types
// ============================================

void explain_program_types(void) {
    printf("\n=== eBPF Program Types ===\n\n");

    printf("Different program types for different hook points:\n");

    printf("\nTracing:\n");
    printf("  BPF_PROG_TYPE_KPROBE\n");
    printf("    - Hook any kernel function\n");
    printf("    - kprobe (entry) / kretprobe (return)\n");
    printf("\n");
    printf("  BPF_PROG_TYPE_TRACEPOINT\n");
    printf("    - Stable kernel tracepoints\n");
    printf("    - More stable API than kprobes\n");
    printf("\n");
    printf("  BPF_PROG_TYPE_RAW_TRACEPOINT\n");
    printf("    - Raw access to tracepoint data\n");
    printf("    - Lower overhead\n");
    printf("\n");
    printf("  BPF_PROG_TYPE_PERF_EVENT\n");
    printf("    - Hardware/software events\n");
    printf("    - Sampling, counting\n");

    printf("\nNetworking:\n");
    printf("  BPF_PROG_TYPE_XDP\n");
    printf("    - eXpress Data Path\n");
    printf("    - Earliest hook (before sk_buff)\n");
    printf("    - Ultra-fast packet processing\n");
    printf("\n");
    printf("  BPF_PROG_TYPE_SCHED_CLS\n");
    printf("    - Traffic control classifier\n");
    printf("    - TC ingress/egress\n");
    printf("\n");
    printf("  BPF_PROG_TYPE_SOCKET_FILTER\n");
    printf("    - Socket filtering\n");
    printf("    - Classic BPF compatible\n");

    printf("\nSecurity:\n");
    printf("  BPF_PROG_TYPE_LSM\n");
    printf("    - Linux Security Module hooks\n");
    printf("    - Custom security policies\n");

    printf("\nCgroup:\n");
    printf("  BPF_PROG_TYPE_CGROUP_SKB\n");
    printf("  BPF_PROG_TYPE_CGROUP_SOCK\n");
    printf("    - Per-cgroup networking\n");
}

void explain_xdp(void) {
    printf("\n=== XDP (eXpress Data Path) ===\n\n");

    printf("XDP runs at the earliest point in network stack:\n");
    printf("  NIC -> XDP -> Network Stack\n");

    printf("\nXDP actions:\n");
    printf("  XDP_PASS    - Continue to network stack\n");
    printf("  XDP_DROP    - Drop packet\n");
    printf("  XDP_TX      - Send back out same interface\n");
    printf("  XDP_REDIRECT - Forward to another interface\n");
    printf("  XDP_ABORTED - Error, drop with trace\n");

    printf("\nXDP modes:\n");
    printf("  Native (driver)  - Best performance\n");
    printf("  Offloaded        - Run on NIC (if supported)\n");
    printf("  Generic (SKB)    - Fallback, slower\n");

    printf("\nXDP use cases:\n");
    printf("  - DDoS mitigation (drop at line rate)\n");
    printf("  - Load balancing\n");
    printf("  - Packet forwarding\n");
    printf("  - Network monitoring\n");

    printf("\nExample XDP program:\n");
    printf("  SEC(\"xdp\")\n");
    printf("  int xdp_drop_all(struct xdp_md *ctx) {\n");
    printf("      return XDP_DROP;\n");
    printf("  }\n");
}

// ============================================
// CO-RE
// ============================================

void explain_core(void) {
    printf("\n=== CO-RE (Compile Once - Run Everywhere) ===\n\n");

    printf("Problem: Kernel structures change between versions\n");
    printf("Solution: CO-RE with BTF (BPF Type Format)\n");

    printf("\nBTF:\n");
    printf("  - Type information embedded in kernel\n");
    printf("  - Describes structs, unions, enums\n");
    printf("  - Enables relocations at load time\n");

    printf("\nCheck BTF support:\n");
    printf("  ls /sys/kernel/btf/vmlinux\n");
    printf("  bpftool btf dump file /sys/kernel/btf/vmlinux\n");

    printf("\nCO-RE workflow:\n");
    printf("  1. Compile with BTF (clang -g -target bpf)\n");
    printf("  2. libbpf reads BTF from compiled .o\n");
    printf("  3. At load time, adjust offsets based on running kernel\n");
    printf("  4. Works across kernel versions!\n");

    printf("\nCO-RE macros:\n");
    printf("  BPF_CORE_READ(src, field)\n");
    printf("  BPF_CORE_READ_STR_INTO(dst, src, field)\n");
    printf("  bpf_core_field_exists(field)\n");
    printf("  bpf_core_field_size(field)\n");

    printf("\nvmlinux.h:\n");
    printf("  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h\n");
    printf("  # Contains all kernel types - no need for kernel headers\n");
}

// ============================================
// eBPF Tools
// ============================================

void explain_bcc(void) {
    printf("\n=== BCC (BPF Compiler Collection) ===\n\n");

    printf("High-level framework for writing eBPF:\n");
    printf("  - Python/Lua frontend\n");
    printf("  - Compiles C code at runtime\n");
    printf("  - Many ready-to-use tools\n");

    printf("\nInstall:\n");
    printf("  apt install bpfcc-tools  # Ubuntu\n");
    printf("  dnf install bcc-tools    # Fedora\n");

    printf("\nPopular BCC tools:\n");
    printf("  execsnoop    - Trace new processes\n");
    printf("  opensnoop    - Trace file opens\n");
    printf("  biosnoop     - Block I/O tracing\n");
    printf("  tcpconnect   - TCP connection tracing\n");
    printf("  tcplife      - TCP session lifespans\n");
    printf("  funccount    - Count function calls\n");
    printf("  stackcount   - Count stack traces\n");
    printf("  profile      - CPU profiler\n");
    printf("  trace        - Dynamic function tracing\n");
    printf("  argdist      - Summarize function arguments\n");

    printf("\nExample usage:\n");
    printf("  execsnoop-bpfcc              # Trace all exec()\n");
    printf("  opensnoop-bpfcc -p 1234      # Trace opens for PID\n");
    printf("  biosnoop-bpfcc               # Block I/O latency\n");
    printf("  tcpconnect-bpfcc             # New TCP connections\n");
    printf("  funccount-bpfcc 'vfs_*'      # Count VFS calls\n");
}

void explain_bpftrace(void) {
    printf("\n=== bpftrace ===\n\n");

    printf("High-level tracing language (like awk for eBPF):\n");

    printf("\nInstall:\n");
    printf("  apt install bpftrace\n");

    printf("\nSyntax:\n");
    printf("  probe /filter/ { action }\n");

    printf("\nProbe types:\n");
    printf("  kprobe:function    - Kernel function entry\n");
    printf("  kretprobe:function - Kernel function return\n");
    printf("  uprobe:binary:func - Userspace function\n");
    printf("  tracepoint:cat:name - Tracepoint\n");
    printf("  usdt:binary:probe  - User static probe\n");
    printf("  profile:hz:99      - Sampling\n");
    printf("  interval:s:1       - Timer\n");
    printf("  BEGIN, END         - Start/end\n");

    printf("\nBuilt-in variables:\n");
    printf("  pid, tid, uid, comm, nsecs, cpu\n");
    printf("  arg0-argN, retval, func, probe\n");
    printf("  curtask, kstack, ustack\n");

    printf("\nExamples:\n");
    printf("  # Count syscalls by process\n");
    printf("  bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'\n");
    printf("\n");
    printf("  # Trace open() calls\n");
    printf("  bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf(\"%%s %%s\\\\n\", comm, str(args->filename)); }'\n");
    printf("\n");
    printf("  # Histogram of read sizes\n");
    printf("  bpftrace -e 'tracepoint:syscalls:sys_exit_read { @bytes = hist(args->ret); }'\n");
    printf("\n");
    printf("  # Profile CPU\n");
    printf("  bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'\n");
}

void explain_libbpf(void) {
    printf("\n=== libbpf ===\n\n");

    printf("C library for eBPF (recommended for production):\n");
    printf("  - CO-RE support\n");
    printf("  - Skeleton generation\n");
    printf("  - Stable API\n");

    printf("\nWorkflow:\n");
    printf("  1. Write eBPF program (.bpf.c)\n");
    printf("  2. Compile with clang\n");
    printf("  3. Generate skeleton\n");
    printf("  4. Write loader (.c)\n");
    printf("  5. Compile and run\n");

    printf("\nCompile eBPF:\n");
    printf("  clang -g -O2 -target bpf -c prog.bpf.c -o prog.bpf.o\n");

    printf("\nGenerate skeleton:\n");
    printf("  bpftool gen skeleton prog.bpf.o > prog.skel.h\n");

    printf("\nLoader code:\n");
    printf("  #include \"prog.skel.h\"\n");
    printf("\n");
    printf("  struct prog_bpf *skel;\n");
    printf("  skel = prog_bpf__open();\n");
    printf("  prog_bpf__load(skel);\n");
    printf("  prog_bpf__attach(skel);\n");
    printf("  // ... run ...\n");
    printf("  prog_bpf__destroy(skel);\n");
}

void explain_bpftool(void) {
    printf("\n=== bpftool ===\n\n");

    printf("Inspect and manage eBPF:\n");

    printf("\nList loaded programs:\n");
    printf("  bpftool prog list\n");
    printf("  bpftool prog show id 123\n");

    printf("\nDump program:\n");
    printf("  bpftool prog dump xlated id 123    # eBPF instructions\n");
    printf("  bpftool prog dump jited id 123     # Native code\n");

    printf("\nList maps:\n");
    printf("  bpftool map list\n");
    printf("  bpftool map dump id 456\n");

    printf("\nMap operations:\n");
    printf("  bpftool map lookup id 456 key 0x01 0x00 0x00 0x00\n");
    printf("  bpftool map update id 456 key 0x01 0x00 0x00 0x00 value 0x42\n");

    printf("\nBTF:\n");
    printf("  bpftool btf list\n");
    printf("  bpftool btf dump file /sys/kernel/btf/vmlinux\n");

    printf("\nFeature detection:\n");
    printf("  bpftool feature probe\n");
}

// ============================================
// Writing eBPF Programs
// ============================================

void show_ebpf_example(void) {
    printf("\n=== Example: Tracing execve ===\n\n");

    printf("execsnoop.bpf.c:\n");
    printf("  #include <vmlinux.h>\n");
    printf("  #include <bpf/bpf_helpers.h>\n");
    printf("  #include <bpf/bpf_core_read.h>\n");
    printf("\n");
    printf("  struct event {\n");
    printf("      u32 pid;\n");
    printf("      u32 ppid;\n");
    printf("      char comm[16];\n");
    printf("      char filename[256];\n");
    printf("  };\n");
    printf("\n");
    printf("  struct {\n");
    printf("      __uint(type, BPF_MAP_TYPE_RINGBUF);\n");
    printf("      __uint(max_entries, 256 * 1024);\n");
    printf("  } events SEC(\".maps\");\n");
    printf("\n");
    printf("  SEC(\"tracepoint/syscalls/sys_enter_execve\")\n");
    printf("  int trace_execve(struct trace_event_raw_sys_enter *ctx) {\n");
    printf("      struct event *e;\n");
    printf("      struct task_struct *task;\n");
    printf("\n");
    printf("      e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);\n");
    printf("      if (!e) return 0;\n");
    printf("\n");
    printf("      task = (struct task_struct *)bpf_get_current_task();\n");
    printf("\n");
    printf("      e->pid = bpf_get_current_pid_tgid() >> 32;\n");
    printf("      e->ppid = BPF_CORE_READ(task, real_parent, tgid);\n");
    printf("      bpf_get_current_comm(&e->comm, sizeof(e->comm));\n");
    printf("      bpf_probe_read_user_str(&e->filename, sizeof(e->filename),\n");
    printf("                              (void *)ctx->args[0]);\n");
    printf("\n");
    printf("      bpf_ringbuf_submit(e, 0);\n");
    printf("      return 0;\n");
    printf("  }\n");
    printf("\n");
    printf("  char LICENSE[] SEC(\"license\") = \"GPL\";\n");
}

void show_xdp_example(void) {
    printf("\n=== Example: XDP Packet Counter ===\n\n");

    printf("xdp_counter.bpf.c:\n");
    printf("  #include <linux/bpf.h>\n");
    printf("  #include <bpf/bpf_helpers.h>\n");
    printf("  #include <linux/if_ether.h>\n");
    printf("  #include <linux/ip.h>\n");
    printf("\n");
    printf("  struct {\n");
    printf("      __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\n");
    printf("      __uint(max_entries, 256);\n");
    printf("      __type(key, u32);\n");
    printf("      __type(value, u64);\n");
    printf("  } pkt_count SEC(\".maps\");\n");
    printf("\n");
    printf("  SEC(\"xdp\")\n");
    printf("  int xdp_count(struct xdp_md *ctx) {\n");
    printf("      void *data = (void *)(long)ctx->data;\n");
    printf("      void *data_end = (void *)(long)ctx->data_end;\n");
    printf("      struct ethhdr *eth = data;\n");
    printf("\n");
    printf("      if ((void *)(eth + 1) > data_end)\n");
    printf("          return XDP_PASS;\n");
    printf("\n");
    printf("      u32 key = eth->h_proto;\n");
    printf("      u64 *count = bpf_map_lookup_elem(&pkt_count, &key);\n");
    printf("      if (count)\n");
    printf("          (*count)++;\n");
    printf("\n");
    printf("      return XDP_PASS;\n");
    printf("  }\n");
    printf("\n");
    printf("  char LICENSE[] SEC(\"license\") = \"GPL\";\n");

    printf("\nAttach XDP:\n");
    printf("  ip link set dev eth0 xdp obj xdp_counter.o sec xdp\n");
    printf("  ip link set dev eth0 xdp off  # Detach\n");
}

// ============================================
// Use Cases
// ============================================

void explain_use_cases(void) {
    printf("\n=== eBPF Use Cases ===\n\n");

    printf("1. Observability:\n");
    printf("   - System-wide tracing (traces, spans)\n");
    printf("   - Application performance monitoring\n");
    printf("   - Infrastructure monitoring\n");
    printf("   - Tools: Pixie, Hubble, Cilium\n");

    printf("\n2. Networking:\n");
    printf("   - Load balancing (Katran, Cilium)\n");
    printf("   - Kubernetes networking (CNI)\n");
    printf("   - DDoS mitigation\n");
    printf("   - Service mesh (sidecar-less)\n");

    printf("\n3. Security:\n");
    printf("   - Runtime security (Falco, Tetragon)\n");
    printf("   - Network security policies\n");
    printf("   - Syscall filtering\n");
    printf("   - Threat detection\n");

    printf("\n4. Profiling:\n");
    printf("   - CPU profiling\n");
    printf("   - Memory allocation tracking\n");
    printf("   - Latency analysis\n");
    printf("   - Continuous profiling\n");

    printf("\nProduction eBPF projects:\n");
    printf("  Cilium     - Kubernetes networking/security\n");
    printf("  Falco      - Runtime security\n");
    printf("  Tetragon   - Security observability\n");
    printf("  Katran     - L4 load balancer (Facebook)\n");
    printf("  Pixie      - Kubernetes observability\n");
    printf("  bpftrace   - Tracing\n");
}

int main(void) {
    explain_ebpf();
    explain_verifier();
    explain_jit();
    explain_maps();
    explain_helper_functions();
    explain_program_types();
    explain_xdp();
    explain_core();

    explain_bcc();
    explain_bpftrace();
    explain_libbpf();
    explain_bpftool();

    show_ebpf_example();
    show_xdp_example();
    explain_use_cases();

    printf("\n=== Quick Reference ===\n\n");
    printf("  bpftrace -e 'probe { action }'  # One-liner tracing\n");
    printf("  execsnoop-bpfcc                 # Trace exec\n");
    printf("  opensnoop-bpfcc                 # Trace open\n");
    printf("  bpftool prog list               # List programs\n");
    printf("  bpftool map list                # List maps\n");

    return 0;
}
```

---

## Fichiers

```
ex21/
├── ebpf_intro.h
├── ebpf_overview.c
├── maps_helpers.c
├── program_types.c
├── tools.c
├── examples/
│   ├── execsnoop.bpf.c
│   ├── xdp_counter.bpf.c
│   └── Makefile
└── Makefile
```

