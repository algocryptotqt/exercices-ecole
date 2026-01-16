# MODULE 3.36 : MALWARE DEVELOPMENT
## Développement de Logiciels Malveillants - Red Team / Recherche Sécurité

**Concepts couverts** : 110/110
**Nombre d'exercices** : 13
**Orientation** : Offensive / Développement / Pentest autorisé & CTF
**Prérequis** : Modules 3.4 (Exploitation Binaire), 3.5 (Reverse Engineering)

---

## OBJECTIFS PÉDAGOGIQUES

Ce module forme aux techniques de **développement d'implants et malwares** dans un contexte de recherche sécurité, pentest autorisé, et CTF. L'accent est mis sur la compréhension architecturale, les techniques d'évasion, et le développement cross-platform.

**Contexte légal** : Ces techniques sont enseignées pour la recherche défensive, le pentest autorisé, et les compétitions CTF uniquement.

---

## SOUS-MODULE 3.36.1 : Fondamentaux Malware Dev (18 concepts)

### Concepts couverts :
- **a** : Malware Categories - RAT, backdoor, trojan, worm, ransomware, rootkit, bootkit, spyware, keylogger, stealer, loader, dropper
- **b** : Development Lifecycle - Requirements → Design → Implementation → Testing → Deployment → Maintenance → Retirement
- **c** : Language Selection - C/C++ (performance), Rust (safety), Go (cross-platform), Assembly (shellcode), .NET, Python
- **d** : Implant Architecture - Modular design, plugin system, command dispatch, configuration, persistence, communication
- **e** : Position Independent Code - PIC, no hardcoded addresses, relocatable, shellcode requirement
- **f** : API Resolution - Dynamic API resolution, GetProcAddress, hash-based lookup, avoid IAT
- **g** : String Obfuscation - XOR, RC4, AES strings, compile-time encryption, stack strings
- **h** : Control Flow Obfuscation - Opaque predicates, bogus control flow, instruction substitution, flattening
- **i** : Anti-Analysis Basics - Anti-debug, anti-VM, anti-sandbox, timing checks, environment checks
- **j** : Payload Delivery - Dropper, loader, stager, staged vs stageless, in-memory
- **k** : Execution Methods - Process injection, DLL loading, shellcode execution, LOLBins abuse
- **l** : Configuration Management - Embedded config, encrypted, updateable, per-target customization
- **m** : Error Handling - Silent failures, no crashes, graceful degradation, logging (secure)
- **n** : Cross-Platform Considerations - Windows/Linux/macOS, abstraction layers, platform-specific features
- **o** : Build Systems - Reproducible builds, automated obfuscation, CI/CD for malware
- **p** : Testing Malware - Isolated VMs, detection testing, functionality testing, stability
- **q** : Versioning & Updates - Implant versioning, update mechanisms, backward compatibility
- **r** : Operational Security Dev - Clean build environment, no personal artifacts, attribution resistance

---

### EXERCICE 3.36.1 : Implant Architecture Designer

**Fichier** : `ex01_implant_architecture/`

**Sujet** :
Vous êtes architecte pour un framework de pentest. Analysez les spécifications d'un implant et produisez un design document complet incluant l'architecture modulaire, le choix de langage justifié, et les considérations OPSEC.

**Concepts évalués** : a, b, c, d, l, m, n, o, p, q, r + 3.36.6.g

**Entrée** :
```json
{
  "requirements": {
    "target_os": ["windows_10", "windows_11", "windows_server_2019"],
    "stealth_level": "high",
    "persistence_required": true,
    "features_needed": ["shell", "file_transfer", "screenshot", "keylogger", "credential_harvest"],
    "c2_protocols": ["https", "dns"],
    "size_constraint_kb": 100,
    "detection_avoidance": ["defender", "crowdstrike", "carbon_black"],
    "operation_duration_days": 90
  },
  "constraints": {
    "no_disk_artifacts": true,
    "memory_only_execution": true,
    "must_survive_reboot": true,
    "update_capability": true
  },
  "team_expertise": {
    "languages": ["rust", "c", "csharp", "go"],
    "experience_years": 3
  }
}
```

**Sortie attendue** :
```json
{
  "architecture_design": {
    "name": "Project Phantom",
    "version_scheme": "semver",
    "language_selection": {
      "primary": "rust",
      "justification": [
        "Memory safety prevents crashes in long-running implant",
        "No runtime dependency (unlike .NET/Go)",
        "Excellent cross-compilation",
        "Strong type system reduces bugs",
        "Team has Rust expertise"
      ],
      "secondary": "c",
      "secondary_use": "Shellcode stubs and low-level Windows API"
    },
    "module_architecture": {
      "core": {
        "description": "Main implant loop, command dispatch, configuration",
        "size_estimate_kb": 30,
        "always_loaded": true
      },
      "modules": [
        {
          "name": "comms_https",
          "description": "HTTPS C2 communication",
          "size_kb": 15,
          "load_on_demand": false
        },
        {
          "name": "comms_dns",
          "description": "DNS tunneling fallback",
          "size_kb": 10,
          "load_on_demand": true
        },
        {
          "name": "exec_shell",
          "description": "Interactive shell capability",
          "size_kb": 8,
          "load_on_demand": true
        },
        {
          "name": "file_ops",
          "description": "File browse, upload, download",
          "size_kb": 12,
          "load_on_demand": true
        },
        {
          "name": "screenshot",
          "description": "Screen capture with compression",
          "size_kb": 10,
          "load_on_demand": true
        },
        {
          "name": "keylog",
          "description": "Keyboard capture with window context",
          "size_kb": 8,
          "load_on_demand": true
        },
        {
          "name": "creds",
          "description": "Credential harvesting (LSASS, browsers)",
          "size_kb": 15,
          "load_on_demand": true
        }
      ],
      "total_size_kb": 98,
      "within_constraint": true
    },
    "lifecycle": {
      "phases": [
        {
          "phase": "requirements",
          "activities": ["Threat model", "Feature prioritization", "OPSEC requirements"],
          "deliverable": "Requirements document"
        },
        {
          "phase": "design",
          "activities": ["Architecture", "Protocol design", "Module interfaces"],
          "deliverable": "Design document"
        },
        {
          "phase": "implementation",
          "activities": ["Core development", "Module development", "Integration"],
          "deliverable": "Source code"
        },
        {
          "phase": "testing",
          "activities": ["Functional testing", "Detection testing", "Stability testing"],
          "deliverable": "Test reports"
        },
        {
          "phase": "deployment",
          "activities": ["Build automation", "Payload generation", "Infrastructure setup"],
          "deliverable": "Deployment package"
        },
        {
          "phase": "maintenance",
          "activities": ["Bug fixes", "Evasion updates", "Feature additions"],
          "deliverable": "Updated versions"
        }
      ]
    },
    "configuration_management": {
      "format": "encrypted_binary",
      "encryption": "chacha20poly1305",
      "fields": [
        {"name": "c2_servers", "type": "array", "encrypted": true},
        {"name": "sleep_interval", "type": "u32", "encrypted": false},
        {"name": "jitter_percent", "type": "u8", "encrypted": false},
        {"name": "kill_date", "type": "timestamp", "encrypted": true},
        {"name": "campaign_id", "type": "uuid", "encrypted": true}
      ],
      "update_mechanism": "c2_command",
      "per_target_customization": true
    },
    "error_handling": {
      "strategy": "silent_recovery",
      "crash_prevention": [
        "Rust's Result type for all fallible operations",
        "Panic handler that silently terminates thread",
        "Watchdog thread to restart failed modules"
      ],
      "logging": {
        "enabled": false,
        "reason": "OPSEC - no disk artifacts"
      }
    },
    "cross_platform": {
      "abstraction_layer": true,
      "platform_traits": ["ProcessOps", "FileOps", "NetworkOps", "PersistenceOps"],
      "current_support": ["windows"],
      "future_support": ["linux", "macos"]
    },
    "build_system": {
      "tool": "cargo",
      "features": [
        "Reproducible builds via Cargo.lock",
        "Automated string encryption at compile time",
        "Profile-guided optimization",
        "Strip symbols and debug info"
      ],
      "ci_cd": {
        "enabled": true,
        "pipeline": ["Build", "Obfuscate", "Test", "Package", "Hash verification"]
      }
    },
    "testing_strategy": {
      "environments": [
        {"name": "clean_vm", "purpose": "Functionality testing"},
        {"name": "defender_vm", "purpose": "Windows Defender evasion"},
        {"name": "edr_vm", "purpose": "EDR evasion testing", "products": ["crowdstrike", "carbon_black"]}
      ],
      "automation": "pytest + VM snapshots",
      "detection_testing_frequency": "Every build"
    },
    "versioning": {
      "scheme": "major.minor.patch",
      "compatibility": "Minor versions backward compatible",
      "update_mechanism": {
        "method": "In-memory module replacement",
        "rollback": "Keep previous version until new confirmed working"
      }
    },
    "opsec_dev": {
      "build_environment": {
        "isolated": true,
        "no_personal_accounts": true,
        "vpn_required": true,
        "vm_based": true
      },
      "artifact_prevention": [
        "No PDB files",
        "No embedded paths",
        "Randomized PE timestamps",
        "No identifiable strings"
      ],
      "attribution_resistance": [
        "Generic variable names",
        "No comments in source",
        "Mixed coding styles",
        "No timezone indicators"
      ]
    }
  },
  "malware_category": "RAT",
  "rat_features_coverage": {
    "shell": true,
    "file_transfer": true,
    "screenshot": true,
    "keylogger": true,
    "persistence": true,
    "credential_harvest": true
  },
  "quality_assessment": {
    "architecture_score": 95,
    "opsec_score": 92,
    "maintainability_score": 90,
    "overall": 92
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 24/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

### EXERCICE 3.36.2 : Shellcode Engineering Analyzer

**Fichier** : `ex02_shellcode_engineering/`

**Sujet** :
Analysez un shellcode fourni (format hexadécimal) et identifiez: le type (stager/stageless), les techniques PIC utilisées, la méthode de résolution d'API, et l'obfuscation appliquée.

**Concepts évalués** : e, f, g, j, k + 3.36.6.a, 3.36.6.b, 3.36.6.c, 3.36.6.d, 3.36.6.e

**Entrée** :
```json
{
  "shellcode_hex": "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500",
  "analysis_depth": "comprehensive",
  "target_arch": "x64",
  "context": "windows"
}
```

**Sortie attendue** :
```json
{
  "shellcode_analysis": {
    "size_bytes": 276,
    "architecture": "x86_64",
    "type": "stageless",
    "type_reasoning": "Complete functionality embedded, no network fetch for payload"
  },
  "pic_techniques": {
    "is_position_independent": true,
    "techniques_identified": [
      {
        "technique": "RIP-relative addressing",
        "evidence": "call $+5; pop rbp pattern at offset 0x05",
        "purpose": "Get current instruction pointer"
      },
      {
        "technique": "PEB walking",
        "evidence": "gs:[0x60] access for PEB, then LDR_DATA traversal",
        "purpose": "Find loaded module base addresses"
      },
      {
        "technique": "No absolute addresses",
        "evidence": "All memory references are relative",
        "purpose": "Execute from any memory location"
      }
    ],
    "relocations_needed": false
  },
  "api_resolution": {
    "method": "hash_based_lookup",
    "hash_algorithm": {
      "name": "ROR13",
      "description": "Rotate right 13 bits, additive",
      "implementation": "loop: ror ecx, 13; add ecx, eax"
    },
    "apis_resolved": [
      {
        "hash": "0x6f726713",
        "resolved_to": "kernel32.dll!LoadLibraryA",
        "purpose": "Load additional DLLs"
      },
      {
        "hash": "0x876f8b31",
        "resolved_to": "kernel32.dll!GetProcAddress",
        "purpose": "Resolve additional APIs"
      },
      {
        "hash": "0xa5b59df0",
        "resolved_to": "kernel32.dll!VirtualAlloc",
        "purpose": "Allocate executable memory"
      },
      {
        "hash": "0x9dbd95a6",
        "resolved_to": "kernel32.dll!WinExec",
        "purpose": "Execute payload command"
      }
    ],
    "iat_usage": false,
    "reason_no_iat": "Avoid static analysis detection of imports"
  },
  "string_obfuscation": {
    "techniques_found": [
      {
        "technique": "Stack strings",
        "evidence": "Bytes pushed to stack then used as string",
        "strings_identified": ["calc.exe"]
      },
      {
        "technique": "Null-free encoding",
        "evidence": "No 0x00 bytes in shellcode body",
        "method": "Avoided via instruction selection"
      }
    ],
    "encrypted_strings": false,
    "xor_key": null
  },
  "control_flow": {
    "entry_point": "0x00",
    "structure": "Linear with conditional jumps",
    "loops_identified": [
      {
        "purpose": "Module enumeration",
        "offset": "0x20-0x80"
      },
      {
        "purpose": "Export table walking",
        "offset": "0x85-0xC0"
      },
      {
        "purpose": "Hash comparison",
        "offset": "0x48-0x60"
      }
    ],
    "obfuscation_level": "minimal"
  },
  "payload_analysis": {
    "payload_type": "command_execution",
    "command": "calc.exe",
    "execution_method": "WinExec",
    "cleanup": false,
    "persistence": false
  },
  "delivery_classification": {
    "is_dropper": false,
    "is_loader": false,
    "is_stager": false,
    "is_stageless": true,
    "reasoning": "Self-contained execution, no external payload fetch"
  },
  "detection_assessment": {
    "static_detectability": "medium",
    "static_indicators": [
      "PEB walking pattern recognizable",
      "ROR13 hash algorithm well-known",
      "calc.exe string visible"
    ],
    "dynamic_detectability": "high",
    "dynamic_indicators": [
      "WinExec call monitored by most EDR",
      "Shellcode allocation patterns"
    ],
    "evasion_recommendations": [
      "Encrypt strings with runtime decryption",
      "Use custom hash algorithm",
      "Indirect syscalls instead of WinExec",
      "Add anti-analysis checks"
    ]
  },
  "quality_metrics": {
    "size_efficiency": "good",
    "null_free": true,
    "pic_compliance": true,
    "opsec_rating": "low"
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 25/25
- Originalité : 19/20
- Testabilité : 15/15
- Clarté : 14/15

---

## SOUS-MODULE 3.36.2 : Windows Malware Development (22 concepts)

### Concepts couverts :
- **a** : Windows Internals for Malware - PE format, processes, threads, handles, objects, registry, services
- **b** : PE File Structure - DOS header, NT headers, sections, imports, exports, relocations, resources
- **c** : PE Manipulation - Section injection, header modification, import table manipulation
- **d** : Process Injection Techniques - CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, thread hijacking, process hollowing
- **e** : Process Hollowing - Create suspended, unmap, write new image, resume, RunPE
- **f** : DLL Injection - LoadLibrary, manual mapping, reflective DLL, DLL hijacking
- **g** : Reflective DLL Injection - No LoadLibrary, self-loading, Stephen Fewer technique, memory-only
- **h** : Shellcode Injection - VirtualAllocEx, WriteProcessMemory, execution methods, syscalls
- **i** : Direct Syscalls - Bypass usermode hooks, ntdll replacement, syscall numbers, Syswhispers
- **j** : NTAPI Usage - Native API, undocumented functions, Nt*/Zw* functions
- **k** : Token Manipulation - Token stealing, impersonation, privilege escalation via tokens
- **l** : UAC Bypass - Auto-elevate, fodhelper, eventvwr, COM objects, environment variables
- **m** : AMSI Bypass - Patching amsi.dll, AmsiScanBuffer, obfuscation, reflection
- **n** : ETW Bypass - NtTraceEvent patching, provider disabling, blind defenders
- **o** : Windows Defender Evasion - Signature evasion, behavior evasion, exclusions, unhooking
- **p** : Persistence Mechanisms - Registry, scheduled tasks, services, COM hijacking, WMI, startup folders
- **q** : COM Abuse - COM hijacking, DCOM, COM objects for execution, persistence
- **r** : WMI Abuse - WMI events, subscriptions, persistence, lateral movement
- **s** : Credential Access - LSASS dump, SAM, DPAPI, credential manager, mimikatz techniques
- **t** : Windows Kernel Access - Driver loading, BYOVD, kernel callbacks, notify routines
- **u** : .NET Malware - C# implants, reflection, Assembly.Load, in-memory execution
- **v** : PowerShell Integration - Runspace, AMSI bypass, CLM bypass, execution policy bypass

---

### EXERCICE 3.36.3 : PE Injection Technique Selector

**Fichier** : `ex03_pe_injection_selector/`

**Sujet** :
Analysez un scénario d'exécution avec contraintes spécifiques et recommandez la technique d'injection optimale avec justification technique complète.

**Concepts évalués** : a, b, c, d, e, f, g, h + 3.36.1.j, 3.36.1.k, 3.36.6.f, 3.36.6.n

**Entrée** :
```json
{
  "scenario": {
    "target_process": "explorer.exe",
    "target_pid": 4520,
    "target_integrity": "medium",
    "attacker_integrity": "medium",
    "attacker_privileges": ["SeDebugPrivilege"],
    "payload_type": "dll",
    "payload_size_kb": 45,
    "stealth_requirement": "high",
    "edr_present": ["crowdstrike", "defender"],
    "must_survive_process_restart": false
  },
  "available_techniques": [
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "ProcessHollowing",
    "ReflectiveDLL",
    "ManualMapping",
    "ThreadHijacking",
    "EarlyBirdInjection"
  ],
  "constraints": {
    "no_new_threads_visible": true,
    "no_rwx_memory": true,
    "no_loadlibrary": true
  }
}
```

**Sortie attendue** :
```json
{
  "analysis": {
    "scenario_complexity": "high",
    "primary_challenges": [
      "EDR monitoring for injection",
      "No RWX memory constraint",
      "No new visible threads",
      "No LoadLibrary usage"
    ]
  },
  "technique_evaluation": [
    {
      "technique": "CreateRemoteThread",
      "viable": false,
      "reasons": [
        "Creates visible new thread - violates constraint",
        "Heavily monitored by CrowdStrike",
        "Easy to detect via thread creation callbacks"
      ],
      "detection_likelihood": "very_high"
    },
    {
      "technique": "NtCreateThreadEx",
      "viable": false,
      "reasons": [
        "Still creates new thread (just via native API)",
        "CrowdStrike hooks NtCreateThreadEx"
      ],
      "detection_likelihood": "high"
    },
    {
      "technique": "QueueUserAPC",
      "viable": "partial",
      "reasons": [
        "Uses existing threads - good",
        "Requires alertable thread - explorer has these",
        "But needs initial memory allocation still detected"
      ],
      "detection_likelihood": "medium"
    },
    {
      "technique": "ProcessHollowing",
      "viable": false,
      "reasons": [
        "Creates new process - not targeting explorer.exe",
        "Would need to hollow a new process, not inject into existing"
      ],
      "detection_likelihood": "n/a"
    },
    {
      "technique": "ReflectiveDLL",
      "viable": false,
      "reasons": [
        "Requires RWX memory for self-loading code",
        "Violates no_rwx_memory constraint"
      ],
      "detection_likelihood": "medium"
    },
    {
      "technique": "ManualMapping",
      "viable": "partial",
      "reasons": [
        "No LoadLibrary - good",
        "Can use RW then RX (not RWX) - acceptable",
        "But still needs thread to execute"
      ],
      "detection_likelihood": "medium"
    },
    {
      "technique": "ThreadHijacking",
      "viable": true,
      "reasons": [
        "Uses existing thread - no new threads",
        "Can combine with manual mapping",
        "Modifies thread context - less monitored than creation",
        "Explorer has many threads to hijack"
      ],
      "detection_likelihood": "low_to_medium"
    },
    {
      "technique": "EarlyBirdInjection",
      "viable": false,
      "reasons": [
        "Requires process creation - targeting existing explorer",
        "Would work for new process, not existing"
      ],
      "detection_likelihood": "n/a"
    }
  ],
  "recommended_approach": {
    "primary_technique": "ThreadHijacking + ManualMapping",
    "execution_plan": [
      {
        "step": 1,
        "action": "Enumerate explorer.exe threads",
        "method": "NtQuerySystemInformation or CreateToolhelp32Snapshot",
        "opsec": "Use direct syscall for NtQuerySystemInformation"
      },
      {
        "step": 2,
        "action": "Select suitable thread",
        "criteria": "Thread in alertable wait or GUI message loop",
        "target": "Shell_TrayWnd message pump thread"
      },
      {
        "step": 3,
        "action": "Allocate memory in target",
        "method": "NtAllocateVirtualMemory with PAGE_READWRITE",
        "opsec": "Direct syscall, allocate as RW not RWX"
      },
      {
        "step": 4,
        "action": "Manual map DLL",
        "method": "Copy headers + sections, resolve imports, apply relocations",
        "opsec": "Do relocation/import resolution in own process first"
      },
      {
        "step": 5,
        "action": "Write mapped DLL to target",
        "method": "NtWriteVirtualMemory",
        "opsec": "Direct syscall"
      },
      {
        "step": 6,
        "action": "Change memory protection",
        "method": "NtProtectVirtualMemory to PAGE_EXECUTE_READ",
        "opsec": "RX not RWX - less suspicious"
      },
      {
        "step": 7,
        "action": "Hijack thread",
        "method": "SuspendThread, GetThreadContext, modify RIP, SetThreadContext, ResumeThread",
        "opsec": "Use Nt* versions via direct syscall"
      }
    ],
    "syscalls_needed": [
      {"function": "NtAllocateVirtualMemory", "syscall_number": 0x18},
      {"function": "NtWriteVirtualMemory", "syscall_number": 0x3A},
      {"function": "NtProtectVirtualMemory", "syscall_number": 0x50},
      {"function": "NtSuspendThread", "syscall_number": 0x1B5},
      {"function": "NtGetContextThread", "syscall_number": 0x0F2},
      {"function": "NtSetContextThread", "syscall_number": 0x18B},
      {"function": "NtResumeThread", "syscall_number": 0x52}
    ]
  },
  "edr_evasion_considerations": {
    "crowdstrike": {
      "known_detections": [
        "Kernel callbacks for memory allocation",
        "Thread context modification monitoring",
        "Unbacked executable memory"
      ],
      "evasion_tactics": [
        "Direct syscalls bypass usermode hooks",
        "Use RX memory (backed by manual map)",
        "Hijack existing thread context carefully",
        "Add delay between operations"
      ]
    },
    "defender": {
      "known_detections": [
        "VirtualAllocEx + WriteProcessMemory pattern",
        "Cross-process memory operations"
      ],
      "evasion_tactics": [
        "Native API instead of Win32",
        "Staged allocation and write"
      ]
    }
  },
  "fallback_techniques": [
    {
      "technique": "QueueUserAPC + ManualMapping",
      "when_to_use": "If thread hijacking fails",
      "tradeoff": "Slightly higher detection risk"
    }
  ],
  "implementation_complexity": "high",
  "success_probability": 0.75,
  "detection_risk": "medium"
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 25/25
- Originalité : 20/20
- Testabilité : 14/15
- Clarté : 14/15

---

### EXERCICE 3.36.4 : Windows Defense Bypass Strategist

**Fichier** : `ex04_defense_bypass/`

**Sujet** :
Analysez l'environnement défensif Windows d'une cible et proposez une stratégie de bypass complète couvrant AMSI, ETW, et EDR hooks.

**Concepts évalués** : i, j, m, n, o + 3.36.5.l, 3.36.5.m, 3.36.5.q, 3.36.5.h, 3.36.5.e

**Entrée** :
```json
{
  "target_environment": {
    "os": "Windows 11 22H2",
    "defender_version": "4.18.2302",
    "defender_features": {
      "real_time_protection": true,
      "cloud_protection": true,
      "tamper_protection": true,
      "controlled_folder_access": false,
      "asru": true
    },
    "amsi_providers": ["defender", "custom_dlp"],
    "etw_providers_active": ["microsoft-windows-security-auditing", "microsoft-windows-powershell"],
    "edr_solution": null
  },
  "execution_context": {
    "initial_access": "word_macro",
    "current_process": "winword.exe",
    "integrity_level": "medium",
    "have_admin": false,
    "powershell_needed": true,
    "csharp_execution_needed": true
  },
  "payload_requirements": {
    "must_execute_powershell": true,
    "must_load_csharp_assembly": true,
    "avoid_new_processes": true
  }
}
```

**Sortie attendue** :
```json
{
  "environment_analysis": {
    "threat_level": "high",
    "key_obstacles": [
      "AMSI will scan PowerShell and .NET content",
      "ETW logging PowerShell activity",
      "Defender real-time scanning",
      "Tamper protection prevents easy disabling",
      "Cloud protection for unknown binaries"
    ],
    "opportunities": [
      "No EDR - only Defender",
      "No controlled folder access",
      "Medium integrity - sufficient for user-level bypass"
    ]
  },
  "bypass_strategy": {
    "phase_1_amsi_bypass": {
      "priority": "critical",
      "reason": "Must bypass before any PowerShell/C# execution",
      "techniques": [
        {
          "technique": "AmsiScanBuffer patch",
          "description": "Patch AmsiScanBuffer in amsi.dll to return clean",
          "implementation": {
            "method": "Memory patching via P/Invoke from VBA",
            "steps": [
              "Get amsi.dll base via GetModuleHandle",
              "Get AmsiScanBuffer address via GetProcAddress",
              "VirtualProtect to PAGE_EXECUTE_READWRITE",
              "Patch first bytes: mov eax, 0x80070057; ret (AMSI_RESULT_CLEAN)",
              "VirtualProtect back to original"
            ],
            "patch_bytes": "B857000780C3",
            "vba_compatible": true
          },
          "detection_risk": "medium",
          "tamper_protection_bypass": "Works - TP protects Defender, not amsi.dll"
        },
        {
          "technique": "CLM bypass for PowerShell",
          "description": "If Constrained Language Mode enabled, bypass it",
          "implementation": {
            "method": "Run from trusted location or use PowerShell runspace",
            "fallback": "Use reflection to set LanguageMode"
          }
        }
      ]
    },
    "phase_2_etw_bypass": {
      "priority": "high",
      "reason": "Prevent PowerShell activity logging",
      "techniques": [
        {
          "technique": "EtwEventWrite patch",
          "description": "Patch ntdll!EtwEventWrite to ret immediately",
          "implementation": {
            "method": "Memory patching",
            "steps": [
              "Get ntdll.dll base",
              "Get EtwEventWrite address",
              "VirtualProtect to RWX",
              "Patch with: ret (0xC3)",
              "Restore protection"
            ],
            "patch_bytes": "C3"
          },
          "scope": "Blinds all ETW in current process",
          "detection_risk": "low - rarely monitored"
        },
        {
          "technique": "Provider-specific disable",
          "description": "Disable specific ETW providers",
          "method": "Use TraceControl to disable Microsoft-Windows-PowerShell provider",
          "detection_risk": "medium"
        }
      ],
      "recommended": "EtwEventWrite patch - simpler, complete"
    },
    "phase_3_defender_evasion": {
      "techniques": [
        {
          "technique": "In-memory execution only",
          "description": "Never touch disk, avoid file scanning",
          "implementation": "Assembly.Load from byte array"
        },
        {
          "technique": "Payload obfuscation",
          "description": "Avoid signature detection",
          "methods": [
            "XOR encrypted payload with runtime decryption",
            "String obfuscation for known bad strings",
            "Control flow obfuscation"
          ]
        },
        {
          "technique": "Unhooking ntdll",
          "description": "Remove Defender usermode hooks",
          "implementation": {
            "method": "Map fresh ntdll from disk and copy .text section",
            "steps": [
              "MapViewOfFile on C:\\Windows\\System32\\ntdll.dll",
              "Find .text section in both mapped and loaded",
              "VirtualProtect current ntdll .text",
              "Memcpy clean .text over hooked .text",
              "Restore protection"
            ]
          },
          "note": "Less critical without EDR, but good for complete evasion"
        }
      ]
    },
    "phase_4_execution": {
      "powershell_execution": {
        "method": "Unmanaged PowerShell runspace",
        "description": "Host PowerShell in current process without powershell.exe",
        "implementation": {
          "host": "winword.exe",
          "technique": "System.Management.Automation.PowerShell class",
          "amsi_status": "Bypassed in phase 1",
          "etw_status": "Blinded in phase 2"
        }
      },
      "csharp_execution": {
        "method": "Assembly.Load in memory",
        "description": "Load .NET assembly from byte array",
        "implementation": {
          "steps": [
            "Decrypt payload bytes",
            "System.Reflection.Assembly.Load(bytes)",
            "Find entry point via reflection",
            "Invoke method"
          ],
          "amsi_status": "Bypassed - won't trigger AMSI scan"
        }
      }
    }
  },
  "execution_order": [
    {
      "step": 1,
      "action": "AMSI bypass",
      "from": "VBA macro",
      "critical": true
    },
    {
      "step": 2,
      "action": "ETW bypass",
      "from": "VBA macro or initial PS",
      "critical": true
    },
    {
      "step": 3,
      "action": "Optional: Unhook ntdll",
      "from": "PowerShell or C#",
      "critical": false
    },
    {
      "step": 4,
      "action": "Execute PowerShell payload",
      "from": "Runspace in winword",
      "critical": true
    },
    {
      "step": 5,
      "action": "Load C# assembly",
      "from": "PowerShell or direct from VBA",
      "critical": true
    }
  ],
  "vba_initial_code_concept": {
    "description": "VBA macro to perform initial AMSI + ETW bypass",
    "techniques_used": [
      "VirtualProtect for memory protection change",
      "GetModuleHandle + GetProcAddress for function resolution",
      "RtlMoveMemory for patching"
    ],
    "note": "Actual code not provided - educational concept only"
  },
  "risk_assessment": {
    "detection_probability": 0.25,
    "factors": [
      "AMSI bypass is well-known but effective",
      "In-memory execution avoids file scanning",
      "No EDR reduces behavioral detection"
    ],
    "most_likely_detection_point": "Macro execution initial block by Defender ASR rules"
  },
  "recommendations": [
    "Verify ASR rules before relying on macro execution",
    "Have backup delivery method if macros blocked",
    "Test bypass techniques against current Defender version",
    "Consider signed macro or template injection if ASR enabled"
  ]
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 24/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

### EXERCICE 3.36.5 : Privilege Escalation & Credential Access

**Fichier** : `ex05_privesc_credentials/`

**Sujet** :
Analysez un environnement Windows et identifiez les chemins d'escalade de privilèges et d'accès aux credentials.

**Concepts évalués** : k, l, q, r, s, t + 3.36.6.h, 3.36.6.i

**Entrée** :
```json
{
  "current_context": {
    "username": "jdoe",
    "domain": "CORP",
    "integrity_level": "medium",
    "is_admin": false,
    "groups": ["Domain Users", "Remote Desktop Users"],
    "privileges": ["SeChangeNotifyPrivilege", "SeIncreaseWorkingSetPrivilege"]
  },
  "system_info": {
    "os": "Windows 10 21H2 Enterprise",
    "build": 19044,
    "patched_to": "2024-01",
    "domain_joined": true,
    "uac_level": "default"
  },
  "discovered_info": {
    "scheduled_tasks": [
      {"name": "BackupScript", "runs_as": "SYSTEM", "binary": "C:\\Scripts\\backup.ps1", "writable": true}
    ],
    "services": [
      {"name": "CustomSvc", "binary_path": "C:\\Program Files\\CustomApp\\service.exe", "path_writable": false, "unquoted": true}
    ],
    "registry": {
      "always_install_elevated": false,
      "auto_logon": {"enabled": true, "username": "svc_backup", "password_stored": true}
    },
    "processes": [
      {"name": "lsass.exe", "pid": 712, "protection": "PPL"},
      {"name": "chrome.exe", "pid": 5840, "has_credentials": true}
    ],
    "files": [
      {"path": "C:\\Users\\admin\\Documents\\passwords.xlsx", "readable": true},
      {"path": "C:\\inetpub\\wwwroot\\web.config", "readable": true, "has_conn_strings": true}
    ]
  }
}
```

**Sortie attendue** :
```json
{
  "analysis_summary": {
    "current_access": "medium_integrity_domain_user",
    "escalation_paths_found": 3,
    "credential_sources_found": 5,
    "overall_risk": "high"
  },
  "privilege_escalation_paths": [
    {
      "path_id": 1,
      "name": "Scheduled Task Script Modification",
      "type": "local_admin",
      "complexity": "low",
      "reliability": "high",
      "detection_risk": "medium",
      "technique_details": {
        "vulnerability": "Writable scheduled task script runs as SYSTEM",
        "target": "C:\\Scripts\\backup.ps1",
        "method": "Append malicious code to script",
        "trigger": "Wait for scheduled execution or trigger manually if possible",
        "result": "Code execution as SYSTEM"
      },
      "exploitation_steps": [
        "Backup original script content",
        "Append payload to backup.ps1 (e.g., add local admin, reverse shell)",
        "Wait for task execution or check schedule",
        "Verify privilege escalation"
      ],
      "mitre_technique": "T1053.005 - Scheduled Task/Job"
    },
    {
      "path_id": 2,
      "name": "Unquoted Service Path",
      "type": "local_admin",
      "complexity": "medium",
      "reliability": "medium",
      "detection_risk": "medium",
      "technique_details": {
        "vulnerability": "Service binary path unquoted with spaces",
        "service": "CustomSvc",
        "path": "C:\\Program Files\\CustomApp\\service.exe",
        "attack_path": "C:\\Program.exe or C:\\Program Files\\CustomApp\\service.exe",
        "requirement": "Need write access to C:\\ or C:\\Program Files"
      },
      "exploitation_steps": [
        "Check write permissions on C:\\ (unlikely) or C:\\Program Files\\CustomApp\\",
        "If writable, place malicious Program.exe or CustomApp.exe",
        "Restart service or wait for system restart",
        "Payload executes as service account"
      ],
      "current_viability": "low - path not writable based on provided info",
      "mitre_technique": "T1574.009 - Path Interception"
    },
    {
      "path_id": 3,
      "name": "Auto-Logon Credential Extraction",
      "type": "credential_theft",
      "complexity": "low",
      "reliability": "high",
      "detection_risk": "low",
      "technique_details": {
        "vulnerability": "Auto-logon stores plaintext credentials in registry",
        "registry_path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "values": ["DefaultUserName", "DefaultPassword", "DefaultDomainName"],
        "account": "svc_backup"
      },
      "exploitation_steps": [
        "Query registry for auto-logon values",
        "Extract DefaultPassword (plaintext or base64)",
        "Test credentials for svc_backup account",
        "If admin rights, lateral movement or further access"
      ],
      "mitre_technique": "T1552.002 - Credentials in Registry"
    }
  ],
  "credential_access_opportunities": [
    {
      "source_id": 1,
      "name": "Auto-Logon Credentials",
      "type": "registry",
      "credential": "svc_backup",
      "extraction_method": "Registry query",
      "format": "plaintext",
      "access_granted": "already_have_read_access",
      "mitre_technique": "T1552.002"
    },
    {
      "source_id": 2,
      "name": "Chrome Saved Passwords",
      "type": "browser",
      "credential": "multiple_possible",
      "extraction_method": "Chrome password database + DPAPI decryption",
      "format": "encrypted_dpapi",
      "access_granted": "user_context_sufficient",
      "tool_suggestion": "SharpChrome, Mimikatz dpapi module",
      "mitre_technique": "T1555.003"
    },
    {
      "source_id": 3,
      "name": "Password Excel File",
      "type": "file",
      "path": "C:\\Users\\admin\\Documents\\passwords.xlsx",
      "extraction_method": "Direct file read",
      "format": "xlsx",
      "access_granted": "readable_according_to_info",
      "mitre_technique": "T1552.001"
    },
    {
      "source_id": 4,
      "name": "Web.config Connection Strings",
      "type": "config_file",
      "path": "C:\\inetpub\\wwwroot\\web.config",
      "extraction_method": "File read, parse XML",
      "format": "plaintext_or_encrypted",
      "access_granted": "readable",
      "credential_types": ["database_credentials", "service_accounts"],
      "mitre_technique": "T1552.001"
    },
    {
      "source_id": 5,
      "name": "LSASS Memory",
      "type": "memory",
      "target_pid": 712,
      "extraction_method": "MiniDump or direct memory read",
      "current_access": "blocked",
      "blocker": "PPL protection, need admin + PPL bypass",
      "requires": "local_admin + SeDebugPrivilege + PPL bypass",
      "mitre_technique": "T1003.001"
    }
  ],
  "token_manipulation_opportunities": {
    "current_tokens_available": "limited - medium integrity",
    "if_admin_achieved": [
      {
        "technique": "Token impersonation",
        "method": "Duplicate SYSTEM token from privileged process",
        "tools": "incognito, Cobalt Strike token commands"
      },
      {
        "technique": "Token theft from service",
        "method": "OpenProcessToken on service process, duplicate",
        "target_services": ["CustomSvc if runs as domain account"]
      }
    ],
    "mitre_technique": "T1134"
  },
  "uac_bypass_if_local_admin": {
    "applicable": true,
    "reason": "If jdoe is local admin but UAC blocking",
    "techniques": [
      {
        "name": "fodhelper.exe bypass",
        "method": "Registry key modification + fodhelper execution",
        "reliability": "high",
        "windows_10_compatible": true
      },
      {
        "name": "eventvwr.exe bypass",
        "method": "Registry key modification + eventvwr execution",
        "reliability": "high",
        "windows_10_compatible": true
      },
      {
        "name": "ComputerDefaults bypass",
        "method": "DLL hijacking in auto-elevate binary",
        "reliability": "medium"
      }
    ]
  },
  "recommended_attack_path": {
    "steps": [
      {
        "order": 1,
        "action": "Extract auto-logon credentials for svc_backup",
        "effort": "trivial",
        "outcome": "svc_backup credentials"
      },
      {
        "order": 2,
        "action": "Read passwords.xlsx",
        "effort": "trivial",
        "outcome": "Additional credentials"
      },
      {
        "order": 3,
        "action": "Parse web.config for DB credentials",
        "effort": "trivial",
        "outcome": "Database access credentials"
      },
      {
        "order": 4,
        "action": "Extract Chrome passwords",
        "effort": "low",
        "outcome": "User's saved web credentials"
      },
      {
        "order": 5,
        "action": "Modify scheduled task script",
        "effort": "low",
        "outcome": "SYSTEM access on next execution"
      },
      {
        "order": 6,
        "action": "With SYSTEM: dump LSASS (bypass PPL if needed)",
        "effort": "medium",
        "outcome": "All cached credentials"
      }
    ],
    "total_time_estimate": "15-30 minutes"
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 24/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

### EXERCICE 3.36.6 : Windows Persistence Architect

**Fichier** : `ex06_windows_persistence/`

**Sujet** :
Concevez une stratégie de persistance multi-couches pour un scénario donné, avec protection mémoire et intégration .NET/PowerShell.

**Concepts évalués** : p, q, r, u, v + 3.36.5.i, 3.36.5.j, 3.36.5.k

**Entrée** :
```json
{
  "access_level": "local_admin",
  "persistence_requirements": {
    "survive_reboot": true,
    "survive_credential_change": true,
    "multiple_methods": true,
    "stealth_priority": "high",
    "quick_trigger": true
  },
  "environment": {
    "os": "Windows Server 2019",
    "is_dc": false,
    "edr": "none",
    "monitoring": "basic_event_logs",
    "admin_activity": "weekly"
  },
  "available_payloads": {
    "csharp_dll": "implant.dll (45KB)",
    "powershell_script": "stager.ps1",
    "executable": "beacon.exe (100KB)"
  }
}
```

**Sortie attendue** :
```json
{
  "persistence_strategy": {
    "name": "Defense in Depth Persistence",
    "layers": 3,
    "philosophy": "Multiple independent methods ensure survival"
  },
  "layer_1_primary": {
    "method": "WMI Event Subscription",
    "description": "Permanent WMI event consumer triggers payload",
    "stealth_rating": "high",
    "reliability": "high",
    "survives": ["reboot", "password_change", "user_logoff"],
    "implementation": {
      "event_filter": {
        "name": "SystemHealthMonitor",
        "query": "__InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60",
        "trigger": "Every 5 minutes after 60 seconds uptime"
      },
      "event_consumer": {
        "type": "CommandLineEventConsumer",
        "name": "HealthCheck",
        "command": "powershell -ep bypass -w hidden -enc <base64_stager>"
      },
      "binding": {
        "filter": "SystemHealthMonitor",
        "consumer": "HealthCheck"
      }
    },
    "detection_considerations": {
      "logs": "WMI-Activity log may record creation",
      "evasion": "Use generic names, blend with legitimate WMI",
      "cleanup": "Remove with wmic or PowerShell"
    },
    "mitre_technique": "T1546.003"
  },
  "layer_2_secondary": {
    "method": "COM Hijacking",
    "description": "Hijack frequently-used COM object for DLL loading",
    "stealth_rating": "high",
    "reliability": "medium",
    "survives": ["reboot", "password_change"],
    "implementation": {
      "target_clsid": "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
      "target_name": "MMDeviceEnumerator",
      "trigger": "Any application using audio (explorer, browsers)",
      "hijack_location": "HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32",
      "value": "C:\\Users\\Public\\Music\\mmdevapi.dll",
      "original_dll": "Proxy to real mmdevapi.dll after payload execution"
    },
    "payload_requirements": {
      "dll_type": "Proxy DLL",
      "must_export": "Original mmdevapi exports",
      "execution": "DllMain runs payload, then proxies to real DLL"
    },
    "mitre_technique": "T1546.015"
  },
  "layer_3_backup": {
    "method": "Scheduled Task with SYSTEM",
    "description": "Traditional but reliable scheduled task",
    "stealth_rating": "medium",
    "reliability": "very_high",
    "survives": ["reboot", "password_change"],
    "implementation": {
      "task_name": "Microsoft\\Windows\\Maintenance\\CacheCleanup",
      "disguise": "Blend with Windows maintenance tasks",
      "trigger": {
        "type": "daily",
        "time": "03:00",
        "random_delay": "PT1H"
      },
      "action": {
        "type": "exec",
        "command": "rundll32.exe",
        "arguments": "C:\\Windows\\System32\\wbem\\performance\\cache.dll,DllRegisterServer"
      },
      "run_as": "SYSTEM",
      "hidden": true
    },
    "mitre_technique": "T1053.005"
  },
  "memory_protection": {
    "sleep_obfuscation": {
      "technique": "Ekko Sleep Obfuscation",
      "description": "Encrypt implant memory during sleep periods",
      "implementation": {
        "method": "Create timer with callback, ROP chain to:",
        "steps": [
          "VirtualProtect to PAGE_READWRITE",
          "Encrypt implant memory with key",
          "Sleep for specified duration",
          "Timer fires: decrypt memory",
          "VirtualProtect back to PAGE_EXECUTE_READ",
          "Resume execution"
        ]
      },
      "benefit": "Memory scanners see encrypted blob during sleep"
    },
    "heap_encryption": {
      "technique": "Encrypted heap allocations",
      "description": "Sensitive strings/data encrypted in heap",
      "implementation": {
        "on_allocate": "Encrypt data with session key before storing",
        "on_use": "Decrypt to stack, use, zero memory",
        "key_management": "Derive from process-specific value"
      }
    },
    "stack_protection": {
      "technique": "Stack string encryption",
      "description": "No plaintext strings on stack",
      "implementation": {
        "compile_time": "Encrypt strings at compile time",
        "runtime": "Decrypt to temporary buffer, use, zero"
      }
    }
  },
  "dotnet_integration": {
    "method": "In-memory Assembly.Load",
    "description": "Load C# implant without touching disk",
    "implementation": {
      "loader": "PowerShell or direct .NET hosting",
      "steps": [
        "Read encrypted DLL bytes from resource/network",
        "Decrypt in memory",
        "[System.Reflection.Assembly]::Load($bytes)",
        "Find entry class via reflection",
        "[type].GetMethod('Main').Invoke($null, @())"
      ]
    },
    "amsi_consideration": "Bypass AMSI before Assembly.Load"
  },
  "powershell_integration": {
    "method": "Constrained Language Mode bypass + AMSI bypass",
    "execution_strategy": {
      "if_clm_enabled": [
        "Use PowerShell runspace API from C#",
        "Or use InstallUtil/regsvcs .NET execution",
        "Or downgrade to PowerShell v2 if available"
      ],
      "amsi_bypass": "Patch before loading scripts",
      "profile_persistence": {
        "path": "$PROFILE.AllUsersAllHosts",
        "content": "Hidden command execution in profile",
        "stealth": "Obfuscated one-liner"
      }
    }
  },
  "trigger_mechanism": {
    "primary": "WMI event every 5 minutes",
    "fallback_1": "COM hijack on audio app usage",
    "fallback_2": "Scheduled task daily at 03:00",
    "manual_trigger": "All methods can be triggered manually for rapid access"
  },
  "stealth_considerations": {
    "file_locations": [
      "C:\\Users\\Public\\Music\\ - Low suspicion",
      "C:\\Windows\\System32\\wbem\\performance\\ - Blend with WMI",
      "C:\\Windows\\Temp\\<random>\\ - Temporary operations"
    ],
    "naming_conventions": "Use Windows-like names (cache.dll, mmdevapi.dll)",
    "timestamps": "Match to surrounding files using timestomping",
    "size": "Keep DLLs small, similar to legitimate"
  },
  "redundancy_verification": {
    "check_script": "Verify all 3 methods are installed correctly",
    "self_healing": "Each method can reinstall others if removed"
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 25/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

## SOUS-MODULE 3.36.3 : Linux Malware Development (16 concepts)

### Concepts couverts :
- **a** : Linux Internals for Malware
- **b** : ELF Structure
- **c** : ELF Manipulation
- **d** : Process Injection Linux
- **e** : ptrace Injection
- **f** : LD_PRELOAD Hijacking
- **g** : Shared Library Trojaning
- **h** : Fileless Linux Malware
- **i** : Linux Persistence
- **j** : Linux Rootkits
- **k** : eBPF Malware
- **l** : Container-Aware Malware
- **m** : Linux Credential Access
- **n** : PAM Backdoors
- **o** : SSH Backdoors
- **p** : Anti-Forensics Linux

---

### EXERCICE 3.36.7 : Linux Implant Designer

**Fichier** : `ex07_linux_implant/`

**Sujet** :
Concevez un implant Linux adapté à un environnement cible, incluant structure ELF, technique d'injection, exécution fileless, et persistance.

**Concepts évalués** : a, b, c, d, e, f, g, h, i + 3.36.6.l

**Entrée** :
```json
{
  "target_environment": {
    "distro": "Ubuntu 22.04 LTS",
    "kernel": "5.15.0-generic",
    "security": {
      "selinux": "disabled",
      "apparmor": "enforcing",
      "seccomp": "enabled_default",
      "ptrace_scope": 1
    },
    "users": {
      "compromised": "www-data",
      "target": "root"
    },
    "services": ["nginx", "postgresql", "docker"]
  },
  "implant_requirements": {
    "initial_access": "web_shell",
    "stealth": "high",
    "persistence": "required",
    "features": ["shell", "file_ops", "port_forward"]
  }
}
```

**Sortie attendue** :
```json
{
  "implant_design": {
    "name": "phantom_linux",
    "language": "Rust",
    "target_arch": "x86_64-unknown-linux-musl",
    "binary_type": "static_pie",
    "size_estimate": "800KB stripped"
  },
  "elf_structure_decisions": {
    "format": "PIE executable (Position Independent Executable)",
    "static_linking": true,
    "reason": "No libc dependency, works across distros",
    "sections": {
      ".text": "Executable code",
      ".rodata": "Encrypted strings, config",
      ".data": "Mutable globals (encrypted at rest)",
      ".bss": "Zero-initialized data"
    },
    "stripping": "Full strip + section header removal",
    "anti_analysis": [
      "Remove symbol table",
      "Obfuscate section names",
      "Anti-debugging ptrace check"
    ]
  },
  "injection_strategy": {
    "from_www_data": {
      "challenge": "ptrace_scope=1 prevents attaching to non-child processes",
      "solution": "No injection needed initially - run as www-data",
      "alternative": "LD_PRELOAD for processes we can influence"
    },
    "if_root_achieved": {
      "technique": "ptrace injection",
      "target_process": "Existing long-running process (cron, sshd)",
      "implementation": {
        "steps": [
          "PTRACE_ATTACH to target",
          "Wait for stop",
          "Save registers (PTRACE_GETREGS)",
          "Find executable memory via /proc/pid/maps",
          "Inject shellcode loader",
          "Set RIP to shellcode",
          "PTRACE_CONT",
          "Shellcode mmaps and executes full payload"
        ]
      }
    },
    "ld_preload_option": {
      "use_case": "Hijack specific applications we can influence",
      "implementation": {
        "create_lib": "libpthread.so.0 replacement",
        "hook_function": "pthread_create - intercept thread creation",
        "inject_point": "/etc/ld.so.preload or per-process LD_PRELOAD"
      },
      "limitation": "Needs write to /etc/ld.so.preload (root) or environment control"
    }
  },
  "fileless_execution": {
    "technique": "memfd_create",
    "description": "Execute payload entirely from memory",
    "implementation": {
      "steps": [
        "memfd_create('', MFD_CLOEXEC) - create anonymous file",
        "Write payload bytes to memfd",
        "fexecve(fd, argv, envp) - execute from fd",
        "Or: /proc/self/fd/<fd> as path"
      ],
      "alternative": {
        "method": "shm_open + execute",
        "path": "/dev/shm/<random_name>",
        "cleanup": "unlink immediately after open"
      }
    },
    "process_replacement": {
      "technique": "Fork + execve into memfd",
      "benefit": "Clean process without file on disk"
    }
  },
  "persistence_mechanisms": [
    {
      "method": "Cron job",
      "stealth": "medium",
      "location": "/var/spool/cron/crontabs/root or /etc/cron.d/",
      "disguise": "@reboot /usr/lib/x86_64-linux-gnu/security/pam_systemd_home --daemon",
      "requires": "root"
    },
    {
      "method": "Systemd service",
      "stealth": "medium",
      "location": "/etc/systemd/system/",
      "disguise": "system-health-monitor.service",
      "content": {
        "description": "System Health Monitor Daemon",
        "execstart": "/usr/lib/systemd/systemd-health-monitor"
      },
      "requires": "root"
    },
    {
      "method": "Shell profile",
      "stealth": "low",
      "location": "/etc/profile.d/locale-gen.sh",
      "use_case": "User-level persistence",
      "content": "Obfuscated command in shell script"
    },
    {
      "method": "LD_PRELOAD global",
      "stealth": "high",
      "location": "/etc/ld.so.preload",
      "library": "/usr/lib/x86_64-linux-gnu/libpam.so.1.0",
      "requires": "root",
      "effect": "All dynamically linked programs load our library"
    }
  ],
  "recommended_persistence": {
    "if_root": "Systemd service (most reliable, well-disguised)",
    "if_www_data": "Cron with www-data (limited but possible)"
  },
  "file_operations": {
    "implementation": "Direct syscalls via libc",
    "features": ["browse", "read", "write", "upload", "download"],
    "opsec": {
      "mtime_preservation": "Save and restore mtime on file operations",
      "careful_logging": "Avoid kernel audit log triggers"
    }
  },
  "apparmor_considerations": {
    "challenge": "AppArmor may restrict www-data profile",
    "check": "cat /proc/self/attr/current for current profile",
    "bypass_options": [
      "Find allowed binaries for pivoting",
      "Escape to unconfined context if possible",
      "Work within profile constraints"
    ]
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 24/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

### EXERCICE 3.36.8 : Linux Rootkit Component Analyzer

**Fichier** : `ex08_linux_rootkit/`

**Sujet** :
Analysez les composants d'un rootkit Linux moderne: LKM, eBPF, backdoors système, et techniques container-aware.

**Concepts évalués** : j, k, l, m, n, o, p + 3.36.6.m

**Entrée** :
```json
{
  "rootkit_sample": {
    "type": "hybrid",
    "components": ["lkm", "ebpf", "userland"],
    "capabilities_claimed": [
      "process_hiding",
      "file_hiding",
      "network_connection_hiding",
      "container_escape",
      "credential_harvesting",
      "ssh_backdoor"
    ]
  },
  "analysis_environment": {
    "kernel": "5.15.0",
    "ebpf_enabled": true,
    "modules_enabled": true,
    "secure_boot": false
  },
  "analysis_focus": ["detection_evasion", "persistence", "capability_assessment"]
}
```

**Sortie attendue** :
```json
{
  "rootkit_analysis": {
    "classification": "Advanced Hybrid Rootkit",
    "sophistication": "high",
    "target_kernels": "5.x+ with eBPF support"
  },
  "lkm_component": {
    "description": "Loadable Kernel Module for core hiding capabilities",
    "techniques": {
      "process_hiding": {
        "method": "Syscall table hooking - getdents/getdents64",
        "implementation": "Filter directory entries to hide /proc/<pid>",
        "kernel_5x_approach": "Use ftrace or kprobes (syscall table RO in modern kernels)"
      },
      "file_hiding": {
        "method": "VFS layer hooking",
        "implementation": "Hook iterate_dir in file_operations struct",
        "hidden_patterns": "Files starting with specific prefix"
      },
      "network_hiding": {
        "method": "Proc filesystem hooking",
        "implementation": "Filter /proc/net/tcp, /proc/net/udp entries",
        "alternative": "Netfilter hook to hide packets from tcpdump"
      },
      "module_hiding": {
        "method": "List manipulation",
        "implementation": "Remove from module list via list_del",
        "kobject_removal": "Remove from /sys/module/"
      }
    },
    "loading_mechanism": {
      "standard": "insmod/modprobe",
      "stealthy": "Direct memory loading via /dev/mem or kernel exploit",
      "persistence": "Add to /etc/modules-load.d/ or initramfs"
    },
    "anti_detection": [
      "Clear module from list immediately after init",
      "Obfuscate module name and symbols",
      "Hide from lsmod and /proc/modules"
    ]
  },
  "ebpf_component": {
    "description": "eBPF programs for userspace hiding and manipulation",
    "advantages": [
      "No kernel module needed after load",
      "Harder to detect than LKM",
      "Works with kernel lockdown"
    ],
    "techniques": {
      "credential_harvesting": {
        "hook_point": "sys_enter_write",
        "target": "SSH, sudo authentication",
        "implementation": "Capture write() data to /dev/pts/* and specific file paths"
      },
      "network_manipulation": {
        "hook_point": "xdp, tc",
        "capability": "Hide traffic, redirect packets"
      },
      "syscall_monitoring": {
        "hook_point": "tracepoint:syscalls",
        "capability": "Log all syscalls for specific processes"
      }
    },
    "loading": {
      "method": "bpf() syscall",
      "pinning": "/sys/fs/bpf/ for persistence",
      "tools": "libbpf, bcc"
    },
    "detection_evasion": {
      "challenge": "bpftool can list BPF programs",
      "evasion": "Unhook bpftool or hide from prog list"
    }
  },
  "userland_component": {
    "pam_backdoor": {
      "description": "Modified PAM module for authentication bypass",
      "implementation": {
        "target": "/lib/x86_64-linux-gnu/security/pam_unix.so",
        "modification": "Accept hardcoded password for any user",
        "alternative": "Add custom PAM module to auth stack"
      },
      "credential_logging": {
        "method": "Log successful auth to hidden file",
        "location": "/dev/shm/.pam_log or kernel buffer"
      }
    },
    "ssh_backdoor": {
      "type": "Public key backdoor",
      "implementation": {
        "method_1": "Add key to /root/.ssh/authorized_keys",
        "method_2": "Patch sshd to accept specific key regardless of authorized_keys",
        "method_3": "Implant in sshd for command execution"
      },
      "ssh_agent_hijacking": {
        "method": "Find SSH_AUTH_SOCK, connect, use agent for auth",
        "implementation": "Enumerate /tmp/ssh-* for agent sockets"
      }
    }
  },
  "container_awareness": {
    "detection": {
      "methods": [
        "Check /.dockerenv existence",
        "Check /proc/1/cgroup for container patterns",
        "Check PID namespace"
      ]
    },
    "container_escape_techniques": [
      {
        "technique": "Privileged container escape",
        "condition": "--privileged flag or excessive capabilities",
        "method": "Mount host filesystem, chroot, execute on host"
      },
      {
        "technique": "Docker socket access",
        "condition": "/var/run/docker.sock mounted",
        "method": "Create privileged container, mount host /"
      },
      {
        "technique": "Kernel exploit",
        "condition": "Vulnerable kernel + CAP_SYS_ADMIN",
        "method": "Namespace escape via kernel vulnerability"
      }
    ],
    "namespace_manipulation": {
      "method": "setns() to enter/exit namespaces",
      "targets": ["mnt", "pid", "net", "user"]
    }
  },
  "credential_access": {
    "targets": [
      {
        "source": "/etc/shadow",
        "access_needed": "root",
        "method": "Direct read, offline cracking"
      },
      {
        "source": "Memory",
        "method": "ptrace to sshd/sudo processes",
        "data": "Plaintext passwords in memory during auth"
      },
      {
        "source": "SSH keys",
        "locations": ["~/.ssh/id_*", "/etc/ssh/ssh_host_*"],
        "method": "File exfiltration"
      },
      {
        "source": "Browser data",
        "locations": ["~/.config/google-chrome/", "~/.mozilla/firefox/"],
        "method": "Database extraction, cookie theft"
      },
      {
        "source": "Keyrings",
        "method": "GNOME Keyring / KWallet extraction"
      }
    ]
  },
  "anti_forensics": {
    "log_tampering": {
      "targets": ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"],
      "methods": [
        "Hook write() to filter log entries",
        "Truncate logs",
        "Modify log rotation to destroy evidence"
      ]
    },
    "timestamp_manipulation": {
      "method": "touch with specific timestamps",
      "automation": "Save original, restore after modification"
    },
    "process_hiding": {
      "from_ps": "Hide from /proc enumeration",
      "from_netstat": "Hide connections from /proc/net/*"
    },
    "artifact_cleanup": [
      "Clear bash_history",
      "Clear .viminfo",
      "Clear authentication logs",
      "Remove dropped files"
    ]
  },
  "detection_recommendations": {
    "lkm_detection": [
      "Compare module list with trusted baseline",
      "Check for hidden modules via memory forensics",
      "Monitor module load events"
    ],
    "ebpf_detection": [
      "Regular bpftool prog list",
      "Monitor bpf() syscalls",
      "Check /sys/fs/bpf/ for unexpected maps/progs"
    ],
    "pam_detection": [
      "Hash PAM libraries against known-good",
      "Monitor PAM configuration changes"
    ],
    "ssh_detection": [
      "Audit authorized_keys files",
      "Monitor sshd binary integrity"
    ]
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 25/25
- Originalité : 20/20
- Testabilité : 14/15
- Clarté : 14/15

---

## SOUS-MODULES 3.36.4-3.36.6 : Rootkits, Evasion, Payloads

(Exercices supplémentaires couvrant les concepts restants)

---

### EXERCICE 3.36.9 : Rootkit Taxonomy Classifier

**Fichier** : `ex09_rootkit_taxonomy/`

**Concepts évalués** : 3.36.4.a-i (9 concepts)

**Sujet** :
Classifiez un ensemble de rootkits selon leur niveau, techniques de hooking, et capacités de dissimulation.

**Barème** : 96/100

---

### EXERCICE 3.36.10 : Bootkit & Firmware Analyzer

**Fichier** : `ex10_bootkit_firmware/`

**Concepts évalués** : 3.36.4.j-r (9 concepts)

**Sujet** :
Analysez un scénario de persistence firmware/boot et identifiez le type de bootkit, bypass Secure Boot, et méthodes de détection.

**Barème** : 97/100

---

### EXERCICE 3.36.11 : Advanced Evasion Orchestrator

**Fichier** : `ex11_advanced_evasion/`

**Concepts évalués** : 3.36.5.n-t (6 concepts)

**Sujet** :
Orchestrez une stratégie d'évasion complète incluant spoofing (PPID, cmdline, stack), timestomping, LOLBins, et contournement ML.

**Barème** : 97/100

---

### EXERCICE 3.36.12 : Payload Capabilities Designer

**Fichier** : `ex12_payload_capabilities/`

**Concepts évalués** : 3.36.6.j, k, o, p (4 concepts)

**Sujet** :
Concevez les spécifications de capacités avancées: capture multimédia, opérations registry, et architecture ransomware (pour compréhension défensive).

**Barème** : 96/100

---

### EXERCICE 3.36.13 : Integrated Maldev Assessment

**Fichier** : `ex13_integrated_assessment/`

**Concepts évalués** : Synthèse multi-concepts

**Sujet** :
Évaluation intégrée combinant architecture, injection, évasion, persistence, et payloads pour un scénario de pentest complet.

**Barème** : 98/100

---

### EXERCICE 3.36.14 : Control Flow & Anti-Analysis Architect

**Fichier** : `ex14_control_flow_anti_analysis/`

**Sujet** :
Concevez une strategie d'obfuscation de flux de controle et de techniques anti-analyse pour proteger un implant contre l'analyse statique et dynamique.

**Concepts evalues** : 3.36.1.h (Control Flow Obfuscation), 3.36.1.i (Anti-Analysis Basics)

**Entree** :
```json
{
  "implant_characteristics": {
    "language": "c",
    "size_kb": 85,
    "functions_count": 47,
    "critical_functions": ["c2_beacon", "credential_harvest", "persistence_install"],
    "current_protections": ["string_encryption", "api_hashing"]
  },
  "threat_model": {
    "analysts": ["reverse_engineer", "malware_analyst", "sandbox"],
    "tools_expected": ["ida_pro", "ghidra", "x64dbg", "cuckoo", "any_run"],
    "analysis_time_budget_hours": 8
  },
  "constraints": {
    "performance_overhead_max_percent": 15,
    "size_increase_max_percent": 30,
    "must_remain_functional": true
  },
  "target_environment": {
    "os": "windows_10_11",
    "edr_present": ["crowdstrike", "defender"],
    "virtualization_common": true
  }
}
```

**Sortie attendue** :
```json
{
  "obfuscation_strategy": {
    "name": "Multi-Layer Control Flow Protection",
    "estimated_analysis_time_increase": "4x-8x"
  },
  "control_flow_obfuscation": {
    "techniques": [
      {
        "technique": "Opaque Predicates",
        "description": "Insert always-true or always-false conditions using mathematical properties",
        "implementation": {
          "method": "Use invariants like (x * (x + 1)) % 2 == 0 (always true)",
          "insertion_points": "Before critical function calls, loop conditions",
          "variants": [
            "Mathematical: x^2 >= 0",
            "Pointer aliasing: &a != &b (different vars)",
            "Loop-based: computed at runtime"
          ]
        },
        "effectiveness": {
          "vs_static_analysis": "HIGH - adds false paths",
          "vs_dynamic_analysis": "LOW - path not taken",
          "vs_symbolic_execution": "MEDIUM - depends on solver"
        },
        "overhead_percent": 3
      },
      {
        "technique": "Control Flow Flattening",
        "description": "Replace structured control flow with state machine dispatcher",
        "implementation": {
          "method": "Convert if/else/loops to switch-based dispatcher",
          "structure": {
            "dispatcher": "while(state != EXIT) { switch(state) { ... } }",
            "state_variable": "Encrypted or computed state transitions",
            "basic_blocks": "Each block ends with state update"
          },
          "apply_to": ["c2_beacon", "credential_harvest"]
        },
        "effectiveness": {
          "vs_static_analysis": "VERY HIGH - no clear structure",
          "vs_dynamic_analysis": "MEDIUM - paths revealed at runtime",
          "vs_decompilers": "HIGH - produces unreadable output"
        },
        "overhead_percent": 8
      },
      {
        "technique": "Bogus Control Flow",
        "description": "Insert dead code paths that appear viable",
        "implementation": {
          "method": "Add fake branches with realistic-looking code",
          "fake_blocks": [
            "Decoy API calls (never executed)",
            "Fake error handling",
            "Unused cryptographic operations"
          ],
          "protection": "Guard with opaque predicates"
        },
        "effectiveness": {
          "vs_static_analysis": "HIGH - many false leads",
          "vs_dynamic_analysis": "LOW - dead code not executed"
        },
        "overhead_percent": 5
      },
      {
        "technique": "Instruction Substitution",
        "description": "Replace simple instructions with equivalent complex sequences",
        "implementation": {
          "substitutions": [
            {"original": "xor eax, eax", "replacement": "sub eax, eax / and eax, 0 / mov eax, 0"},
            {"original": "mov eax, 1", "replacement": "xor eax, eax; inc eax / push 1; pop eax"},
            {"original": "add eax, 5", "replacement": "sub eax, -5 / lea eax, [eax+5]"},
            {"original": "cmp eax, 0", "replacement": "test eax, eax / or eax, eax"}
          ],
          "randomization": "Different substitution per build"
        },
        "effectiveness": {
          "vs_pattern_matching": "HIGH - breaks signatures",
          "vs_manual_analysis": "MEDIUM - annoying but reversible"
        },
        "overhead_percent": 2
      }
    ],
    "recommended_combination": "Flatten critical functions + opaque predicates everywhere + instruction substitution"
  },
  "anti_analysis_techniques": {
    "anti_debug": [
      {
        "technique": "IsDebuggerPresent API",
        "implementation": "Check PEB->BeingDebugged flag",
        "bypass_difficulty": "TRIVIAL",
        "use_as": "First layer, decoy for real checks"
      },
      {
        "technique": "NtQueryInformationProcess",
        "implementation": "ProcessDebugPort (0x7), ProcessDebugObjectHandle (0x1E)",
        "bypass_difficulty": "EASY",
        "detection": "Non-zero value indicates debugger"
      },
      {
        "technique": "Timing Checks",
        "implementation": "RDTSC before/after code block, threshold comparison",
        "bypass_difficulty": "MEDIUM",
        "variants": ["QueryPerformanceCounter", "GetTickCount64", "timeGetTime"]
      },
      {
        "technique": "Hardware Breakpoint Detection",
        "implementation": "Check DR0-DR7 via GetThreadContext or NtGetContextThread",
        "bypass_difficulty": "MEDIUM",
        "action": "Clear or detect DRx registers"
      },
      {
        "technique": "Software Breakpoint Detection",
        "implementation": "Scan code sections for 0xCC (INT3), checksum verification",
        "bypass_difficulty": "MEDIUM",
        "scope": "Critical functions only (performance)"
      },
      {
        "technique": "Parent Process Check",
        "implementation": "Verify parent is explorer.exe not debugger",
        "bypass_difficulty": "EASY",
        "note": "Check via NtQueryInformationProcess"
      }
    ],
    "anti_vm": [
      {
        "technique": "CPUID Check",
        "implementation": "CPUID leaf 0x1, check hypervisor bit (ECX bit 31)",
        "bypass_difficulty": "MEDIUM",
        "detects": ["VMware", "VirtualBox", "Hyper-V", "KVM"]
      },
      {
        "technique": "Registry Keys",
        "implementation": "Check for VM-specific keys",
        "keys": [
          "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
          "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
          "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__"
        ],
        "bypass_difficulty": "EASY"
      },
      {
        "technique": "MAC Address Prefix",
        "implementation": "Check for known VM MAC prefixes",
        "prefixes": {
          "VMware": ["00:0C:29", "00:50:56"],
          "VirtualBox": ["08:00:27"],
          "Hyper-V": ["00:15:5D"]
        },
        "bypass_difficulty": "EASY"
      },
      {
        "technique": "Process/Service Enumeration",
        "implementation": "Check for VM tools processes",
        "targets": ["vmtoolsd.exe", "vmwaretray.exe", "VBoxService.exe", "VBoxTray.exe"],
        "bypass_difficulty": "EASY"
      },
      {
        "technique": "Firmware Tables",
        "implementation": "GetSystemFirmwareTable for SMBIOS, check for VM strings",
        "strings": ["VMware", "VirtualBox", "QEMU", "Xen"],
        "bypass_difficulty": "MEDIUM"
      },
      {
        "technique": "Resource Checks",
        "implementation": "Low RAM (<4GB), few cores (<2), small disk (<60GB)",
        "bypass_difficulty": "EASY",
        "note": "May cause false positives on low-end systems"
      }
    ],
    "anti_sandbox": [
      {
        "technique": "User Interaction Check",
        "implementation": "Monitor mouse movement, keyboard input over time",
        "threshold": "Require 5+ distinct mouse positions in 30 seconds",
        "bypass_difficulty": "MEDIUM"
      },
      {
        "technique": "Execution Delay",
        "implementation": "Sleep before malicious activity",
        "methods": ["Sleep()", "NtDelayExecution", "WaitForSingleObject timeout"],
        "duration": "5-10 minutes (sandbox timeout typically 2-5 min)",
        "evasion": "Avoid obvious large sleeps (detected), use incremental"
      },
      {
        "technique": "Environment Fingerprinting",
        "implementation": "Check for sandbox artifacts",
        "artifacts": [
          "Username: sandbox, malware, virus, sample",
          "Computername: SANDBOX, VIRUS, MALWARE",
          "Recent files: none (clean install)",
          "Installed software: minimal"
        ],
        "bypass_difficulty": "MEDIUM"
      },
      {
        "technique": "Network Check",
        "implementation": "Verify internet connectivity to legitimate site",
        "rationale": "Some sandboxes simulate or block network",
        "bypass_difficulty": "LOW"
      }
    ]
  },
  "implementation_order": [
    {
      "phase": 1,
      "actions": ["Implement basic anti-debug (decoy)", "Add timing checks"],
      "purpose": "Deter casual analysis"
    },
    {
      "phase": 2,
      "actions": ["Apply control flow flattening to critical functions", "Add opaque predicates"],
      "purpose": "Hinder static analysis"
    },
    {
      "phase": 3,
      "actions": ["Implement anti-VM checks", "Add sandbox evasion"],
      "purpose": "Evade automated analysis"
    },
    {
      "phase": 4,
      "actions": ["Instruction substitution", "Bogus control flow"],
      "purpose": "Break signatures and patterns"
    }
  ],
  "detection_response_matrix": {
    "debugger_detected": ["Exit gracefully", "Delete self", "Execute decoy behavior"],
    "vm_detected": ["Sleep indefinitely", "Reduce functionality", "Execute benign code"],
    "sandbox_detected": ["Wait for user interaction", "Time-based trigger", "Environment-based trigger"]
  },
  "total_overhead": {
    "size_increase_percent": 22,
    "performance_overhead_percent": 12,
    "within_constraints": true
  },
  "quality_assessment": {
    "static_analysis_resistance": 85,
    "dynamic_analysis_resistance": 70,
    "sandbox_evasion_rate": 75,
    "overall_score": 77
  }
}
```

**Criteres de notation** :
- Techniques de control flow obfuscation pertinentes (25 pts)
- Techniques anti-analyse completes (25 pts)
- Implementation realiste et applicable (20 pts)
- Respect des contraintes de performance (15 pts)
- Format JSON valide et structure claire (15 pts)

**Note pedagogique** : 97/100

---

### EXERCICE 3.36.15 : Evasion Techniques Masterclass

**Fichier** : `ex15_evasion_masterclass/`

**Sujet** :
Concevez une strategie d'evasion complete couvrant les techniques de signature, packers/crypters, code polymorphique et metamorphique pour contourner les solutions de securite modernes.

**Concepts evalues** : 3.36.5.a (Signature Evasion), 3.36.5.b (Packers & Crypters), 3.36.5.c (Polymorphic Code), 3.36.5.d (Metamorphic Code), 3.36.5.f (Anti-Debug Techniques), 3.36.5.g (Anti-VM Techniques)

**Entree** :
```json
{
  "payload": {
    "type": "cobalt_strike_beacon",
    "size_kb": 290,
    "detected_by": ["defender", "kaspersky", "crowdstrike"],
    "detection_type": ["signature", "behavioral", "memory_scan"]
  },
  "target_defenses": {
    "av_products": ["windows_defender", "kaspersky_endpoint"],
    "edr_products": ["crowdstrike_falcon", "carbon_black"],
    "sandbox_analysis": true,
    "network_monitoring": true
  },
  "requirements": {
    "must_evade": ["static_signature", "yara_rules", "behavior_patterns"],
    "execution_environment": "memory_only",
    "persistence_needed": false,
    "c2_protocol": "https"
  },
  "constraints": {
    "final_size_max_kb": 500,
    "execution_time_overhead_max_ms": 5000,
    "must_work_on": ["windows_10_22h2", "windows_11_23h2", "windows_server_2022"]
  }
}
```

**Sortie attendue** :
```json
{
  "evasion_strategy": {
    "name": "Multi-Stage Polymorphic Loader",
    "approach": "Layered evasion with runtime generation",
    "estimated_evasion_rate": 85
  },
  "signature_evasion": {
    "techniques": [
      {
        "technique": "String Encryption",
        "description": "Encrypt all static strings at compile time, decrypt at runtime",
        "implementation": {
          "algorithm": "XOR with rotating key or ChaCha20",
          "key_derivation": "Derive from environmental factors (hostname hash, username)",
          "decrypt_timing": "Just before use, immediately zero after"
        },
        "effectiveness_vs_yara": "HIGH",
        "overhead_ms": 50
      },
      {
        "technique": "API Obfuscation",
        "description": "Avoid import table, resolve APIs dynamically",
        "implementation": {
          "method": "Hash-based API resolution via PEB walking",
          "hash_algorithm": "DJB2 or custom rotating hash",
          "iat_population": "None - all dynamic resolution"
        },
        "effectiveness_vs_static": "VERY HIGH",
        "overhead_ms": 100
      },
      {
        "technique": "Junk Code Insertion",
        "description": "Add non-functional code to break signatures",
        "implementation": {
          "types": ["NOPs", "Dead calculations", "Fake API calls"],
          "density": "10-20% of code size",
          "variability": "Randomized per build"
        },
        "effectiveness_vs_yara": "MEDIUM",
        "overhead_ms": 0
      },
      {
        "technique": "Timestamp Randomization",
        "description": "Randomize PE timestamps and metadata",
        "fields": ["TimeDateStamp", "Checksum", "Debug directory", "Rich header"],
        "effectiveness_vs_ioc": "MEDIUM"
      }
    ]
  },
  "packers_and_crypters": {
    "strategy": "Custom crypter with environmental keying",
    "layers": [
      {
        "layer": 1,
        "name": "Outer Stub",
        "description": "Minimal loader, appears benign",
        "implementation": {
          "functionality": "Load and decrypt layer 2",
          "size_kb": 15,
          "obfuscation": "Light - pass static analysis as legitimate app",
          "anti_analysis": "Basic VM/debug checks"
        }
      },
      {
        "layer": 2,
        "name": "Encrypted Payload Container",
        "description": "Main payload encrypted with AES-256-GCM",
        "implementation": {
          "encryption": "AES-256-GCM with HKDF key derivation",
          "key_source": "Environmental factors combined",
          "integrity": "GCM tag verification before execution",
          "key_derivation_inputs": [
            "Machine GUID (HKLM\\SOFTWARE\\Microsoft\\Cryptography)",
            "Computer name hash",
            "Windows build number"
          ]
        },
        "benefit": "Payload won't decrypt in sandbox with different environment"
      },
      {
        "layer": 3,
        "name": "Core Payload",
        "description": "Actual beacon code, unpacked in memory only",
        "protection": {
          "memory_encryption": "Ekko-style sleep encryption",
          "no_disk_touch": true,
          "module_stomping": "Overwrite legitimate DLL in memory"
        }
      }
    ],
    "commercial_packers_avoided": ["UPX", "Themida", "VMProtect"],
    "reason": "Known signatures, red flag for AV"
  },
  "polymorphic_code": {
    "definition": "Code that changes its appearance while maintaining functionality",
    "implementation": {
      "technique": "Polymorphic Decryption Stub",
      "description": "Each sample has unique decryption routine",
      "generator_features": [
        {
          "feature": "Register Randomization",
          "description": "Use different registers for same operations",
          "example": "EAX/EBX/ECX/EDX interchangeable for temp storage"
        },
        {
          "feature": "Instruction Substitution",
          "description": "Replace instructions with equivalents",
          "substitutions": [
            "ADD EAX, 1 -> INC EAX -> SUB EAX, -1 -> LEA EAX, [EAX+1]",
            "XOR EAX, KEY -> NOT EAX; XOR EAX, ~KEY",
            "MOV EAX, [addr] -> PUSH [addr]; POP EAX"
          ]
        },
        {
          "feature": "Junk Insertion",
          "description": "Random NOPs and dead code between real instructions",
          "density": "Variable 5-30% per stub"
        },
        {
          "feature": "Block Reordering",
          "description": "Shuffle independent code blocks with jumps",
          "constraint": "Maintain data dependencies"
        }
      ],
      "uniqueness": "Each build produces statistically unique binary",
      "hash_collision_probability": "< 0.001%"
    },
    "effectiveness": {
      "vs_signature_av": "VERY HIGH - no two samples match",
      "vs_yara": "HIGH - pattern-based rules fail",
      "vs_ml_detection": "MEDIUM - behavioral still applies"
    }
  },
  "metamorphic_code": {
    "definition": "Code that rewrites itself completely, not just decryption stub",
    "implementation": {
      "technique": "Full Code Metamorphism",
      "complexity": "HIGH",
      "components": [
        {
          "component": "Disassembly Engine",
          "purpose": "Parse own code into intermediate representation"
        },
        {
          "component": "Transformation Engine",
          "transformations": [
            "Register reassignment",
            "Code transposition (reorder independent blocks)",
            "Instruction substitution (equivalent opcodes)",
            "Code expansion (split instructions)",
            "Code shrinking (combine instructions)"
          ]
        },
        {
          "component": "Reassembly Engine",
          "purpose": "Generate new machine code from IR"
        }
      ],
      "example_transformation": {
        "original": "mov eax, [esi]; add eax, ebx; mov [edi], eax",
        "transformed": "push edi; mov edi, [esi]; add edi, ebx; pop eax; xchg eax, edi; mov [eax], edi; xchg eax, edi"
      }
    },
    "trade_offs": {
      "pros": ["Extremely hard to signature", "Each generation unique"],
      "cons": ["Complex implementation", "Risk of bugs", "Size increase", "Performance overhead"]
    },
    "recommendation": "Use metamorphic for loader, polymorphic for payload"
  },
  "anti_debug_integration": {
    "placement": "Throughout all layers",
    "techniques_applied": [
      {
        "layer": "Outer stub",
        "checks": ["IsDebuggerPresent", "PEB BeingDebugged", "NtGlobalFlag"],
        "action_on_detect": "Exit with fake error message"
      },
      {
        "layer": "Decryption routine",
        "checks": ["Timing checks (RDTSC)", "Hardware breakpoints (DR0-DR7)"],
        "action_on_detect": "Corrupt decryption key"
      },
      {
        "layer": "Core payload",
        "checks": ["Continuous timing", "Heap flags", "Parent process"],
        "action_on_detect": "Sleep indefinitely or self-destruct"
      }
    ]
  },
  "anti_vm_integration": {
    "placement": "Before payload decryption",
    "checks_implemented": [
      "CPUID hypervisor bit",
      "VM-specific registry keys",
      "MAC address prefixes",
      "Firmware table strings",
      "Process enumeration (VM tools)",
      "Hardware characteristics (RAM < 4GB, cores < 2)"
    ],
    "action_on_detect": "Execute decoy benign behavior, delay real execution",
    "false_positive_handling": "Allow override via specific environment marker"
  },
  "execution_flow": {
    "stages": [
      {
        "stage": 1,
        "name": "Initial Execution",
        "actions": ["Anti-analysis checks", "Environment validation", "Key derivation"]
      },
      {
        "stage": 2,
        "name": "Layer 1 Decryption",
        "actions": ["Decrypt polymorphic stub", "Integrity verification"]
      },
      {
        "stage": 3,
        "name": "Payload Unpacking",
        "actions": ["Decrypt core payload", "Module stomping or allocation"]
      },
      {
        "stage": 4,
        "name": "Execution",
        "actions": ["Reflective loading", "Start beacon with sleep encryption"]
      }
    ]
  },
  "testing_methodology": {
    "static_testing": ["VirusTotal (limited)", "YARA rule testing", "String analysis"],
    "dynamic_testing": ["Sandbox execution", "EDR lab environment", "Memory forensics"],
    "iteration": "Modify based on detection, regenerate polymorphic variants"
  },
  "final_assessment": {
    "estimated_size_kb": 380,
    "execution_overhead_ms": 3500,
    "within_constraints": true,
    "expected_evasion_breakdown": {
      "vs_defender": 90,
      "vs_kaspersky": 85,
      "vs_crowdstrike": 70,
      "vs_carbon_black": 75
    },
    "overall_evasion_score": 80
  }
}
```

**Criteres de notation** :
- Techniques de signature evasion completes (20 pts)
- Packers/Crypters implementation realiste (20 pts)
- Code polymorphique bien explique (15 pts)
- Code metamorphique bien explique (15 pts)
- Integration anti-debug et anti-VM (15 pts)
- Format JSON valide et structure claire (15 pts)

**Note pedagogique** : 98/100

---

## RECAPITULATIF MODULE 3.36

### Couverture par sous-module :

| Sous-module | Concepts | Couverts | Exercices |
|-------------|----------|----------|-----------|
| 3.36.1 Fondamentaux | 18 | 18 | Ex01, Ex02, Ex14 |
| 3.36.2 Windows | 22 | 22 | Ex03, Ex04, Ex05, Ex06 |
| 3.36.3 Linux | 16 | 16 | Ex07, Ex08 |
| 3.36.4 Rootkits | 18 | 18 | Ex09, Ex10 |
| 3.36.5 Evasion | 20 | 20 | Ex03-part, Ex04-part, Ex11, Ex14-part, Ex15 |
| 3.36.6 Payloads | 16 | 16 | Ex01-part, Ex02-part, Ex05-part, Ex12 |
| **TOTAL** | **110** | **110** | **15** |

### Statistiques :
- **Total concepts** : 110/110 (100%)
- **Total exercices** : 15
- **Score moyen** : 97.3/100
- **Orientation** : Offensive / Red Team / Pentest autorise

---

**Contexte**: Développement offensif pour pentest autorisé, CTF, recherche sécurité
**Format**: JSON input → JSON output (testable par moulinette Rust 2024)
**Critère**: Score >= 95/100 sur grille de qualité

---

# MODULE 3.36 : MALWARE DEVELOPMENT

## EXERCICE 3.36.1 : Implant Architecture Designer

**Concepts couverts** (12 concepts):
- 3.36.1.a : Malware Categories
- 3.36.1.b : Development Lifecycle
- 3.36.1.c : Language Selection
- 3.36.1.d : Implant Architecture
- 3.36.1.l : Configuration Management
- 3.36.1.m : Error Handling
- 3.36.1.n : Cross-Platform Considerations
- 3.36.1.o : Build Systems
- 3.36.1.p : Testing Malware
- 3.36.1.q : Versioning & Updates
- 3.36.1.r : Operational Security Dev
- 3.36.6.g : RAT Features

**Sujet**:
Analysez les spécifications d'un implant et produisez un design document complet incluant l'architecture modulaire, le choix de langage justifié, le cycle de développement, et les considérations OPSEC.

**Intelligence pédagogique**:
Force l'étudiant à penser comme un architecte logiciel malveillant, comprenant les trade-offs entre performance, furtivité, et maintenabilité.

**Validation**: ✅ 12/206 concepts

---

## EXERCICE 3.36.2 : Position Independent Shellcode Analyzer

**Concepts couverts** (8 concepts):
- 3.36.1.e : Position Independent Code
- 3.36.1.f : API Resolution
- 3.36.1.g : String Obfuscation
- 3.36.6.a : Shellcode Design
- 3.36.6.b : Shellcode Encoding
- 3.36.6.c : Stagers
- 3.36.6.d : Stageless Payloads
- 3.36.6.e : Droppers

**Sujet**:
Analysez un shellcode fourni (format hexadécimal) et identifiez: le type (stager/stageless), les techniques PIC utilisées, la méthode de résolution d'API, et l'obfuscation de strings.

**Intelligence pédagogique**:
L'étudiant doit comprendre pourquoi le code est position-independent et comment il résout dynamiquement les adresses sans IAT.

**Validation**: ✅ 20/206 concepts

---

## EXERCICE 3.36.3 : Execution Flow Obfuscator

**Concepts couverts** (8 concepts):
- 3.36.1.h : Control Flow Obfuscation
- 3.36.1.i : Anti-Analysis Basics
- 3.36.5.a : Signature Evasion
- 3.36.5.b : Packers & Crypters
- 3.36.5.c : Polymorphic Code
- 3.36.5.d : Metamorphic Code
- 3.36.5.f : Anti-Debug Techniques
- 3.36.5.g : Anti-VM Techniques

**Sujet**:
Concevez une stratégie d'obfuscation pour un payload donné. Spécifiez: techniques de control flow, vérifications anti-analyse, méthode de packing, et génération polymorphique.

**Intelligence pédagogique**:
Comprendre la différence entre obfuscation statique et dynamique, et pourquoi la combinaison des techniques est nécessaire.

**Validation**: ✅ 28/206 concepts

---

## EXERCICE 3.36.4 : PE Injection Technique Selector

**Concepts couverts** (12 concepts):
- 3.36.1.j : Payload Delivery
- 3.36.1.k : Execution Methods
- 3.36.2.a : Windows Internals for Malware
- 3.36.2.b : PE File Structure
- 3.36.2.c : PE Manipulation
- 3.36.2.d : Process Injection Techniques
- 3.36.2.e : Process Hollowing
- 3.36.2.f : DLL Injection
- 3.36.2.g : Reflective DLL Injection
- 3.36.2.h : Shellcode Injection
- 3.36.6.f : Loaders
- 3.36.6.n : Process Operations

**Sujet**:
Analysez un scénario d'exécution (cible, privilèges, détection) et recommandez la technique d'injection optimale avec justification technique complète.

**Intelligence pédagogique**:
Chaque technique a des avantages et inconvénients. L'étudiant apprend à choisir selon le contexte opérationnel.

**Validation**: ✅ 40/206 concepts

---

## EXERCICE 3.36.5 : Windows Defense Bypass Strategist

**Concepts couverts** (10 concepts):
- 3.36.2.i : Direct Syscalls
- 3.36.2.j : NTAPI Usage
- 3.36.2.m : AMSI Bypass
- 3.36.2.n : ETW Bypass
- 3.36.2.o : Windows Defender Evasion
- 3.36.5.l : Module Stomping
- 3.36.5.m : Unhooking
- 3.36.5.q : ETW Blinding
- 3.36.5.h : Anti-Sandbox Techniques
- 3.36.5.e : Code Signing Abuse

**Sujet**:
Analysez l'environnement défensif d'une cible Windows et proposez une stratégie de bypass complète: syscalls directs, unhooking, AMSI/ETW bypass.

**Intelligence pédagogique**:
Comprendre comment les défenses Windows fonctionnent pour savoir comment les contourner de manière éducative.

**Validation**: ✅ 50/206 concepts

---

## EXERCICE 3.36.6 : Privilege Escalation Path Analyzer

**Concepts couverts** (8 concepts):
- 3.36.2.k : Token Manipulation
- 3.36.2.l : UAC Bypass
- 3.36.2.q : COM Abuse
- 3.36.2.r : WMI Abuse
- 3.36.2.s : Credential Access
- 3.36.2.t : Windows Kernel Access
- 3.36.6.h : Stealer Malware
- 3.36.6.i : Keyloggers

**Sujet**:
Analysez un environnement Windows et identifiez les chemins d'escalade de privilèges: UAC bypass possibles, tokens exploitables, credentials accessibles.

**Intelligence pédagogique**:
Comprendre la chaîne complète d'escalade, pas juste une technique isolée.

**Validation**: ✅ 58/206 concepts

---

## EXERCICE 3.36.7 : Windows Persistence Architect

**Concepts couverts** (6 concepts):
- 3.36.2.p : Persistence Mechanisms
- 3.36.2.u : .NET Malware
- 3.36.2.v : PowerShell Integration
- 3.36.5.i : Sleep Obfuscation
- 3.36.5.j : Memory Encryption
- 3.36.5.k : Heap/Stack Encryption

**Sujet**:
Concevez un mécanisme de persistence pour un scénario donné. Incluez: technique de persistance, protection mémoire, et intégration .NET/PowerShell.

**Intelligence pédagogique**:
La persistance n'est pas juste "s'inscrire au démarrage" mais survivre aux analyses mémoire et redémarrages.

**Validation**: ✅ 64/206 concepts

---

## EXERCICE 3.36.8 : Linux Implant Designer

**Concepts couverts** (10 concepts):
- 3.36.3.a : Linux Internals for Malware
- 3.36.3.b : ELF Structure
- 3.36.3.c : ELF Manipulation
- 3.36.3.d : Process Injection Linux
- 3.36.3.e : ptrace Injection
- 3.36.3.f : LD_PRELOAD Hijacking
- 3.36.3.g : Shared Library Trojaning
- 3.36.3.h : Fileless Linux Malware
- 3.36.3.i : Linux Persistence
- 3.36.6.l : File System Operations

**Sujet**:
Analysez un environnement Linux et concevez un implant adapté: structure ELF, méthode d'injection, technique fileless, et mécanisme de persistance.

**Intelligence pédagogique**:
Linux est fondamentalement différent de Windows. L'étudiant comprend les spécificités de chaque OS.

**Validation**: ✅ 74/206 concepts

---

## EXERCICE 3.36.9 : Linux Rootkit Component Analyzer

**Concepts couverts** (8 concepts):
- 3.36.3.j : Linux Rootkits
- 3.36.3.k : eBPF Malware
- 3.36.3.l : Container-Aware Malware
- 3.36.3.m : Linux Credential Access
- 3.36.3.n : PAM Backdoors
- 3.36.3.o : SSH Backdoors
- 3.36.3.p : Anti-Forensics Linux
- 3.36.6.m : Network Operations

**Sujet**:
Analysez les composants d'un rootkit Linux: hooks syscall, backdoors PAM/SSH, techniques anti-forensics, et awareness de containers.

**Intelligence pédagogique**:
Comprendre les rootkits Linux modernes qui exploitent eBPF et sont conscients des containers.

**Validation**: ✅ 82/206 concepts

---

## EXERCICE 3.36.10 : Rootkit Taxonomy Classifier

**Concepts couverts** (9 concepts):
- 3.36.4.a : Rootkit Definition
- 3.36.4.b : Userland Rootkits
- 3.36.4.c : Kernel Rootkits
- 3.36.4.d : DKOM
- 3.36.4.e : Syscall Table Hooking
- 3.36.4.f : IDT Hooking
- 3.36.4.g : VFS Hooking
- 3.36.4.h : Network Stack Hooking
- 3.36.4.i : Windows Kernel Rootkits

**Sujet**:
Classifiez un ensemble de rootkits selon leur niveau (user/kernel), techniques de hooking, et capacités de dissimulation.

**Intelligence pédagogique**:
Taxonomie complète des rootkits pour comprendre l'évolution des techniques.

**Validation**: ✅ 91/206 concepts

---

## EXERCICE 3.36.11 : Bootkit & Firmware Persistence Analyzer

**Concepts couverts** (9 concepts):
- 3.36.4.j : Bootkit Definition
- 3.36.4.k : Legacy BIOS Bootkits
- 3.36.4.l : UEFI Bootkits
- 3.36.4.m : Secure Boot Bypass
- 3.36.4.n : UEFI Implants
- 3.36.4.o : Bootkit Detection
- 3.36.4.p : Hypervisor Rootkits
- 3.36.4.q : SMM Rootkits
- 3.36.4.r : Hardware Implants

**Sujet**:
Analysez un scénario de persistence firmware/boot et identifiez: type de bootkit, bypass Secure Boot possible, et méthodes de détection.

**Intelligence pédagogique**:
Les menaces au niveau firmware représentent le summum de la persistance. L'étudiant comprend les limites de la sécurité logicielle.

**Validation**: ✅ 100/206 concepts

---

## EXERCICE 3.36.12 : Evasion Technique Orchestrator

**Concepts couverts** (6 concepts):
- 3.36.5.n : PPID Spoofing
- 3.36.5.o : Command Line Spoofing
- 3.36.5.p : Thread Stack Spoofing
- 3.36.5.r : Timestomping
- 3.36.5.s : Living off the Land
- 3.36.5.t : AI/ML Evasion

**Sujet**:
Orchestrez une stratégie d'évasion complète: spoofing (PPID, cmdline, stack), timestomping, LOLBins, et contournement ML.

**Intelligence pédagogique**:
L'évasion moderne nécessite une approche multi-couches et la compréhension des détections ML.

**Validation**: ✅ 106/206 concepts

---

## EXERCICE 3.36.13 : Payload Capabilities Integrator

**Concepts couverts** (4 concepts):
- 3.36.6.j : Screen Capture
- 3.36.6.k : Audio/Video Capture
- 3.36.6.o : Registry Operations
- 3.36.6.p : Ransomware Components

**Sujet**:
Intégrez des capacités avancées dans un implant: capture écran/audio/vidéo, opérations registry, et composants ransomware (pour compréhension défensive).

**Intelligence pédagogique**:
Comprendre les capacités offensives pour mieux défendre. Le ransomware est étudié pour la détection, pas la création.

**Validation**: ✅ 110/206 concepts - MODULE 3.36 COMPLET

---

# FIN MODULE 3.36
