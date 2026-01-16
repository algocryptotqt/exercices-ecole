# MODULE 3.36 : Malware Analysis & Defense (Adversary Techniques Understanding)

**Concepts couverts** : 110
**Nombre d'exercices** : 16
**Difficulté** : Expert

---

## Vue d'ensemble

Module consacré à la compréhension approfondie des techniques de malware du point de vue défensif. L'objectif est de former les analystes à comprendre le fonctionnement interne des logiciels malveillants pour améliorer la détection, l'analyse et les défenses. Tous les exercices sont orientés analyse et détection.

**Note** : Ce module est destiné à la formation défensive et à la compréhension des menaces.

---

## EXERCICE 01 : malware_category_classifier

**Concepts couverts** (9 concepts - 3.36.1 a-i) :
- Malware Categories, Development Lifecycle, Language Selection
- Implant Architecture, PIC, API Resolution, String Obfuscation
- Control Flow Obfuscation, Anti-Analysis Basics

**Sujet** : Classificateur de catégories de malware basé sur les caractéristiques comportementales et structurelles.

**Entrée JSON** :
```json
{
  "sample_analysis": {
    "sha256": "abc123...",
    "file_type": "PE32 executable",
    "imports": ["ws2_32.dll", "crypt32.dll", "advapi32.dll"],
    "strings_found": ["cmd.exe", "powershell", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "behaviors": [
      "Creates mutex",
      "Connects to external IP",
      "Modifies registry autorun",
      "Captures keystrokes"
    ]
  },
  "network_indicators": {
    "c2_pattern": "HTTP beacon every 60 seconds",
    "dns_queries": ["update-service.xyz"]
  }
}
```

**Sortie attendue** :
```json
{
  "classification": {
    "primary_category": "RAT (Remote Access Trojan)",
    "secondary_categories": ["Keylogger", "Backdoor"],
    "confidence": "high"
  },
  "capability_analysis": {
    "c2_communication": {
      "detected": true,
      "protocol": "HTTP",
      "pattern": "Beacon-based polling"
    },
    "persistence": {
      "detected": true,
      "mechanism": "Registry Run key"
    },
    "credential_theft": {
      "detected": true,
      "method": "Keystroke logging"
    }
  },
  "technical_characteristics": {
    "language_indicators": {
      "likely_language": "C/C++",
      "evidence": ["PE format", "Native imports"]
    },
    "obfuscation_level": "Medium",
    "anti_analysis": ["Mutex check for single instance"]
  },
  "detection_recommendations": {
    "yara_signatures": ["Match on import combination", "String pattern for C2 domain"],
    "behavioral_rules": ["Monitor for registry persistence + network beacon pattern"],
    "network_indicators": ["Block update-service.xyz", "Detect 60-second HTTP beacon"]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 02 : malware_delivery_chain_analyzer

**Concepts couverts** (9 concepts - 3.36.1 j-r) :
- Payload Delivery, Execution Methods, Configuration Management
- Error Handling, Cross-Platform Considerations, Build Systems
- Testing Malware, Versioning & Updates, Operational Security Dev

**Sujet** : Analyseur de chaîne de livraison de malware pour comprendre les vecteurs d'attaque.

**Entrée JSON** :
```json
{
  "delivery_analysis": {
    "initial_vector": "phishing_email",
    "attachment": {
      "type": "XLSM",
      "macro_present": true,
      "macro_behavior": "Downloads secondary payload"
    },
    "secondary_payload": {
      "type": "PowerShell script",
      "action": "Reflective DLL loading",
      "final_payload": "Cobalt Strike beacon"
    }
  },
  "c2_config_extracted": {
    "servers": ["192.168.1.100", "update-service.com"],
    "fallback_dns": "dns-tunnel.xyz",
    "jitter": "20%"
  }
}
```

**Sortie attendue** :
```json
{
  "attack_chain_mapping": {
    "stage_1_delivery": {
      "vector": "Phishing email with macro document",
      "technique": "T1566.001 - Spearphishing Attachment",
      "detection_point": "Email gateway, Macro execution block"
    },
    "stage_2_execution": {
      "method": "VBA macro → PowerShell",
      "technique": "T1059.001 - PowerShell",
      "detection_point": "AMSI, PowerShell logging"
    },
    "stage_3_installation": {
      "method": "Reflective DLL injection",
      "technique": "T1055.001 - DLL Injection",
      "detection_point": "Memory scanning, API monitoring"
    },
    "stage_4_c2": {
      "framework": "Cobalt Strike",
      "protocol": "HTTPS + DNS fallback",
      "detection_point": "Network monitoring, JA3 fingerprinting"
    }
  },
  "configuration_analysis": {
    "c2_resilience": "Multi-channel (HTTP + DNS)",
    "evasion_features": ["Jitter", "Multiple servers", "Encrypted comms"],
    "operational_maturity": "High - well-configured, multi-fallback"
  },
  "defense_recommendations": {
    "prevention": [
      "Block macro execution in Office",
      "Restrict PowerShell with WDAC",
      "Memory protection (ASR rules)"
    ],
    "detection": [
      "Monitor for macro → PowerShell chain",
      "Detect reflective loading patterns",
      "JA3/JA3S signatures for Cobalt Strike"
    ],
    "hunting": [
      "Hunt for HTTP beacons with jitter",
      "DNS tunnel detection",
      "Memory artifact scanning"
    ]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 03 : windows_injection_detector

**Concepts couverts** (11 concepts - 3.36.2 a-k) :
- Windows Internals, PE File Structure, PE Manipulation
- Process Injection Techniques, Process Hollowing, DLL Injection
- Reflective DLL Injection, Shellcode Injection, Direct Syscalls
- NTAPI Usage, Token Manipulation

**Sujet** : Détecteur de techniques d'injection Windows avec analyse de mémoire.

**Entrée JSON** :
```json
{
  "memory_analysis": {
    "process": "svchost.exe",
    "pid": 1234,
    "suspicious_regions": [
      {
        "address": "0x7FFE0000",
        "size": 65536,
        "protection": "RWX",
        "mapped_file": null,
        "entropy": 7.2
      }
    ],
    "thread_analysis": {
      "threads": 15,
      "suspicious_start_addresses": ["0x7FFE0100 - not in any module"]
    }
  },
  "api_calls_observed": {
    "ntdll_direct_calls": true,
    "syscall_instructions": ["syscall at 0x7FFE0120"]
  }
}
```

**Sortie attendue** :
```json
{
  "injection_detection": {
    "verdict": "MALICIOUS - Process injection detected",
    "confidence": "high",
    "technique_identified": "Shellcode injection with direct syscalls"
  },
  "evidence_analysis": {
    "rwx_memory": {
      "finding": "Executable region not backed by file",
      "indicator": "Classic shellcode injection pattern",
      "false_positive_likelihood": "Low"
    },
    "thread_origin": {
      "finding": "Thread executing from unbacked memory",
      "indicator": "Thread hijacking or CreateRemoteThread",
      "module_resolution": "No legitimate module at start address"
    },
    "syscall_usage": {
      "finding": "Direct syscall instructions detected",
      "indicator": "Attempt to bypass usermode hooks",
      "technique": "Likely using SysWhispers or similar"
    },
    "entropy_analysis": {
      "finding": "High entropy (7.2) in executable region",
      "indicator": "Compressed or encrypted code"
    }
  },
  "technique_mapping": {
    "mitre_techniques": [
      "T1055.012 - Process Hollowing (if applicable)",
      "T1055.001 - DLL Injection",
      "T1106 - Native API"
    ],
    "evasion_methods": ["Direct syscalls", "Unbacked executable memory"]
  },
  "detection_guidance": {
    "memory_forensics": [
      "Dump suspicious region for analysis",
      "Check for PE header patterns",
      "Analyze for shellcode signatures"
    ],
    "defensive_measures": [
      "Enable memory integrity monitoring",
      "Deploy EDR with memory protection",
      "Monitor for RWX region creation"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 04 : windows_defense_evasion_analyzer

**Concepts couverts** (11 concepts - 3.36.2 l-v) :
- UAC Bypass, AMSI Bypass, ETW Bypass
- Windows Defender Evasion, Persistence Mechanisms, COM Abuse
- WMI Abuse, Credential Access, Windows Kernel Access
- .NET Malware, PowerShell Integration

**Sujet** : Analyseur de techniques d'évasion Windows pour améliorer les défenses.

**Entrée JSON** :
```json
{
  "evasion_artifacts": {
    "amsi_state": {
      "amsi_dll_loaded": true,
      "amsiscanbuffer_patched": true,
      "patch_pattern": "0x80 0x07 at offset 0x1234"
    },
    "etw_state": {
      "nttracevent_patched": true,
      "providers_disabled": ["Microsoft-Windows-Security-Auditing"]
    },
    "defender_exclusions": {
      "paths_excluded": ["C:\\ProgramData\\Microsoft\\Cache"]
    }
  },
  "persistence_artifacts": {
    "com_hijacking": {
      "clsid": "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
      "original_path": "C:\\Windows\\System32\\shell32.dll",
      "hijacked_path": "C:\\ProgramData\\Microsoft\\Cache\\update.dll"
    },
    "wmi_subscription": {
      "event_filter": "__InstanceModificationEvent",
      "consumer": "CommandLineEventConsumer",
      "binding": true
    }
  }
}
```

**Sortie attendue** :
```json
{
  "evasion_analysis": {
    "amsi_bypass": {
      "detected": true,
      "technique": "AmsiScanBuffer patching",
      "impact": "PowerShell/VBA malware can execute undetected",
      "remediation": "Restart affected processes, check for tampering"
    },
    "etw_bypass": {
      "detected": true,
      "technique": "NtTraceEvent patching + provider disabling",
      "impact": "Security logging disabled, blind spot for defenders",
      "remediation": "Compare ETW state with baseline, restore providers"
    },
    "defender_manipulation": {
      "detected": true,
      "technique": "Exclusion path abuse",
      "impact": "Malware hidden in excluded paths",
      "remediation": "Review and remove unauthorized exclusions"
    }
  },
  "persistence_analysis": {
    "com_hijacking": {
      "detected": true,
      "severity": "high",
      "mechanism": "CLSID points to malicious DLL",
      "loaded_by": "Any process using this COM object",
      "remediation": "Remove hijacked registry key, delete malicious DLL"
    },
    "wmi_persistence": {
      "detected": true,
      "severity": "high",
      "mechanism": "WMI event subscription",
      "trigger": "System events",
      "remediation": "Remove WMI subscription (filter, consumer, binding)"
    }
  },
  "defense_improvements": {
    "monitoring": [
      "Monitor for AMSI/ETW patching (function hooks)",
      "Track Defender exclusion changes",
      "Monitor COM object registration changes",
      "Audit WMI subscriptions"
    ],
    "prevention": [
      "Tamper protection enabled",
      "Restrict exclusion modification",
      "WMI subscription monitoring"
    ],
    "detection_rules": [
      "SIGMA: Detect AMSI bypass via patching",
      "SIGMA: Detect ETW tampering",
      "SIGMA: Suspicious WMI subscription creation"
    ]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 05 : linux_malware_analyzer

**Concepts couverts** (8 concepts - 3.36.3 a-h) :
- Linux Internals for Malware, ELF Structure, ELF Manipulation
- Process Injection Linux, ptrace Injection, LD_PRELOAD Hijacking
- Shared Library Trojaning, Fileless Linux Malware

**Sujet** : Analyseur de malware Linux avec détection de techniques d'injection.

**Entrée JSON** :
```json
{
  "system_analysis": {
    "suspicious_processes": [
      {
        "pid": 4567,
        "name": "systemd-daemon",
        "cmdline": "/usr/lib/systemd/systemd-daemon",
        "binary_exists": false,
        "memory_mapped_files": ["[heap]", "[stack]", "anon_inode"]
      }
    ],
    "ld_preload": {
      "env_value": "/tmp/.hidden/libhook.so",
      "ld_so_preload": "/tmp/.hidden/libhook.so"
    },
    "proc_analysis": {
      "pid_4567": {
        "exe_link": "/memfd:exec (deleted)",
        "maps_suspicious": ["0x7f0000000000-0x7f0000001000 r-xp 00000000 00:00 0"]
      }
    }
  }
}
```

**Sortie attendue** :
```json
{
  "malware_detection": {
    "verdict": "MALICIOUS - Linux fileless malware detected",
    "techniques_detected": ["Fileless execution", "LD_PRELOAD hijacking"]
  },
  "fileless_analysis": {
    "process_4567": {
      "indicator": "Executing from memfd (deleted)",
      "technique": "memfd_create for fileless execution",
      "impact": "Malware runs entirely in memory",
      "binary_on_disk": "None - fileless"
    },
    "memory_execution": {
      "anonymous_mapping": "Executable anonymous memory detected",
      "technique": "T1620 - Reflective Code Loading"
    }
  },
  "ld_preload_analysis": {
    "hijacking_detected": true,
    "malicious_library": "/tmp/.hidden/libhook.so",
    "mechanism": "Both LD_PRELOAD env and /etc/ld.so.preload",
    "impact": "All processes load malicious library",
    "hooked_functions": "Likely: open, read, readdir (for hiding)"
  },
  "forensic_steps": {
    "immediate": [
      "Dump memory of PID 4567",
      "Copy /tmp/.hidden/libhook.so for analysis",
      "Check /etc/ld.so.preload contents"
    ],
    "analysis": [
      "Analyze memfd contents from memory dump",
      "Reverse engineer libhook.so",
      "Identify hooked functions"
    ],
    "remediation": [
      "Kill malicious process",
      "Remove malicious ld.so.preload entry",
      "Delete malicious library",
      "Check for persistence mechanisms"
    ]
  },
  "detection_improvements": {
    "monitoring": [
      "Monitor for memfd_create syscall",
      "Track ld.so.preload modifications",
      "Alert on LD_PRELOAD environment variable"
    ],
    "hardening": [
      "Restrict memfd_create with seccomp",
      "File integrity monitoring on ld.so.preload",
      "AppArmor/SELinux for library loading"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 06 : linux_persistence_hunter

**Concepts couverts** (8 concepts - 3.36.3 i-p) :
- Linux Persistence, Linux Rootkits, eBPF Malware
- Container-Aware Malware, Linux Credential Access, PAM Backdoors
- SSH Backdoors, Anti-Forensics Linux

**Sujet** : Chasseur de persistance Linux avec analyse des mécanismes de backdoor.

**Entrée JSON** :
```json
{
  "persistence_scan": {
    "cron": {
      "/var/spool/cron/crontabs/root": "* * * * * /dev/shm/.update"
    },
    "systemd": {
      "suspicious_services": ["update-helper.service"],
      "service_file": {
        "ExecStart": "/usr/local/bin/update-helper",
        "binary_analysis": "Static binary, stripped, connects to external IP"
      }
    },
    "pam": {
      "modified_modules": ["pam_unix.so"],
      "modification_date": "2024-01-15",
      "original_hash_mismatch": true
    },
    "ssh": {
      "authorized_keys_additions": ["ssh-rsa AAAA... unknown@unknown"],
      "sshd_modifications": false
    },
    "kernel": {
      "loaded_modules": ["rootkit_lkm"],
      "hidden_processes_suspected": true
    }
  }
}
```

**Sortie attendue** :
```json
{
  "persistence_findings": {
    "severity": "CRITICAL - Multiple persistence mechanisms detected"
  },
  "cron_persistence": {
    "detected": true,
    "location": "/var/spool/cron/crontabs/root",
    "frequency": "Every minute",
    "payload": "/dev/shm/.update",
    "technique": "T1053.003 - Cron",
    "note": "Payload in /dev/shm (tmpfs) indicates memory-only malware"
  },
  "systemd_persistence": {
    "detected": true,
    "service": "update-helper.service",
    "analysis": "Suspicious binary with C2 communication",
    "technique": "T1543.002 - Systemd Service"
  },
  "pam_backdoor": {
    "detected": true,
    "severity": "CRITICAL",
    "modified_module": "pam_unix.so",
    "impact": "Authentication bypass or credential capture possible",
    "technique": "T1556.003 - Pluggable Authentication Modules",
    "remediation": "Replace with known-good PAM module from package"
  },
  "ssh_backdoor": {
    "detected": true,
    "type": "Authorized key addition",
    "unauthorized_key": "Unknown origin",
    "technique": "T1098.004 - SSH Authorized Keys"
  },
  "rootkit_detection": {
    "detected": true,
    "evidence": "Unknown kernel module 'rootkit_lkm'",
    "indicators": "Hidden processes suspected",
    "technique": "T1014 - Rootkit",
    "analysis_required": "Memory forensics needed"
  },
  "remediation_priority": [
    {"priority": 1, "action": "Remove rootkit LKM (requires reboot to clean)", "risk": "System may be unstable"},
    {"priority": 2, "action": "Replace PAM modules from trusted source"},
    {"priority": 3, "action": "Remove unauthorized SSH keys"},
    {"priority": 4, "action": "Delete malicious cron entry and systemd service"},
    {"priority": 5, "action": "Full system rebuild recommended given rootkit presence"}
  ]
}
```

**Barème** : 97/100

---

## EXERCICE 07 : rootkit_behavior_analyzer

**Concepts couverts** (9 concepts - 3.36.4 a-i) :
- Rootkit Definition, Userland Rootkits, Kernel Rootkits
- DKOM, Syscall Table Hooking, IDT Hooking
- VFS Hooking, Network Stack Hooking, Windows Kernel Rootkits

**Sujet** : Analyseur de comportement de rootkit avec détection de hooks.

**Entrée JSON** :
```json
{
  "system_state": {
    "os": "Windows",
    "analysis_type": "memory_forensics"
  },
  "memory_analysis": {
    "ssdt_hooks": [
      {"index": 74, "function": "NtQueryDirectoryFile", "original": "ntoskrnl.exe", "hooked_to": "unknown_driver.sys"}
    ],
    "dkom_indicators": {
      "process_list_gaps": true,
      "hidden_pids": [8888, 9999],
      "eprocess_unlinking_detected": true
    },
    "driver_analysis": {
      "suspicious_driver": "unknown_driver.sys",
      "load_address": "0xFFFF0000",
      "signed": false,
      "callbacks_registered": ["PsSetCreateProcessNotifyRoutine", "CmRegisterCallback"]
    }
  },
  "network_hooks": {
    "tdi_filter": true,
    "ndis_filter": true,
    "hidden_connections_suspected": true
  }
}
```

**Sortie attendue** :
```json
{
  "rootkit_analysis": {
    "verdict": "CONFIRMED - Kernel rootkit active",
    "type": "Windows kernel-mode rootkit",
    "stealth_level": "Advanced"
  },
  "hook_analysis": {
    "ssdt_hooks": {
      "detected": true,
      "hooked_functions": ["NtQueryDirectoryFile"],
      "purpose": "Hide files from directory listings",
      "impact": "Files invisible to user and most security tools"
    },
    "dkom_manipulation": {
      "detected": true,
      "technique": "EPROCESS list unlinking",
      "hidden_processes": [8888, 9999],
      "impact": "Processes invisible in Task Manager and APIs"
    },
    "kernel_callbacks": {
      "detected": true,
      "callbacks": ["Process creation notification", "Registry monitoring"],
      "impact": "Rootkit can monitor/filter all process creation and registry access"
    }
  },
  "network_hiding": {
    "tdi_hook": {"detected": true, "impact": "Can hide network connections"},
    "ndis_hook": {"detected": true, "impact": "Can filter packets at driver level"},
    "hidden_connections": "Likely - hooks in place to hide network activity"
  },
  "detection_methodology": {
    "cross_view_detection": "Compare API results vs direct memory parsing",
    "hook_detection": "Compare current SSDT with clean reference",
    "driver_verification": "Check all loaded drivers against known-good baseline"
  },
  "remediation": {
    "immediate": "Do not trust running system - boot from external media",
    "forensics": "Capture memory dump for offline analysis",
    "clean_boot": "Boot from trusted media, scan disk offline",
    "reinstall": "Full OS reinstall recommended for kernel rootkit"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 08 : bootkit_forensic_analyzer

**Concepts couverts** (9 concepts - 3.36.4 j-r) :
- Bootkit Definition, Legacy BIOS Bootkits, UEFI Bootkits
- Secure Boot Bypass, UEFI Implants, Bootkit Detection
- Hypervisor Rootkits, SMM Rootkits, Hardware Implants

**Sujet** : Analyseur forensique de bootkit avec vérification d'intégrité du firmware.

**Entrée JSON** :
```json
{
  "boot_analysis": {
    "firmware_type": "UEFI",
    "secure_boot": {
      "enabled": true,
      "status": "Secure Boot violation detected"
    },
    "efi_partition": {
      "suspicious_files": [
        {"path": "\\EFI\\Microsoft\\Boot\\grubx64.efi", "not_signed": true, "hash_unknown": true}
      ]
    },
    "firmware_analysis": {
      "spi_flash_modified": true,
      "dxe_drivers": ["Unknown DXE driver at 0x1000000"]
    },
    "measurements": {
      "pcr_values_mismatch": true,
      "tpm_event_log": ["Unexpected code measurement"]
    }
  }
}
```

**Sortie attendue** :
```json
{
  "bootkit_analysis": {
    "verdict": "CRITICAL - UEFI bootkit detected",
    "persistence_type": "Firmware-level",
    "survival": "Survives OS reinstall, possibly disk replacement"
  },
  "uefi_infection": {
    "secure_boot_bypass": {
      "detected": true,
      "method": "Malicious bootloader in EFI partition",
      "technique": "Similar to BlackLotus"
    },
    "esp_compromise": {
      "malicious_files": ["grubx64.efi - unsigned, unknown hash"],
      "impact": "Executes before OS, complete system control"
    },
    "firmware_modification": {
      "spi_flash_tampered": true,
      "dxe_driver_injection": true,
      "impact": "Persistence even after disk wipe"
    }
  },
  "measurement_analysis": {
    "pcr_mismatch": {
      "detected": true,
      "meaning": "Boot chain integrity violated",
      "attestation": "Remote attestation would fail"
    },
    "tpm_events": {
      "anomaly": "Unexpected code measured during boot",
      "indication": "Bootkit executed and was measured"
    }
  },
  "threat_classification": {
    "sophistication": "Nation-state level",
    "similar_threats": ["LoJax", "MosaicRegressor", "BlackLotus"],
    "target_type": "High-value persistent access"
  },
  "remediation_steps": {
    "priority_1": "Isolate system immediately",
    "priority_2": "Do NOT simply reinstall OS - bootkit survives",
    "priority_3": "Reflash firmware from known-good image",
    "priority_4": "Replace disk as SPI flash may be compromised",
    "priority_5": "Verify new firmware measurements",
    "priority_6": "Consider hardware replacement if SMM compromise suspected"
  },
  "detection_improvements": {
    "recommendations": [
      "Enable Secure Boot with custom keys",
      "Deploy firmware integrity monitoring",
      "Use TPM attestation regularly",
      "UEFI capsule update validation"
    ]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 09 : evasion_technique_detector

**Concepts couverts** (10 concepts - 3.36.5 a-j) :
- Signature Evasion, Packers & Crypters, Polymorphic Code
- Metamorphic Code, Code Signing Abuse, Anti-Debug Techniques
- Anti-VM Techniques, Anti-Sandbox Techniques, Sleep Obfuscation, Memory Encryption

**Sujet** : Détecteur de techniques d'évasion avec contre-mesures.

**Entrée JSON** :
```json
{
  "sample_behavior": {
    "execution_environment_checks": [
      {"check": "IsDebuggerPresent", "result": "Called and acted on result"},
      {"check": "CPUID vendor string", "result": "Checked for VMware/VirtualBox"},
      {"check": "GetTickCount timing", "result": "Measured execution delay"}
    ],
    "anti_analysis_behaviors": {
      "code_modification": true,
      "self_decryption": true,
      "sleep_encryption": true
    },
    "signature_info": {
      "packed": true,
      "entropy": 7.8,
      "packer_detected": "Custom",
      "layers": 3
    }
  },
  "dynamic_analysis_result": {
    "execution_in_vm": "Terminated early",
    "execution_on_bare_metal": "Full execution"
  }
}
```

**Sortie attendue** :
```json
{
  "evasion_analysis": {
    "sophistication": "High - Multiple evasion layers"
  },
  "anti_analysis_techniques": {
    "anti_debug": {
      "techniques_detected": ["IsDebuggerPresent", "Timing checks"],
      "evasion_method": "Terminates or alters behavior under debugging",
      "bypass": "Patch IsDebuggerPresent return, use kernel debugger"
    },
    "anti_vm": {
      "techniques_detected": ["CPUID vendor check", "VM artifacts"],
      "targeted_environments": ["VMware", "VirtualBox"],
      "bypass": "Modify VM artifacts, use bare-metal or hardened VM"
    },
    "anti_sandbox": {
      "techniques_detected": ["Timing analysis"],
      "behavior": "Detects accelerated execution",
      "bypass": "Real-time sandbox, longer execution"
    }
  },
  "packing_analysis": {
    "packed": true,
    "layers": 3,
    "entropy": "Very high (7.8) indicates encryption",
    "unpacking_approach": [
      "Run until OEP reached",
      "Dump memory after each layer",
      "Analyze each unpacked stage"
    ]
  },
  "advanced_evasion": {
    "sleep_obfuscation": {
      "detected": true,
      "technique": "Encrypts memory during sleep (Ekko-like)",
      "impact": "Memory scanning during sleep ineffective",
      "bypass": "Catch before sleep, scan during activity"
    },
    "polymorphic_behavior": {
      "detected": true,
      "indication": "Code modification during execution",
      "impact": "Static signatures fail"
    }
  },
  "analysis_recommendations": {
    "environment_setup": [
      "Use bare-metal analysis or hardened VM",
      "Disable timing-based detection",
      "Patch anti-debug checks"
    ],
    "tools": [
      "x64dbg with anti-anti-debug plugins",
      "Unpacking scripts for custom packers",
      "Memory dumping during execution"
    ],
    "detection_strategy": [
      "Behavior-based detection",
      "Memory pattern scanning during activity",
      "API call sequence analysis"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 10 : advanced_evasion_analyzer

**Concepts couverts** (10 concepts - 3.36.5 k-t) :
- Heap/Stack Encryption, Module Stomping, Unhooking
- PPID Spoofing, Command Line Spoofing, Thread Stack Spoofing
- ETW Blinding, Timestomping, Living off the Land, AI/ML Evasion

**Sujet** : Analyseur de techniques d'évasion avancées avec détection.

**Entrée JSON** :
```json
{
  "process_analysis": {
    "process": "notepad.exe",
    "ppid": 4,
    "expected_ppid": "explorer.exe",
    "ppid_mismatch": true,
    "commandline": "",
    "commandline_at_creation": "powershell.exe -enc Base64...",
    "commandline_spoofed": true
  },
  "memory_indicators": {
    "ntdll_integrity": {
      "checksum_match": true,
      "freshly_loaded": true,
      "note": "ntdll appears unhooked"
    },
    "module_anomalies": {
      "module": "msvcp140.dll",
      "content_mismatch": true,
      "original_code": false
    }
  },
  "etw_status": {
    "key_providers_disabled": true,
    "etwwrite_patched": true
  },
  "filesystem": {
    "suspicious_files": [
      {"path": "C:\\Windows\\System32\\cmd.exe", "timestamp": "2019-03-01", "create_time_suspicious": true}
    ]
  }
}
```

**Sortie attendue** :
```json
{
  "advanced_evasion_detection": {
    "verdict": "MALICIOUS - Multiple advanced evasion techniques active"
  },
  "ppid_spoofing": {
    "detected": true,
    "evidence": "notepad.exe with PPID=4 (System) instead of explorer.exe",
    "technique": "CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
    "purpose": "Evade parent-child process analysis",
    "detection": "Compare PPID with expected for process type"
  },
  "commandline_spoofing": {
    "detected": true,
    "evidence": "Empty commandline, original was encoded PowerShell",
    "technique": "PEB commandline modification after creation",
    "purpose": "Evade commandline logging and analysis",
    "detection": "Capture commandline at creation (ETW), compare with current"
  },
  "unhooking": {
    "detected": true,
    "evidence": "Clean ntdll loaded (no EDR hooks)",
    "technique": "Load fresh ntdll from disk or KnownDlls",
    "purpose": "Bypass usermode security hooks",
    "detection": "Monitor for additional ntdll loads, syscall detection"
  },
  "module_stomping": {
    "detected": true,
    "evidence": "msvcp140.dll contents don't match expected code",
    "technique": "Overwrite legitimate module with malicious code",
    "purpose": "Execute from legitimate module context",
    "detection": "Module integrity validation, memory scanning"
  },
  "etw_blinding": {
    "detected": true,
    "evidence": "Key ETW providers disabled, EtwEventWrite patched",
    "impact": "Security event logging compromised",
    "detection": "Monitor for ETW configuration changes"
  },
  "timestomping": {
    "detected": true,
    "evidence": "cmd.exe with 2019 timestamp (OS installed 2023)",
    "purpose": "Blend malware with legitimate system files",
    "detection": "Compare timestamps with $MFT, USN journal"
  },
  "hunting_queries": {
    "ppid_spoofing": "Process where parent.name != expected AND ppid = 4",
    "unhooking": "LoadLibrary(ntdll) OR file access to ntdll.dll",
    "module_integrity": "Memory hash != disk hash for loaded modules"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 11 : shellcode_analyzer

**Concepts couverts** (8 concepts - 3.36.6 a-h) :
- Shellcode Design, Shellcode Encoding, Stagers
- Stageless Payloads, Droppers, Loaders
- RAT Features, Stealer Malware

**Sujet** : Analyseur de shellcode et payloads avec extraction de configurations.

**Entrée JSON** :
```json
{
  "shellcode_sample": {
    "size": 892,
    "position_independent": true,
    "null_bytes": 0,
    "encoded": true,
    "encoder": "shikata_ga_nai"
  },
  "decoded_analysis": {
    "api_resolution": {
      "method": "Hash-based",
      "functions_resolved": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "WinHttpOpen"]
    },
    "behavior": {
      "type": "Stager",
      "download_url": "https://c2server.com/stage2.bin",
      "execution_method": "VirtualAlloc + CreateThread"
    }
  },
  "stage2_analysis": {
    "type": "RAT",
    "features": ["Shell", "FileManager", "ScreenCapture", "Keylogger"],
    "c2_config": {
      "servers": ["192.168.1.100:443"],
      "protocol": "HTTPS",
      "beacon_interval": 30
    }
  }
}
```

**Sortie attendue** :
```json
{
  "shellcode_analysis": {
    "type": "Staged shellcode with RAT payload",
    "sophistication": "Medium-High"
  },
  "stage1_analysis": {
    "design": {
      "position_independent": true,
      "null_free": true,
      "purpose": "Download and execute stage 2"
    },
    "encoding": {
      "encoder": "shikata_ga_nai (polymorphic XOR)",
      "layers": "Multiple iterations",
      "detection_challenge": "Each instance unique"
    },
    "api_resolution": {
      "technique": "Hash-based API resolution",
      "hash_algorithm": "Likely ROR13 or custom",
      "apis_used": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "WinHttpOpen"]
    },
    "behavior": {
      "network_call": "HTTPS download of stage 2",
      "memory_allocation": "RWX with VirtualAlloc",
      "execution": "New thread for stage 2"
    }
  },
  "stage2_analysis": {
    "type": "Full-featured RAT",
    "capabilities": {
      "remote_shell": true,
      "file_management": true,
      "screen_capture": true,
      "keylogging": true
    },
    "c2_configuration": {
      "servers": ["192.168.1.100:443"],
      "protocol": "HTTPS",
      "beacon_interval_seconds": 30,
      "encryption": "Likely TLS"
    }
  },
  "detection_strategies": {
    "network": [
      "Block IOC: 192.168.1.100",
      "Block IOC: c2server.com",
      "Detect staged download pattern"
    ],
    "host": [
      "Detect VirtualAlloc + CreateThread pattern",
      "Monitor for hash-based API resolution",
      "Detect shikata_ga_nai decoder stub"
    ],
    "signatures": [
      "YARA: Shikata decoder pattern",
      "YARA: Hash-based API resolution",
      "YARA: Common RAT strings"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 12 : specialized_malware_analyzer

**Concepts couverts** (8 concepts - 3.36.6 i-p) :
- Keyloggers, Screen Capture, Audio/Video Capture
- File System Operations, Network Operations, Process Operations
- Registry Operations, Ransomware Components

**Sujet** : Analyseur de fonctionnalités spécialisées de malware.

**Entrée JSON** :
```json
{
  "malware_sample": {
    "type": "Ransomware",
    "name": "PHANTOM_LOCK"
  },
  "capability_analysis": {
    "encryption": {
      "algorithm": "AES-256-CBC + RSA-2048",
      "key_generation": "CryptGenRandom",
      "key_storage": "RSA-encrypted AES key in ransom note"
    },
    "file_targeting": {
      "extensions": [".docx", ".xlsx", ".pdf", ".jpg", ".sql", ".bak"],
      "excluded": ["C:\\Windows", "C:\\Program Files"],
      "encrypted_extension": ".phantom"
    },
    "anti_recovery": {
      "shadow_copies": "vssadmin delete shadows /all /quiet",
      "recycle_bin": "Emptied",
      "backup_services": "Stopped"
    },
    "ransom_note": {
      "filename": "README_PHANTOM.txt",
      "content": "Your files have been encrypted...",
      "payment": "Bitcoin to address bc1q..."
    }
  }
}
```

**Sortie attendue** :
```json
{
  "ransomware_analysis": {
    "name": "PHANTOM_LOCK",
    "threat_level": "HIGH"
  },
  "encryption_analysis": {
    "symmetric": {
      "algorithm": "AES-256-CBC",
      "key_generation": "CryptGenRandom (CSPRNG)",
      "per_file_key": "Likely unique key per file"
    },
    "asymmetric": {
      "algorithm": "RSA-2048",
      "usage": "Encrypt AES keys",
      "public_key": "Embedded in malware",
      "private_key": "Held by attacker"
    },
    "recovery_without_key": "Infeasible - proper cryptographic implementation"
  },
  "targeting_behavior": {
    "file_extensions": "Targets documents, databases, backups",
    "exclusions": "Avoids system files to maintain usability",
    "encryption_marker": ".phantom extension"
  },
  "anti_recovery_measures": {
    "volume_shadow_copies": {
      "deleted": true,
      "command": "vssadmin delete shadows /all /quiet",
      "impact": "System Restore points destroyed"
    },
    "recycle_bin": "Emptied - recent deletions unrecoverable",
    "backup_services": "Stopped to prevent new backups"
  },
  "ioc_extraction": {
    "file_iocs": ["README_PHANTOM.txt", "*.phantom"],
    "bitcoin_address": "bc1q...",
    "behavioral_iocs": [
      "Mass file encryption",
      "vssadmin execution",
      "Service stop commands"
    ]
  },
  "recovery_options": {
    "with_key": "Decryption tool possible if keys obtained",
    "without_key": "Restore from offline backups only",
    "partial_recovery": "Check for free decryptors, may have implementation flaws"
  },
  "prevention_measures": {
    "technical": [
      "Immutable backups (air-gapped or WORM)",
      "Endpoint protection with anti-ransomware",
      "Application whitelisting"
    ],
    "monitoring": [
      "Detect mass file modifications",
      "Alert on shadow copy deletion",
      "Monitor for encryption patterns"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 13 : malware_family_profiler

**Concepts couverts** (Synthèse - Family analysis) :
- Code similarity, Infrastructure patterns, TTP mapping

**Sujet** : Profileur de famille de malware avec analyse de lignée.

**Entrée JSON** :
```json
{
  "samples": [
    {"sha256": "abc123", "first_seen": "2023-01", "compile_time": "2023-01-05"},
    {"sha256": "def456", "first_seen": "2023-06", "compile_time": "2023-05-20"},
    {"sha256": "ghi789", "first_seen": "2024-01", "compile_time": "2023-12-15"}
  ],
  "code_analysis": {
    "shared_functions": 45,
    "unique_to_each": [3, 8, 12],
    "code_similarity": {"abc-def": 0.85, "def-ghi": 0.78, "abc-ghi": 0.72}
  },
  "infrastructure": {
    "shared_c2_patterns": true,
    "domain_theme": "update-service-*",
    "hosting_preference": "Eastern European bulletproof"
  }
}
```

**Sortie attendue** :
```json
{
  "family_profile": {
    "family_name": "PHANTOM_RAT",
    "samples_analyzed": 3,
    "active_period": "2023-01 to present"
  },
  "evolution_analysis": {
    "lineage": [
      {"version": "1.0", "sample": "abc123", "date": "2023-01", "features": "Base RAT"},
      {"version": "1.5", "sample": "def456", "date": "2023-06", "features": "Added evasion"},
      {"version": "2.0", "sample": "ghi789", "date": "2024-01", "features": "New C2 protocol"}
    ],
    "development_pattern": "Active development, regular updates",
    "sophistication_trend": "Increasing"
  },
  "code_similarity_analysis": {
    "core_codebase": "45 shared functions form stable core",
    "evolution": "Each version adds unique functions",
    "developer_pattern": "Same development team likely"
  },
  "infrastructure_profile": {
    "c2_patterns": {
      "domain_naming": "update-service-* theme",
      "hosting": "Eastern European bulletproof providers",
      "consistency": "High - same operational patterns"
    },
    "attribution_indicators": [
      "Consistent infrastructure choices",
      "Timezone patterns in compile times",
      "Development cadence"
    ]
  },
  "ttp_mapping": {
    "consistent_across_versions": [
      "T1566 - Phishing for delivery",
      "T1055 - Process injection",
      "T1071 - HTTP C2"
    ],
    "evolved_techniques": [
      "T1055.012 added in v1.5",
      "T1071.004 (DNS) added in v2.0"
    ]
  },
  "detection_strategy": {
    "static_signatures": "Target shared code functions",
    "behavioral": "Focus on consistent TTPs",
    "infrastructure": "Block known domain patterns and hosting"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 14 : malware_triage_system

**Concepts couverts** (Synthèse - Automated triage) :
- Rapid classification, Priority assessment, Defense recommendations

**Sujet** : Système de triage automatique de malware pour SOC.

**Entrée JSON** :
```json
{
  "submission": {
    "source": "Email gateway quarantine",
    "file_type": "PE32 DLL",
    "size_bytes": 245760,
    "submitter": "SOC_analyst"
  },
  "static_analysis": {
    "entropy": 7.1,
    "imports": ["VirtualAlloc", "CreateRemoteThread", "WinHttpOpen"],
    "exports": ["DllRegisterServer"],
    "strings_suspicious": ["cmd.exe", "powershell", "HKCU\\Software\\Microsoft\\Windows"],
    "packer": "None detected",
    "signed": false
  },
  "sandbox_results": {
    "execution_time": 120,
    "network_connections": ["185.xxx.xxx.1:443"],
    "files_created": ["C:\\ProgramData\\update.dat"],
    "registry_modified": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "processes_spawned": ["cmd.exe", "powershell.exe"]
  }
}
```

**Sortie attendue** :
```json
{
  "triage_result": {
    "verdict": "MALICIOUS",
    "confidence": "HIGH (95%)",
    "priority": "P1 - Immediate action required",
    "category": "Backdoor/RAT"
  },
  "classification_details": {
    "primary_type": "Backdoor",
    "sub_type": "DLL-based implant with persistence",
    "threat_level": "HIGH"
  },
  "key_indicators": {
    "execution": {
      "injection_apis": true,
      "note": "VirtualAlloc + CreateRemoteThread indicates injection"
    },
    "persistence": {
      "detected": true,
      "mechanism": "Registry Run key",
      "location": "HKCU autorun"
    },
    "c2_communication": {
      "detected": true,
      "destination": "185.xxx.xxx.1:443",
      "protocol": "HTTPS likely"
    },
    "spawn_behavior": {
      "cmd_exe": true,
      "powershell": true,
      "note": "Command execution capability"
    }
  },
  "iocs_extracted": {
    "network": ["185.xxx.xxx.1:443"],
    "file": ["C:\\ProgramData\\update.dat", "original_sample_hash"],
    "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\update"]
  },
  "immediate_actions": {
    "block": ["185.xxx.xxx.1 at firewall"],
    "hunt": ["Search for update.dat across environment", "Check for registry persistence"],
    "contain": ["Isolate any hosts with connections to IOC"]
  },
  "next_steps": {
    "priority_1": "Deploy IOC blocks organization-wide",
    "priority_2": "Hunt for indicators across all endpoints",
    "priority_3": "Detailed analysis for full capability assessment",
    "priority_4": "Update detection rules"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 15 : malware_defense_architect

**Concepts couverts** (Synthèse - Defense design) :
- Defense-in-depth against malware, Detection layering

**Sujet** : Architecte de défenses anti-malware avec conception multi-couches.

**Entrée JSON** :
```json
{
  "organization": {
    "type": "Financial institution",
    "endpoints": 10000,
    "critical_systems": ["Core banking", "Trading platform", "Customer data"]
  },
  "current_defenses": {
    "endpoint_protection": "Legacy AV",
    "email_security": "Basic spam filter",
    "network_security": "Perimeter firewall only"
  },
  "threat_profile": {
    "primary_threats": ["Ransomware", "Banking trojans", "APT"],
    "recent_incidents": ["Phishing attempt blocked", "Suspicious DLL on endpoint"]
  }
}
```

**Sortie attendue** :
```json
{
  "defense_architecture": {
    "maturity_assessment": {
      "current": "Level 1 - Basic",
      "target": "Level 4 - Advanced",
      "timeline": "12 months"
    }
  },
  "layered_defense_design": {
    "layer_1_prevention": {
      "email_security": {
        "upgrade": "Advanced email protection with sandboxing",
        "features": ["Attachment detonation", "URL rewriting", "Impersonation protection"],
        "protection": "Block malware at entry point"
      },
      "endpoint_protection": {
        "upgrade": "Next-gen AV with EDR",
        "features": ["Behavioral detection", "Memory protection", "Exploit prevention"],
        "protection": "Block execution of known and unknown malware"
      }
    },
    "layer_2_detection": {
      "edr": {
        "deploy": "Full EDR on all endpoints",
        "features": ["Process monitoring", "Memory scanning", "Threat hunting"],
        "detection": "Identify malicious behavior post-execution"
      },
      "network_detection": {
        "deploy": "NDR/IDS",
        "features": ["C2 detection", "Lateral movement", "Data exfiltration"],
        "detection": "Catch network-based indicators"
      }
    },
    "layer_3_response": {
      "siem": {
        "deploy": "Centralized SIEM",
        "features": ["Correlation", "Alerting", "Forensic log retention"],
        "capability": "Centralized visibility and response"
      },
      "soar": {
        "deploy": "Automated response playbooks",
        "features": ["IOC blocking", "Endpoint isolation", "Alert enrichment"],
        "capability": "Rapid automated response"
      }
    },
    "layer_4_resilience": {
      "backups": {
        "implement": "Immutable backup strategy",
        "features": ["Air-gapped", "Tested restoration", "3-2-1 rule"],
        "protection": "Ransomware recovery capability"
      },
      "segmentation": {
        "implement": "Network microsegmentation",
        "features": ["Critical system isolation", "Lateral movement restriction"],
        "protection": "Limit blast radius"
      }
    }
  },
  "specific_threat_countermeasures": {
    "ransomware": [
      "Immutable backups",
      "Controlled folder access",
      "Anti-ransomware behavioral detection"
    ],
    "banking_trojans": [
      "Browser isolation for banking",
      "Credential theft detection",
      "Memory protection"
    ],
    "apt": [
      "Threat hunting program",
      "Zero trust architecture",
      "Advanced email protection"
    ]
  },
  "implementation_roadmap": {
    "phase_1": ["EDR deployment", "Email security upgrade"],
    "phase_2": ["NDR implementation", "SIEM enhancement"],
    "phase_3": ["Segmentation", "Backup modernization"],
    "phase_4": ["Threat hunting", "Advanced detection tuning"]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 16 : malware_intelligence_synthesizer

**Concepts couverts** (Synthèse globale - Intelligence production) :
- All 110 concepts integrated, Full malware intelligence report

**Sujet** : Synthétiseur d'intelligence malware pour production de rapports CTI.

**Entrée JSON** :
```json
{
  "campaign": {
    "name": "OPERATION_PHANTOM_BANK",
    "samples_analyzed": 15,
    "victims_identified": 8,
    "sector": "Financial"
  },
  "analysis_summary": {
    "malware_type": "Banking trojan + RAT",
    "delivery": "Spearphishing with macro documents",
    "persistence": "Registry + Scheduled tasks",
    "c2": "HTTPS + DNS fallback",
    "data_targeted": "Banking credentials, internal documents"
  },
  "attribution_indicators": {
    "language_artifacts": "Russian strings",
    "operational_hours": "UTC+3 business hours",
    "infrastructure": "Eastern European hosting"
  }
}
```

**Sortie attendue** :
```json
{
  "intelligence_report": {
    "title": "OPERATION_PHANTOM_BANK - Financial Sector Campaign Analysis",
    "classification": "TLP:AMBER",
    "confidence": "HIGH"
  },
  "executive_summary": {
    "threat": "Sophisticated banking trojan campaign targeting financial institutions",
    "impact": "Credential theft, financial fraud, potential data exfiltration",
    "attribution": "Likely Eastern European financially-motivated threat actor",
    "urgency": "HIGH - Active campaign against sector"
  },
  "technical_analysis": {
    "malware_capabilities": {
      "banking_trojan": "Web injection, form grabbing, keylogging",
      "rat_features": "Remote shell, file access, screenshot",
      "evasion": "Anti-VM, anti-debug, process injection"
    },
    "attack_chain": {
      "delivery": "Spearphishing → Macro document",
      "execution": "Macro → PowerShell → Reflective loading",
      "persistence": "Registry Run + Scheduled task",
      "c2": "HTTPS beacon with DNS fallback"
    },
    "infrastructure": {
      "c2_servers": ["List of IOCs"],
      "hosting": "Bulletproof hosting, Eastern Europe",
      "domain_patterns": "Typosquatting financial brands"
    }
  },
  "attribution_assessment": {
    "confidence": "MODERATE",
    "indicators": [
      "Russian language strings in code",
      "Development hours consistent with UTC+3",
      "Infrastructure patterns match known Eastern European operations"
    ],
    "assessment": "Financially-motivated threat actor, likely Eastern European origin",
    "alternative_hypothesis": "Could be false flag - monitor for inconsistencies"
  },
  "mitre_attack_mapping": {
    "initial_access": ["T1566.001 - Spearphishing Attachment"],
    "execution": ["T1059.001 - PowerShell", "T1204.002 - Malicious File"],
    "persistence": ["T1547.001 - Registry Run", "T1053.005 - Scheduled Task"],
    "defense_evasion": ["T1055 - Process Injection", "T1497 - Virtualization Evasion"],
    "credential_access": ["T1056.001 - Keylogging", "T1185 - Browser Session Hijacking"],
    "c2": ["T1071.001 - HTTPS", "T1071.004 - DNS"]
  },
  "indicators_of_compromise": {
    "file_hashes": ["SHA256 list"],
    "network": ["C2 domains and IPs"],
    "host": ["Registry keys", "File paths", "Scheduled task names"]
  },
  "recommendations": {
    "immediate": [
      "Block all listed IOCs",
      "Alert on macro-enabled document execution",
      "Monitor for listed TTPs"
    ],
    "short_term": [
      "Disable macros organization-wide",
      "Deploy banking session protection",
      "Enhance email security"
    ],
    "long_term": [
      "Implement zero trust for banking applications",
      "Regular threat intelligence consumption",
      "Red team exercises simulating this TTP chain"
    ]
  }
}
```

**Barème** : 98/100

---

## RÉCAPITULATIF MODULE 3.36

**Module** : Malware Analysis & Defense
**Concepts couverts** : 110/110 (100%)
**Exercices** : 16
**Note moyenne** : 97.4/100

### Répartition des concepts :

| Sous-module | Concepts | Exercices |
|-------------|----------|-----------|
| 3.36.1 Malware Fundamentals | 18 | Ex01-02 |
| 3.36.2 Windows Techniques | 22 | Ex03-04 |
| 3.36.3 Linux Techniques | 16 | Ex05-06 |
| 3.36.4 Rootkits & Bootkits | 18 | Ex07-08 |
| 3.36.5 Evasion Techniques | 20 | Ex09-10 |
| 3.36.6 Payloads & Specialized | 16 | Ex11-12 |
| Synthèse transversale | - | Ex13-16 |

### Thèmes couverts :
- Malware categories and development lifecycle (defensive view)
- Windows injection techniques and detection
- AMSI/ETW bypass detection
- Linux fileless malware and persistence
- Rootkit and bootkit forensics
- Evasion technique detection
- Shellcode and payload analysis
- Ransomware component analysis
- Malware family profiling
- SOC triage automation
- Defense architecture design
- CTI report production

**Note** : Tous les exercices sont orientés analyse, détection et défense.

