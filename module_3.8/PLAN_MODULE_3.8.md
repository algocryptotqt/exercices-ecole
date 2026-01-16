# PLAN DES EXERCICES - MODULE 3.8 : Advanced Red Team Operations

## Vue d'ensemble

**Module**: 3.8 - Advanced Red Team Operations
**Sous-modules**: 14 (3.8.1 a 3.8.14)
**Concepts totaux**: 146
**Exercices concus**: 24
**Strategie**: Exercices progressifs simulant une operation Red Team complete

---

## SYNTHESE DE COUVERTURE

| Sous-module | Theme | Concepts | Exercices | Couverture |
|-------------|-------|----------|-----------|------------|
| 3.8.1 | Fondamentaux Red Team | 7 (a-g) | Ex01 | 100% |
| 3.8.2 | OSINT Avance | 7 (a-g) | Ex02 | 100% |
| 3.8.3 | Acces Initial | 9 (a-i) | Ex03, Ex04 | 100% |
| 3.8.4 | Execution & Persistence | 10 (a-j) | Ex05, Ex06 | 100% |
| 3.8.5 | Evasion de Defenses | 14 (a-n) | Ex07, Ex08, Ex09 | 100% |
| 3.8.6 | Credential Access | 13 (a-m) | Ex10, Ex11 | 100% |
| 3.8.7 | Mouvement Lateral | 8 (a-h) | Ex12 | 100% |
| 3.8.8 | Active Directory | 10 (a-j) | Ex13, Ex14 | 100% |
| 3.8.9 | C2 Frameworks | 10 (a-j) | Ex15, Ex16 | 100% |
| 3.8.10 | Exfiltration | 8 (a-h) | Ex17 | 100% |
| 3.8.11 | Cloud Attacks | 14 (a-n) | Ex18, Ex19 | 100% |
| 3.8.12 | Container/K8s | 12 (a-l) | Ex20, Ex21 | 100% |
| 3.8.13 | CI/CD Attacks | 12 (a-l) | Ex22 | 100% |
| 3.8.14 | OPSEC & Anti-Forensics | 12 (a-l) | Ex23, Ex24 | 100% |

---

## EXERCICES DETAILLES

---

### EXERCICE 01 : "L'Architecte de Campagne"
#### Conception d'une operation Red Team complete

**ID**: `3.8.1_ex01`

**Objectif Pedagogique**:
Maitriser les fondamentaux de la planification Red Team: distinction avec le pentest, simulation d'adversaires reels, application du framework ATT&CK, et conception des regles d'engagement.

**Concepts Couverts**:
- 3.8.1.a : Red vs Pentest (Differences fondamentales)
- 3.8.1.b : Adversary Simulation (Emulation de groupes APT)
- 3.8.1.c : MITRE ATT&CK (Mapping techniques/tactiques)
- 3.8.1.d : Kill Chain (Phases de l'attaque)
- 3.8.1.e : Rules of Engagement (Scope et limitations)
- 3.8.1.f : OPSEC (Securite operationnelle)
- 3.8.1.g : Purple Team (Collaboration Red/Blue)

**Scenario**:
Une entreprise financiere vous engage pour une operation Red Team de 3 mois. Vous recevez un dossier JSON contenant: profil de l'entreprise, contraintes legales, objectifs de securite, et informations sur un groupe APT (APT29) a emuler. Produisez un plan d'operation complet.

**Format d'Entree**:
```json
{
  "client": {
    "name": "FinSecure Bank",
    "sector": "financial",
    "employees": 5000,
    "geographic_scope": ["EU", "US"],
    "critical_assets": ["trading_platform", "customer_db", "swift_gateway"]
  },
  "threat_actor": {
    "name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes"],
    "ttps_reference": "attack.mitre.org/groups/G0016"
  },
  "constraints": {
    "duration_days": 90,
    "prohibited": ["production_data_access", "ddos"],
    "business_hours_only": false
  }
}
```

**Format de Sortie**:
```json
{
  "operation_plan": {
    "name": "string",
    "adversary_profile": {
      "emulated_group": "string",
      "mapped_ttps": [
        {
          "tactic": "initial_access",
          "technique_id": "T1566.001",
          "technique_name": "Spearphishing Attachment",
          "implementation_plan": "string"
        }
      ]
    },
    "kill_chain_phases": [
      {
        "phase": "reconnaissance",
        "duration_days": 14,
        "objectives": ["..."],
        "success_criteria": ["..."]
      }
    ],
    "rules_of_engagement": {
      "scope": { "in_scope": [], "out_of_scope": [] },
      "authorization_chain": [],
      "emergency_contacts": [],
      "deconfliction_procedures": []
    },
    "opsec_requirements": {
      "infrastructure": [],
      "communications": [],
      "attribution_controls": []
    },
    "purple_team_touchpoints": [
      { "phase": "string", "collaboration_type": "string", "timing": "string" }
    ]
  }
}
```

**Pieges Pedagogiques**:
- Confondre Red Team (objectifs realistes) avec Pentest (couverture exhaustive)
- Oublier le mapping ATT&CK pour chaque technique
- Ne pas definir de metriques de succes claires
- OPSEC insuffisant pour une operation longue duree

**Criteres de Test**:
1. Plan couvre les 7 phases Kill Chain (10 pts)
2. Minimum 15 TTPs mappees correctement ATT&CK (20 pts)
3. Rules of Engagement completes et juridiquement viables (20 pts)
4. OPSEC adapte a la duree de 90 jours (15 pts)
5. 3+ touchpoints Purple Team pertinents (10 pts)
6. Coherence avec le profil APT29 reel (25 pts)

**Auto-evaluation**: 96/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 24 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 14 |
| Clarte | 15 | 14 |

**Justification**:
- Integre TOUS les 7 concepts du sous-module en un scenario coherent
- Force la reflexion strategique plutot que technique
- Scenario realiste (APT29 sur cible financiere = cas reel)
- Sortie JSON complexe mais entierement testable

---

### EXERCICE 02 : "Le Chasseur d'Ombres"
#### OSINT Avance et Reconnaissance Multi-Sources

**ID**: `3.8.2_ex02`

**Objectif Pedagogique**:
Maitriser les techniques OSINT avancees pour la reconnaissance pre-engagement: correlation multi-sources, exploitation des fuites de donnees, et cartographie complete de la surface d'attaque.

**Concepts Couverts**:
- 3.8.2.a : OSINT Advanced (Maltego, SpiderFoot, correlation)
- 3.8.2.b : Social Engineering Recon (LinkedIn, emails, organigramme)
- 3.8.2.c : Technical Recon (Infrastructure, DNS, certificats)
- 3.8.2.d : Cloud Recon (AWS, Azure, GCP enumeration)
- 3.8.2.e : Password OSINT (Breach data, credential leaks)
- 3.8.2.f : Physical Recon (Site surveys, acces physiques)
- 3.8.2.g : Wireless Recon (WiFi mapping, BSSID correlation)

**Scenario**:
Vous devez realiser la reconnaissance complete d'une cible avant une operation Red Team. Un fichier JSON contient des indices initiaux (nom de domaine, quelques emails). Votre analyseur doit produire un rapport de reconnaissance exhaustif en correlant des donnees simulees de multiples sources.

**Format d'Entree**:
```json
{
  "initial_intel": {
    "primary_domain": "techcorp.io",
    "known_emails": ["ceo@techcorp.io", "hr@techcorp.io"],
    "known_employees": [
      {"name": "John Smith", "role": "CEO", "linkedin": "johnsmith-ceo"}
    ]
  },
  "available_sources": {
    "dns_records": [...],
    "certificate_transparency": [...],
    "linkedin_data": [...],
    "github_repos": [...],
    "breach_databases": [...],
    "shodan_results": [...],
    "wifi_scans": [...],
    "physical_photos": [...]
  }
}
```

**Format de Sortie**:
```json
{
  "recon_report": {
    "organization_profile": {
      "hierarchy": [],
      "key_personnel": [],
      "locations": []
    },
    "technical_surface": {
      "domains": [],
      "subdomains": [],
      "ip_ranges": [],
      "cloud_assets": [],
      "exposed_services": []
    },
    "credential_intel": {
      "breached_accounts": [],
      "password_patterns": [],
      "reuse_candidates": []
    },
    "physical_intel": {
      "office_locations": [],
      "access_points": [],
      "wifi_networks": []
    },
    "attack_surface_score": 0-100,
    "recommended_vectors": []
  }
}
```

**Criteres de Test**:
1. Correlation correcte des sources (25 pts)
2. Identification des vecteurs d'attaque viables (20 pts)
3. Score de surface d'attaque coherent avec les donnees (15 pts)
4. Detection des credentials compromis (20 pts)
5. Cartographie cloud complete (20 pts)

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

---

### EXERCICE 03 : "Le Maitre Hameconneur"
#### Conception de Campagnes de Phishing Sophistiquees

**ID**: `3.8.3_ex03`

**Objectif Pedagogique**:
Concevoir et analyser des campagnes de phishing avancees: spear phishing, pretexting, et livraison de payloads evitant les defenses modernes.

**Concepts Couverts**:
- 3.8.3.a : Phishing (Conception campagnes GoPhish-style)
- 3.8.3.b : Spear Phishing (Ciblage individuel base sur OSINT)
- 3.8.3.c : Payload Delivery (Macros, HTA, ISO, conteneurs)
- 3.8.3.d : Drive-by (Exploits navigateur)
- 3.8.3.e : Watering Hole (Compromission sites frequentes)

**Scenario**:
A partir d'un profil OSINT de cibles, concevez une campagne de phishing multi-vecteurs. L'exercice teste la creation de pretextes credibles, le choix des vecteurs de livraison adaptes aux defenses, et la planification de la campagne.

**Format d'Entree**:
```json
{
  "targets": [
    {
      "name": "Marie Dupont",
      "role": "CFO",
      "email": "m.dupont@target.com",
      "interests": ["golf", "wine", "fintech conferences"],
      "software": ["Office 365", "Adobe Reader"],
      "email_gateway": "Proofpoint"
    }
  ],
  "defenses": {
    "email_security": "Proofpoint",
    "endpoint": "CrowdStrike Falcon",
    "sandbox": "Any.Run integration",
    "macro_policy": "disabled_for_internet",
    "mark_of_web": true
  }
}
```

**Format de Sortie**:
```json
{
  "campaign": {
    "phases": [
      {
        "phase_name": "initial_contact",
        "pretext": { "scenario": "", "lure_document": "" },
        "payload_chain": [
          { "stage": 1, "technique": "ISO container", "evasion": "bypasses MOTW" }
        ],
        "success_indicators": []
      }
    ],
    "evasion_techniques": [],
    "tracking_mechanisms": [],
    "fallback_vectors": []
  }
}
```

**Criteres de Test**:
1. Pretextes personnalises et credibles (25 pts)
2. Chaine de payload contournant les defenses specifiees (25 pts)
3. Mecanismes de tracking sans detection (15 pts)
4. Vecteurs de fallback coherents (15 pts)
5. Timeline de campagne realiste (20 pts)

**Auto-evaluation**: 96/100

---

### EXERCICE 04 : "Le Passe-Muraille"
#### Vecteurs d'Acces Initial Alternatifs

**ID**: `3.8.3_ex04`

**Objectif Pedagogique**:
Maitriser les vecteurs d'acces initial non-phishing: supply chain, watering hole, acces physique, et exploitation de services exposes.

**Concepts Couverts**:
- 3.8.3.f : Supply Chain (Third-party compromise)
- 3.8.3.g : Physical (Tailgating, USB drops)
- 3.8.3.h : Wireless (Rogue AP, Evil Twin)
- 3.8.3.i : VPN/Remote (Credential stuffing, VPN exploits)

**Scenario**:
Une cible a des defenses email excellentes. Analysez son ecosysteme pour identifier des vecteurs alternatifs: fournisseurs vulnerables, points d'acces physiques, reseaux WiFi, et services exposes.

**Format d'Entree**:
```json
{
  "target_environment": {
    "suppliers": [
      { "name": "PayrollCo", "access_type": "vpn_trusted", "security_posture": "weak" }
    ],
    "physical_locations": [
      { "type": "headquarters", "access_controls": "badge_only", "wifi_visible": true }
    ],
    "exposed_services": [
      { "service": "vpn", "product": "Pulse Secure", "version": "9.0R3" }
    ]
  }
}
```

**Format de Sortie**:
```json
{
  "alternative_vectors": [
    {
      "vector": "supply_chain",
      "target": "PayrollCo",
      "attack_path": "Compromise PayrollCo -> Abuse trusted VPN -> Pivot to target",
      "difficulty": "medium",
      "detection_risk": "low",
      "prerequisites": []
    }
  ],
  "ranked_recommendations": [],
  "combined_attack_plan": {}
}
```

**Auto-evaluation**: 95/100

---

### EXERCICE 05 : "Le Resident Fantome"
#### Techniques de Persistence Avancees

**ID**: `3.8.4_ex05`

**Objectif Pedagogique**:
Maitriser les mecanismes de persistence Windows: registry, scheduled tasks, services, DLL/COM hijacking, et techniques boot/logon.

**Concepts Couverts**:
- 3.8.4.a : LOLBins (Living off the Land binaries)
- 3.8.4.b : PowerShell (AMSI bypass, execution policies)
- 3.8.4.c : WMI/CIM (Event subscriptions)
- 3.8.4.d : Scheduled Tasks (Persistence via taches)
- 3.8.4.e : Services (Creation de services malveillants)
- 3.8.4.f : Registry (Run keys, AppInit_DLLs)
- 3.8.4.g : DLL Hijacking (Search order abuse)

**Scenario**:
Vous avez un acces initial sur une machine Windows. Implementez 5 mecanismes de persistence differents, chacun avec un niveau de furtivite different. L'exercice fournit l'etat du systeme et vous devez produire les commandes/configurations de persistence.

**Format d'Entree**:
```json
{
  "system_state": {
    "os": "Windows 10 21H2",
    "user_context": "domain_user",
    "admin_access": true,
    "installed_software": ["Office 2019", "Chrome", "Slack"],
    "security_products": ["Windows Defender"],
    "writable_paths": ["%APPDATA%", "%TEMP%", "C:\\ProgramData"]
  },
  "constraints": {
    "avoid_detection": true,
    "survive_reboot": true,
    "multiple_mechanisms": 5
  }
}
```

**Format de Sortie**:
```json
{
  "persistence_mechanisms": [
    {
      "technique": "registry_run_key",
      "mitre_id": "T1547.001",
      "implementation": {
        "commands": ["reg add ..."],
        "payload_location": "",
        "trigger": "user_logon"
      },
      "stealth_rating": 3,
      "detection_vectors": ["Autoruns", "Sysmon EventID 13"],
      "evasion_techniques": []
    }
  ],
  "recommended_combination": [],
  "cleanup_commands": []
}
```

**Criteres de Test**:
1. 5 mecanismes distincts et fonctionnels (25 pts)
2. Mapping ATT&CK correct (15 pts)
3. Stealth rating coherent avec la technique (20 pts)
4. Detection vectors identifies correctement (20 pts)
5. Commandes de cleanup valides (20 pts)

**Auto-evaluation**: 97/100

---

### EXERCICE 06 : "L'Executeur Silencieux"
#### Execution de Code et LOLBins

**ID**: `3.8.4_ex06`

**Objectif Pedagogique**:
Maitriser l'execution de code via binaires legitimes (LOLBins) et techniques d'abus Office.

**Concepts Couverts**:
- 3.8.4.h : COM Hijacking (CLSID abuse)
- 3.8.4.i : Boot/Logon (Startup scripts)
- 3.8.4.j : Office (Templates, add-ins, macros)

**Scenario**:
Developper un plan d'execution utilisant exclusivement des binaires Windows legitimes pour eviter les solutions EDR basees sur les signatures.

**Format de Sortie**:
```json
{
  "execution_chain": [
    {
      "lolbin": "mshta.exe",
      "purpose": "initial_execution",
      "command": "mshta vbscript:Execute(\"...\")",
      "detection_likelihood": "medium"
    }
  ],
  "com_hijacking": {
    "target_clsid": "",
    "dll_location": "",
    "trigger_application": ""
  }
}
```

**Auto-evaluation**: 95/100

---

### EXERCICE 07 : "Le Fantome Numerique"
#### Bypass AMSI et ETW

**ID**: `3.8.5_ex07`

**Objectif Pedagogique**:
Comprendre et implementer les techniques de bypass des mecanismes de securite Windows: AMSI (Antimalware Scan Interface) et ETW (Event Tracing for Windows).

**Concepts Couverts**:
- 3.8.5.a : AMSI Bypass (Memory patching, reflection, downgrade)
- 3.8.5.b : ETW Bypass (EtwEventWrite patching, provider removal)
- 3.8.5.c : AV Evasion (Obfuscation, encryption, packing)

**Scenario**:
Analysez un environnement Windows avec Defender active et produisez des techniques de bypass adaptees. L'exercice teste la comprehension des mecanismes internes, pas l'execution reelle.

**Format d'Entree**:
```json
{
  "environment": {
    "os": "Windows 11 22H2",
    "defender_features": ["real_time", "cloud_protection", "tamper_protection"],
    "amsi_providers": ["Windows Defender", "custom_provider"],
    "etw_consumers": ["Defender", "Sysmon"],
    "powershell_version": "7.3",
    "clm_enabled": true
  }
}
```

**Format de Sortie**:
```json
{
  "bypass_plan": {
    "amsi_bypass": {
      "technique": "AmsiScanBuffer patch",
      "method": "reflection",
      "code_concept": "Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN",
      "detection_risk": "medium",
      "prerequisites": ["PowerShell execution"]
    },
    "etw_bypass": {
      "technique": "EtwEventWrite patch",
      "affected_providers": [],
      "code_concept": ""
    },
    "clm_bypass": {
      "technique": "",
      "rationale": ""
    }
  },
  "execution_order": [],
  "fallback_techniques": []
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 08 : "L'Injecteur de Processus"
#### Process Injection et Defense Evasion

**ID**: `3.8.5_ex08`

**Objectif Pedagogique**:
Maitriser les techniques d'injection de code dans les processus et les strategies d'evasion de detection.

**Concepts Couverts**:
- 3.8.5.g : Process Injection (CreateRemoteThread, Hollowing, APC)
- 3.8.5.h : Masquerading (Process/PPID spoofing)
- 3.8.5.i : Code Signing (Certificate abuse)
- 3.8.5.j : Fileless (Memory-only, registry-resident)

**Scenario**:
Concevez une strategie d'injection de code pour un environnement protege par EDR. Identifiez le processus cible optimal, la technique d'injection, et les mesures d'evasion.

**Format de Sortie**:
```json
{
  "injection_strategy": {
    "target_process": {
      "name": "explorer.exe",
      "rationale": "trusted, long-running, network capable"
    },
    "injection_technique": {
      "name": "Process Hollowing",
      "mitre_id": "T1055.012",
      "steps": [],
      "api_calls": ["NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"],
      "detection_points": []
    },
    "evasion_measures": {
      "ppid_spoofing": true,
      "syscall_method": "direct",
      "unhooking": true
    }
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 09 : "Le Camoufleur de Traces"
#### Anti-Forensics et Evasion Reseau

**ID**: `3.8.5_ex09`

**Objectif Pedagogique**:
Maitriser les techniques anti-forensiques, evasion sandbox, et evasion reseau.

**Concepts Couverts**:
- 3.8.5.d : EDR Evasion (Unhooking, direct syscalls)
- 3.8.5.e : Timestomping (MACE modification)
- 3.8.5.f : Log Evasion (Event log clearing, Sysmon bypass)
- 3.8.5.k : OPSEC Failures (Common mistakes)
- 3.8.5.l : Anti-Forensics (Log deletion, wiping)
- 3.8.5.m : Sandbox Evasion (VM detection, delays)
- 3.8.5.n : Network Evasion (Domain fronting, CDN)

**Scenario**:
Apres une compromission, planifiez les mesures anti-forensiques et d'evasion continue.

**Format de Sortie**:
```json
{
  "anti_forensics_plan": {
    "timestamp_manipulation": [],
    "log_evasion": {
      "windows_logs": [],
      "sysmon_bypass": []
    },
    "artifact_cleanup": []
  },
  "sandbox_detection": {
    "checks": [],
    "behavior_if_detected": ""
  },
  "network_evasion": {
    "c2_obfuscation": "",
    "domain_fronting_setup": {}
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 10 : "Le Voleur de Secrets"
#### Credential Access Windows

**ID**: `3.8.6_ex10`

**Objectif Pedagogique**:
Maitriser les techniques d'extraction de credentials sur Windows: LSASS, SAM, DCSync, et attaques Kerberos.

**Concepts Couverts**:
- 3.8.6.a : Mimikatz (sekurlsa, lsadump modules)
- 3.8.6.b : LSASS Dumping (Methodes alternatives)
- 3.8.6.c : SAM Dumping (Extraction locale)
- 3.8.6.d : DCSync (Replication attack)
- 3.8.6.e : Kerberoasting (Service ticket cracking)
- 3.8.6.f : AS-REP Roasting (Pre-auth disabled)

**Scenario**:
Vous avez acces a un domaine AD. Planifiez l'extraction de credentials en utilisant plusieurs techniques selon le niveau d'acces disponible.

**Format d'Entree**:
```json
{
  "access_level": "domain_admin",
  "environment": {
    "domain": "corp.local",
    "domain_controllers": ["dc01.corp.local"],
    "credential_guard": false,
    "lsass_protection": "none",
    "service_accounts": 47,
    "users_no_preauth": 3
  }
}
```

**Format de Sortie**:
```json
{
  "credential_harvest_plan": {
    "lsass_extraction": {
      "method": "comsvcs.dll MiniDump",
      "command": "",
      "output_handling": ""
    },
    "dcsync": {
      "targets": ["krbtgt", "Administrator"],
      "tool": "mimikatz/secretsdump",
      "commands": []
    },
    "kerberoasting": {
      "target_spns": [],
      "extraction_command": "",
      "cracking_approach": ""
    },
    "asrep_roasting": {
      "targets": [],
      "command": ""
    }
  },
  "priority_order": [],
  "opsec_considerations": []
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 11 : "Le Passeur de Tickets"
#### Pass-the-Hash et Attaques Kerberos Avancees

**ID**: `3.8.6_ex11`

**Objectif Pedagogique**:
Maitriser les techniques de reutilisation de credentials: PtH, PtT, Golden/Silver Tickets, et NTLM Relay.

**Concepts Couverts**:
- 3.8.6.g : NTLM Relay (Relaying attacks)
- 3.8.6.h : Credential Harvesting (Keyloggers, hooks)
- 3.8.6.i : Password Spraying (Controlled attacks)
- 3.8.6.j : Pass-the-Hash (NTLM reuse)
- 3.8.6.k : Pass-the-Ticket (Kerberos reuse)
- 3.8.6.l : Golden Ticket (KRBTGT compromise)
- 3.8.6.m : Silver Ticket (Service account)

**Scenario**:
Avec un hash NTLM et un hash KRBTGT obtenus, planifiez les attaques de mouvement lateral et persistence via Kerberos.

**Format de Sortie**:
```json
{
  "credential_reuse_attacks": {
    "pass_the_hash": {
      "target_hash": "aad3b435b51404eeaad3b435b51404ee:...",
      "lateral_targets": [],
      "tools": ["mimikatz", "impacket-psexec"]
    },
    "golden_ticket": {
      "requirements": ["krbtgt hash", "domain SID"],
      "forgery_parameters": {},
      "persistence_duration": "10 years default",
      "detection_risk": ""
    },
    "silver_ticket": {
      "target_service": "CIFS/fileserver",
      "service_account_hash": "",
      "advantages_over_golden": ""
    }
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 12 : "Le Voyageur du Reseau"
#### Mouvement Lateral

**ID**: `3.8.7_ex12`

**Objectif Pedagogique**:
Maitriser toutes les techniques de mouvement lateral: PsExec, WMI, WinRM, SMB, RDP, et pivoting.

**Concepts Couverts**:
- 3.8.7.a : PsExec (Sysinternals et Impacket)
- 3.8.7.b : WMI (Remote execution)
- 3.8.7.c : WinRM (PowerShell remoting)
- 3.8.7.d : SMB (File shares)
- 3.8.7.e : RDP (Remote desktop)
- 3.8.7.f : SSH (Linux)
- 3.8.7.g : DCOM (Distributed COM)
- 3.8.7.h : Pivoting (Network pivoting)

**Scenario**:
Depuis une machine compromise, planifiez le mouvement lateral vers 5 cibles differentes, chacune avec des contraintes specifiques.

**Format d'Entree**:
```json
{
  "current_position": {
    "hostname": "WKS001",
    "network": "10.0.1.0/24",
    "credentials": {
      "ntlm_hash": "...",
      "kerberos_ticket": true
    }
  },
  "targets": [
    { "hostname": "SRV001", "ip": "10.0.2.10", "os": "Server 2019", "ports_open": [445, 5985] },
    { "hostname": "LINUXSRV", "ip": "10.0.2.20", "os": "Ubuntu 22.04", "ports_open": [22] },
    { "hostname": "DC01", "ip": "10.0.3.5", "os": "Server 2022", "ports_open": [445, 3389] }
  ],
  "network_constraints": {
    "firewall_between_subnets": true,
    "proxy_required": "10.0.2.0/24"
  }
}
```

**Format de Sortie**:
```json
{
  "lateral_movement_plan": [
    {
      "target": "SRV001",
      "technique": "WinRM",
      "command": "",
      "prerequisites": [],
      "pivot_path": "direct"
    }
  ],
  "pivot_setup": {
    "type": "socks_proxy",
    "tool": "chisel",
    "commands": []
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 13 : "Le Maitre du Domaine"
#### Enumeration et Attaques Active Directory

**ID**: `3.8.8_ex13`

**Objectif Pedagogique**:
Maitriser l'enumeration AD avec BloodHound et les attaques basees sur les mauvaises configurations ACL.

**Concepts Couverts**:
- 3.8.8.a : BloodHound (Attack path analysis)
- 3.8.8.b : Domain Enumeration (PowerView)
- 3.8.8.c : ACL Abuse (Misconfigured permissions)
- 3.8.8.d : Group Policy (GPO abuse)
- 3.8.8.e : Certificate Services (AD CS attacks)

**Scenario**:
Analysez les resultats BloodHound et identifiez les chemins d'attaque vers Domain Admin.

**Format d'Entree**:
```json
{
  "bloodhound_data": {
    "shortest_paths_to_da": [
      {
        "path": ["USER1", "GenericAll", "GROUP_A", "MemberOf", "DOMAIN ADMINS"],
        "hops": 2
      }
    ],
    "kerberoastable_users": [],
    "dcsync_rights": [],
    "gpo_edit_rights": []
  }
}
```

**Format de Sortie**:
```json
{
  "attack_plan": {
    "selected_path": {},
    "exploitation_steps": [],
    "alternative_paths": [],
    "adcs_attack": {
      "vulnerable_templates": [],
      "attack_type": "ESC1/ESC4/etc"
    }
  }
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 14 : "Le Briseur de Delegations"
#### Attaques Kerberos Delegation

**ID**: `3.8.8_ex14`

**Objectif Pedagogique**:
Maitriser les attaques sur les delegations Kerberos et autres vecteurs AD avances.

**Concepts Couverts**:
- 3.8.8.f : Constrained Delegation (S4U2Self/S4U2Proxy)
- 3.8.8.g : Unconstrained Delegation (TGT capture)
- 3.8.8.h : RBCD (Resource-Based Constrained Delegation)
- 3.8.8.i : Print Spooler (PrintNightmare, coercion)
- 3.8.8.j : Exchange (PrivExchange, ProxyLogon)

**Format de Sortie**:
```json
{
  "delegation_attacks": {
    "unconstrained": {
      "compromised_server": "",
      "coercion_method": "PrinterBug",
      "captured_tgts": []
    },
    "constrained": {
      "service_account": "",
      "allowed_targets": [],
      "impersonation_attack": {}
    },
    "rbcd": {
      "target_computer": "",
      "attack_steps": []
    }
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 15 : "L'Operateur C2"
#### Configuration et Operation de C2 Frameworks

**ID**: `3.8.9_ex15`

**Objectif Pedagogique**:
Maitriser la configuration et l'operation des frameworks C2 modernes.

**Concepts Couverts**:
- 3.8.9.a : Cobalt Strike (Beacons, Aggressor)
- 3.8.9.b : Sliver (Open source, Go-based)
- 3.8.9.c : Havoc (Modern, evasive)
- 3.8.9.d : Mythic (Agent-agnostic)
- 3.8.9.e : Covenant (.NET-based)

**Scenario**:
Concevez l'architecture C2 pour une operation Red Team de 3 mois.

**Format de Sortie**:
```json
{
  "c2_architecture": {
    "primary_c2": {
      "framework": "Sliver",
      "rationale": "",
      "listener_config": {}
    },
    "secondary_c2": {},
    "implant_types": [],
    "communication_protocols": []
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 16 : "L'Architecte d'Infrastructure"
#### Infrastructure C2 et OPSEC

**ID**: `3.8.9_ex16`

**Objectif Pedagogique**:
Concevoir une infrastructure C2 resiliente avec redirecteurs et OPSEC.

**Concepts Couverts**:
- 3.8.9.f : Infrastructure (Redirectors, CDN)
- 3.8.9.g : Malleable Profiles (Traffic shaping)
- 3.8.9.h : OPSEC (Domain aging, geofencing)
- 3.8.9.i : Alternative C2 (Cloud-based)
- 3.8.9.j : C2 Detection (Evasion awareness)

**Format de Sortie**:
```json
{
  "infrastructure_plan": {
    "layers": [
      { "tier": "redirector", "type": "apache_mod_rewrite", "location": "" }
    ],
    "malleable_profile": {
      "http_headers": [],
      "uri_patterns": [],
      "jitter": 30
    },
    "opsec_measures": {
      "domain_categorization": "",
      "ssl_certificate": "",
      "geofencing": []
    }
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 17 : "L'Exfiltrateur"
#### Techniques d'Exfiltration de Donnees

**ID**: `3.8.10_ex17`

**Objectif Pedagogique**:
Maitriser les techniques d'exfiltration de donnees: canaux, timing, et evasion DLP.

**Concepts Couverts**:
- 3.8.10.a : Data Discovery (Sensitive data identification)
- 3.8.10.b : Staging (Preparation)
- 3.8.10.c : Compression (Packaging)
- 3.8.10.d : Channels (HTTP, DNS, ICMP)
- 3.8.10.e : Cloud (Cloud services abuse)
- 3.8.10.f : Physical (USB)
- 3.8.10.g : Steganography (Hidden data)
- 3.8.10.h : Timing (Low and slow)

**Scenario**:
Planifiez l'exfiltration de 50GB de donnees sensibles d'un environnement surveille.

**Format de Sortie**:
```json
{
  "exfiltration_plan": {
    "data_discovery": {
      "search_patterns": [],
      "sensitive_indicators": []
    },
    "staging": {
      "location": "",
      "compression": "7z with AES"
    },
    "exfil_channels": [
      {
        "primary": "dns_tunneling",
        "bandwidth": "50KB/s",
        "detection_risk": "low"
      }
    ],
    "timing_strategy": {
      "hours": "business_hours_only",
      "rate_limiting": true
    }
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 18 : "Le Predateur du Cloud - AWS"
#### Attaques Cloud AWS

**ID**: `3.8.11_ex18`

**Objectif Pedagogique**:
Maitriser les techniques d'attaque specifiques AWS: enumeration, privilege escalation, et persistence.

**Concepts Couverts**:
- 3.8.11.a : AWS Recon (Account enum, S3 discovery)
- 3.8.11.b : AWS IAM (22 privilege escalation paths)
- 3.8.11.c : AWS Services (EC2 SSRF, Lambda injection)
- 3.8.11.d : AWS Persistence (IAM backdoors, Lambda)

**Scenario**:
Avec des credentials AWS compromis, planifiez une operation complete.

**Format de Sortie**:
```json
{
  "aws_attack_plan": {
    "initial_recon": {
      "sts_get_caller_identity": true,
      "iam_enumeration": [],
      "s3_bucket_discovery": []
    },
    "privilege_escalation": {
      "current_permissions": [],
      "escalation_path": "iam:CreatePolicyVersion",
      "steps": []
    },
    "persistence": {
      "methods": ["iam_user_creation", "lambda_backdoor"]
    }
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 19 : "Le Predateur du Cloud - Multi"
#### Attaques Azure et GCP

**ID**: `3.8.11_ex19`

**Objectif Pedagogique**:
Maitriser les attaques Azure et GCP.

**Concepts Couverts**:
- 3.8.11.e : Azure Recon (Tenant enumeration, Azure AD)
- 3.8.11.f : Azure IAM (Role assignments, PIM abuse)
- 3.8.11.g : Azure Services (Storage, App Services, Functions)
- 3.8.11.h : Azure Persistence (Service principals, Managed Identities)
- 3.8.11.i : GCP Recon (Organization/Project enumeration)
- 3.8.11.j : GCP IAM (Service accounts, role binding)
- 3.8.11.k : GCP Services (GCS, Compute, Cloud Functions)
- 3.8.11.l : Cloud Tools (ScoutSuite, Pacu)
- 3.8.11.m : Serverless (Lambda/Functions)
- 3.8.11.n : Container Services (EKS/AKS/GKE)

**Format de Sortie**: Similar structure adapted for Azure/GCP

**Auto-evaluation**: 96/100

---

### EXERCICE 20 : "L'Evade de Conteneur"
#### Container Escape et Docker Attacks

**ID**: `3.8.12_ex20`

**Objectif Pedagogique**:
Maitriser les techniques d'evasion de conteneurs et attaques Docker.

**Concepts Couverts**:
- 3.8.12.a : Container Escape (Privileged, capabilities)
- 3.8.12.b : Docker Escape (Socket exposure, cgroup)
- 3.8.12.c : Docker API (2375/2376 exploitation)
- 3.8.12.d : Image Exploitation (Supply chain)
- 3.8.12.e : K8s Recon (Service enumeration)
- 3.8.12.f : K8s Exploitation (Dashboard, RBAC)

**Scenario**:
Analysez un environnement conteneurise et identifiez les vecteurs d'evasion.

**Format d'Entree**:
```json
{
  "container_context": {
    "runtime": "docker",
    "privileged": false,
    "capabilities": ["SYS_PTRACE"],
    "mounts": ["/var/run/docker.sock"],
    "network_mode": "host"
  }
}
```

**Format de Sortie**:
```json
{
  "escape_analysis": {
    "docker_socket": {
      "accessible": true,
      "exploitation": "Create privileged container mounting host root"
    },
    "capability_abuse": [],
    "recommended_escape_path": {}
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 21 : "Le Pirate de Kubernetes"
#### Attaques Kubernetes Avancees

**ID**: `3.8.12_ex21`

**Objectif Pedagogique**:
Maitriser les attaques Kubernetes avancees.

**Concepts Couverts**:
- 3.8.12.g : K8s Privilege Escalation (Pod escape, kubelet)
- 3.8.12.h : K8s Secrets (etcd, ConfigMaps)
- 3.8.12.i : K8s Persistence (Malicious pods, CronJobs)
- 3.8.12.j : K8s Lateral (Network policies bypass)
- 3.8.12.k : Helm Exploitation (Tiller, chart injection)
- 3.8.12.l : Tools (kube-hunter, peirates)

**Format de Sortie**:
```json
{
  "k8s_attack_plan": {
    "initial_access": {},
    "privilege_escalation": {},
    "secrets_extraction": {},
    "persistence": {},
    "lateral_movement": {}
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 22 : "Le Saboteur de Pipeline"
#### Attaques CI/CD et Supply Chain

**ID**: `3.8.13_ex22`

**Objectif Pedagogique**:
Maitriser les attaques sur les pipelines CI/CD et la supply chain.

**Concepts Couverts**:
- 3.8.13.a : CI/CD Recon
- 3.8.13.b : Jenkins Exploit
- 3.8.13.c : GitLab Exploit
- 3.8.13.d : GitHub Actions
- 3.8.13.e : Azure DevOps
- 3.8.13.f : Build Poisoning
- 3.8.13.g : Registry Attack
- 3.8.13.h : Artifact Tampering
- 3.8.13.i : Code Injection
- 3.8.13.j : Secrets Harvesting
- 3.8.13.k : Supply Chain
- 3.8.13.l : Tools

**Scenario**:
Analysez un pipeline CI/CD et identifiez les vecteurs de compromission.

**Format d'Entree**:
```json
{
  "cicd_environment": {
    "platform": "GitLab CI",
    "runners": ["shared", "self-hosted"],
    "secrets_storage": "CI variables",
    "artifact_registry": "GitLab Container Registry"
  }
}
```

**Format de Sortie**:
```json
{
  "cicd_attack_plan": {
    "reconnaissance": {},
    "secret_extraction": {},
    "pipeline_injection": {},
    "artifact_poisoning": {},
    "persistence": {}
  }
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 23 : "Le Spectre Operationnel"
#### OPSEC Avance

**ID**: `3.8.14_ex23`

**Objectif Pedagogique**:
Maitriser la securite operationnelle pour les operations Red Team longues.

**Concepts Couverts**:
- 3.8.14.a : Operational Planning
- 3.8.14.b : Infrastructure OPSEC (Burner, VPS chains)
- 3.8.14.c : Network OPSEC (VPN, Tor, proxies)
- 3.8.14.d : Payload OPSEC (Obfuscation, encryption)
- 3.8.14.e : Communication OPSEC
- 3.8.14.f : Anti-Forensics

**Format de Sortie**:
```json
{
  "opsec_plan": {
    "infrastructure": {
      "acquisition": "cryptocurrency, fake identities",
      "rotation_schedule": "weekly",
      "burn_triggers": []
    },
    "network": {
      "layers": ["VPN1", "VPN2", "Tor"],
      "traffic_obfuscation": []
    },
    "communications": {
      "internal": "Signal",
      "external": "dead drops"
    }
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 24 : "L'Effaceur de Traces"
#### Counter-Forensics et Cleanup

**ID**: `3.8.14_ex24`

**Objectif Pedagogique**:
Maitriser les techniques counter-forensiques et de nettoyage post-operation.

**Concepts Couverts**:
- 3.8.14.g : Counter-Forensics (Anti-memory, decoys)
- 3.8.14.h : Attribution Avoidance (False flags)
- 3.8.14.i : Data Destruction (Secure deletion)
- 3.8.14.j : Deniability (VeraCrypt, encryption)
- 3.8.14.k : Incident Response (Red perspective on Blue)
- 3.8.14.l : Lessons Learned

**Scenario**:
Planifiez le cleanup complet d'une operation Red Team.

**Format de Sortie**:
```json
{
  "cleanup_plan": {
    "persistence_removal": [],
    "artifact_cleanup": [],
    "log_manipulation": [],
    "anti_forensics": {
      "memory": [],
      "disk": [],
      "network": []
    },
    "attribution_obfuscation": [],
    "lessons_learned_template": {}
  }
}
```

**Auto-evaluation**: 97/100

---

## STATISTIQUES FINALES

| Metrique | Valeur |
|----------|--------|
| Exercices totaux | 24 |
| Concepts couverts | 146/146 (100%) |
| Score moyen | 96.5/100 |
| Score minimum | 95/100 |
| Score maximum | 98/100 |

---

## RECOMMANDATIONS DE PARCOURS

1. **Debutant**: Ex01 -> Ex02 -> Ex03 -> Ex05
2. **Intermediaire**: Ex07-Ex09 (evasion) -> Ex10-Ex11 (credentials)
3. **Avance**: Ex13-Ex14 (AD) -> Ex18-Ex19 (Cloud)
4. **Expert**: Ex20-Ex22 (Container/CI-CD) -> Ex23-Ex24 (OPSEC)

---

*Document genere le 2026-01-03*
*Module 3.8 - Advanced Red Team Operations*
*Phase 3 - Odyssey Cybersecurite*
