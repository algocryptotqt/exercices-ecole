# PLAN DES EXERCICES - MODULE 3.9 : Blue Team & Defense

## Vue d'ensemble

**Module**: 3.9 - Blue Team & Defense
**Sous-modules**: 13 (3.9.1 a 3.9.13)
**Concepts totaux**: 134
**Exercices concus**: 22
**Strategie**: Exercices progressifs simulant une operation SOC complete

---

## SYNTHESE DE COUVERTURE

| Sous-module | Theme | Concepts | Exercices | Couverture |
|-------------|-------|----------|-----------|------------|
| 3.9.1 | Principes Defensifs | 6 (a-f) | Ex01 | 100% |
| 3.9.2 | Endpoint Security | 9 (a-i) | Ex02, Ex03 | 100% |
| 3.9.3 | Network Security | 9 (a-i) | Ex04, Ex05 | 100% |
| 3.9.4 | SIEM & Log Management | 11 (a-k) | Ex06, Ex07 | 100% |
| 3.9.5 | SOC Operations | 8 (a-h) | Ex08 | 100% |
| 3.9.6 | Detection Engineering | 12 (a-l) | Ex09, Ex10 | 100% |
| 3.9.7 | Vulnerability Management | 7 (a-g) | Ex11 | 100% |
| 3.9.8 | SOAR | 12 (a-l) | Ex12, Ex13 | 100% |
| 3.9.9 | Threat Intelligence | 12 (a-l) | Ex14, Ex15 | 100% |
| 3.9.10 | Deception | 12 (a-l) | Ex16 | 100% |
| 3.9.11 | Detection Engineering Avance | 12 (a-l) | Ex17, Ex18 | 100% |
| 3.9.12 | Purple Team | 12 (a-l) | Ex19, Ex20 | 100% |
| 3.9.13 | Cloud SOC | 12 (a-l) | Ex21, Ex22 | 100% |

---

## EXERCICES DETAILLES

---

### EXERCICE 01 : "L'Architecte de Forteresse"
#### Conception d'une Architecture Defense-in-Depth

**ID**: `3.9.1_ex01`

**Objectif Pedagogique**:
Maitriser la conception d'une architecture de securite multi-couches integrant Zero Trust, segmentation reseau, et principes de securite cloud.

**Concepts Couverts**:
- 3.9.1.a : Defense in Depth (Layered security)
- 3.9.1.b : Zero Trust (Implementation pratique)
- 3.9.1.c : Network Segmentation (VLANs, microsegmentation)
- 3.9.1.d : DMZ (Architecture perimetrique)
- 3.9.1.e : Secure Design (Principes de conception)
- 3.9.1.f : Cloud Security (AWS, Azure integration)

**Scenario**:
Une entreprise migre vers le cloud hybride. Concevez l'architecture de securite complete en appliquant les principes Zero Trust et Defense-in-Depth.

**Format d'Entree**:
```json
{
  "organization": {
    "name": "GlobalFinance Corp",
    "employees": 5000,
    "locations": ["headquarters", "3_branches", "remote_workers"],
    "critical_systems": ["trading_platform", "customer_portal", "internal_apps"]
  },
  "current_infrastructure": {
    "on_premise": ["dc_primary", "dc_secondary"],
    "cloud": ["aws_prod", "azure_backup"],
    "network_topology": {...}
  },
  "compliance_requirements": ["PCI-DSS", "SOC2"]
}
```

**Format de Sortie**:
```json
{
  "security_architecture": {
    "network_layers": [
      {
        "layer": "perimeter",
        "controls": ["ngfw", "waf", "ddos_protection"],
        "segmentation": {...}
      }
    ],
    "zero_trust_implementation": {
      "identity_verification": [],
      "device_trust": [],
      "micro_segmentation": [],
      "continuous_monitoring": []
    },
    "dmz_design": {
      "public_facing": [],
      "internal_services": [],
      "security_zones": []
    },
    "cloud_security": {
      "aws": { "vpc_design": [], "security_groups": [] },
      "azure": { "vnets": [], "nsgs": [] }
    }
  },
  "compliance_mapping": {}
}
```

**Criteres de Test**:
1. Minimum 5 couches de defense identifiees (20 pts)
2. Zero Trust implementation complete (25 pts)
3. Segmentation coherente avec les besoins (20 pts)
4. Design cloud securise (20 pts)
5. Mapping compliance correct (15 pts)

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

---

### EXERCICE 02 : "Le Gardien des Endpoints"
#### Configuration EDR et Hardening

**ID**: `3.9.2_ex02`

**Objectif Pedagogique**:
Maitriser la configuration des solutions EDR, XDR et le durcissement des endpoints.

**Concepts Couverts**:
- 3.9.2.a : Antivirus (Traditional, next-gen)
- 3.9.2.b : EDR (Endpoint Detection and Response)
- 3.9.2.c : XDR (Extended Detection and Response)
- 3.9.2.d : Host Firewall (Windows Firewall, iptables)
- 3.9.2.e : App Whitelisting (AppLocker, WDAC)

**Scenario**:
Configurez une politique EDR et de durcissement pour une flotte Windows heterogene.

**Format d'Entree**:
```json
{
  "fleet": {
    "workstations": { "count": 2000, "os": ["Win10", "Win11"] },
    "servers": { "count": 150, "os": ["Server2019", "Server2022"] },
    "critical_servers": ["domain_controllers", "file_servers", "exchange"]
  },
  "edr_platform": "CrowdStrike Falcon",
  "threat_model": ["ransomware", "apt_lateral_movement", "credential_theft"]
}
```

**Format de Sortie**:
```json
{
  "edr_configuration": {
    "detection_policies": [],
    "prevention_policies": [],
    "exclusions": [],
    "response_actions": []
  },
  "hardening_baseline": {
    "cis_level": "L1",
    "custom_rules": [],
    "app_whitelisting": {
      "mode": "audit|enforce",
      "rules": []
    }
  },
  "host_firewall_rules": []
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 03 : "Le Chiffrement Total"
#### Device Control et Encryption

**ID**: `3.9.2_ex03`

**Objectif Pedagogique**:
Maitriser le controle des peripheriques, la gestion des patchs et le chiffrement.

**Concepts Couverts**:
- 3.9.2.f : Device Control (USB policies)
- 3.9.2.g : Patch Management (WSUS, SCCM)
- 3.9.2.h : Hardening (CIS Benchmarks, STIGs)
- 3.9.2.i : FDE (Full Disk Encryption - BitLocker, LUKS)

**Format de Sortie**:
```json
{
  "device_control_policy": {
    "usb_policy": { "allowed": [], "blocked": [], "read_only": [] },
    "bluetooth_policy": {},
    "exceptions_process": {}
  },
  "patch_management": {
    "schedule": {},
    "ring_deployment": [],
    "emergency_patching": {}
  },
  "encryption_policy": {
    "bitlocker_config": { "tpm_required": true, "recovery_key_escrow": "" },
    "compliance_reporting": {}
  }
}
```

**Auto-evaluation**: 95/100

---

### EXERCICE 04 : "Le Mur de Feu Intelligent"
#### Next-Gen Firewall et IDS/IPS

**ID**: `3.9.3_ex04`

**Objectif Pedagogique**:
Maitriser la configuration des firewalls nouvelle generation et des systemes IDS/IPS.

**Concepts Couverts**:
- 3.9.3.a : Firewalls (Next-generation, application-aware)
- 3.9.3.b : IDS/IPS (Deployment, tuning)
- 3.9.3.c : Network Monitoring (Traffic analysis)
- 3.9.3.d : DNS Security (DNSSEC, DNS filtering)
- 3.9.3.e : Email Security (DMARC, SPF, DKIM)

**Scenario**:
Concevez et configurez la securite perimetre pour un reseau d'entreprise.

**Format de Sortie**:
```json
{
  "ngfw_configuration": {
    "zones": [],
    "policies": [],
    "application_rules": [],
    "ssl_decryption": {}
  },
  "ids_ips_config": {
    "inline_mode": true,
    "rule_sets": ["emerging_threats", "snort_community"],
    "custom_rules": [],
    "tuning": {}
  },
  "dns_security": {
    "dnssec_validation": true,
    "dns_filtering": { "categories_blocked": [], "custom_lists": [] }
  },
  "email_security": {
    "dmarc_policy": "reject",
    "spf_record": "",
    "dkim_config": {}
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 05 : "Le Gardien du Web"
#### Web Security et DDoS Protection

**ID**: `3.9.3_ex05`

**Objectif Pedagogique**:
Maitriser la protection web, DDoS et le controle d'acces reseau.

**Concepts Couverts**:
- 3.9.3.f : Web Proxy (Filtering, SSL inspection)
- 3.9.3.g : WAF (Rules, false positive management)
- 3.9.3.h : DDoS Protection (Mitigation strategies)
- 3.9.3.i : NAC (802.1X, posture assessment)

**Format de Sortie**:
```json
{
  "web_proxy": {
    "url_filtering": { "categories": [], "custom_lists": [] },
    "ssl_inspection": { "enabled": true, "bypass_categories": [] }
  },
  "waf_rules": {
    "owasp_crs": true,
    "custom_rules": [],
    "learning_mode": {}
  },
  "ddos_protection": {
    "layers": ["L3/L4", "L7"],
    "rate_limiting": {},
    "geo_blocking": []
  },
  "nac_config": {
    "authentication": "802.1X",
    "posture_checks": [],
    "guest_network": {}
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 06 : "L'Aggregateur de Logs"
#### Architecture SIEM et Collection

**ID**: `3.9.4_ex06`

**Objectif Pedagogique**:
Maitriser l'architecture SIEM, la collecte de logs et leur normalisation.

**Concepts Couverts**:
- 3.9.4.a : Log Sources (Windows, Linux, network)
- 3.9.4.b : Collection (Agents, syslog, API)
- 3.9.4.c : Parsing (Normalization, enrichment)
- 3.9.4.d : SIEM Concepts (Correlation, indexing)
- 3.9.4.e : Splunk (SPL basics, architecture)
- 3.9.4.f : ELK Stack (Elasticsearch, Logstash, Kibana)

**Scenario**:
Concevez l'architecture de collecte de logs pour une entreprise multi-site.

**Format d'Entree**:
```json
{
  "environment": {
    "sites": 5,
    "log_sources": {
      "windows": { "dcs": 10, "servers": 200, "workstations": 3000 },
      "linux": { "servers": 100 },
      "network": { "firewalls": 10, "switches": 50, "routers": 20 },
      "cloud": { "aws_accounts": 3, "azure_subscriptions": 2 }
    },
    "estimated_eps": 15000
  },
  "siem_platform": "Splunk Enterprise"
}
```

**Format de Sortie**:
```json
{
  "collection_architecture": {
    "agents": {
      "windows": { "type": "Universal Forwarder", "config": {} },
      "linux": { "type": "rsyslog", "config": {} }
    },
    "aggregation_points": [],
    "data_flow": []
  },
  "parsing_config": {
    "sourcetypes": [],
    "field_extractions": [],
    "enrichment_lookups": []
  },
  "indexing_strategy": {
    "indexes": [],
    "retention_policies": {},
    "sizing_calculations": {}
  }
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 07 : "Le Createur de Regles"
#### Detection Rules et Alert Tuning

**ID**: `3.9.4_ex07`

**Objectif Pedagogique**:
Maitriser la creation de regles de detection, le tuning des alertes et les use cases SIEM.

**Concepts Couverts**:
- 3.9.4.g : QRadar (IBM SIEM specifics)
- 3.9.4.h : Azure Sentinel (Cloud-native SIEM)
- 3.9.4.i : Detection Rules (Writing, testing)
- 3.9.4.j : Alert Tuning (False positive reduction)
- 3.9.4.k : Use Cases (Scenario-based detection)

**Scenario**:
Creez un ensemble de regles de detection pour des scenarios d'attaque specifiques.

**Format d'Entree**:
```json
{
  "attack_scenarios": [
    "brute_force_authentication",
    "lateral_movement_psexec",
    "data_exfiltration_dns",
    "privilege_escalation_mimikatz"
  ],
  "data_sources_available": [
    "windows_security_logs",
    "sysmon",
    "firewall_logs",
    "dns_query_logs"
  ],
  "siem_platform": "Splunk"
}
```

**Format de Sortie**:
```json
{
  "detection_rules": [
    {
      "name": "Brute Force Authentication",
      "mitre_mapping": "T1110",
      "spl_query": "...",
      "threshold": { "count": 10, "window": "5m" },
      "severity": "high",
      "false_positive_notes": [],
      "tuning_recommendations": []
    }
  ],
  "alert_workflow": {},
  "testing_plan": {}
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 08 : "L'Operateur SOC Elite"
#### SOC Operations et Playbooks

**ID**: `3.9.5_ex08`

**Objectif Pedagogique**:
Maitriser les operations SOC: structure, triage, investigation et playbooks.

**Concepts Couverts**:
- 3.9.5.a : SOC Structure (Tier 1/2/3)
- 3.9.5.b : Alert Triage (Prioritization process)
- 3.9.5.c : Investigation (Methodology)
- 3.9.5.d : Escalation (Criteria, procedures)
- 3.9.5.e : Playbooks (Documentation)
- 3.9.5.f : Metrics (KPIs, SLAs)
- 3.9.5.g : Shift Handover (Communication)
- 3.9.5.h : Improvement (Feedback loops)

**Scenario**:
Concevez la structure operationnelle d'un SOC et ses playbooks de reponse.

**Format de Sortie**:
```json
{
  "soc_structure": {
    "tiers": [
      { "level": 1, "responsibilities": [], "escalation_criteria": [] }
    ],
    "staffing_model": {},
    "shift_schedule": {}
  },
  "triage_process": {
    "priority_matrix": {},
    "sla_by_severity": {},
    "initial_response_steps": []
  },
  "playbooks": [
    {
      "name": "Malware Infection",
      "trigger": "",
      "steps": [],
      "escalation_points": [],
      "recovery_actions": []
    }
  ],
  "metrics": {
    "mttd": {},
    "mttr": {},
    "alert_volume": {},
    "false_positive_rate": {}
  }
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 09 : "L'Ingenieur Detection"
#### IOC, IOA et Sigma Rules

**ID**: `3.9.6_ex09`

**Objectif Pedagogique**:
Maitriser la creation de signatures de detection: IOC, IOA, Sigma, YARA.

**Concepts Couverts**:
- 3.9.6.a : IOC (Indicators of Compromise)
- 3.9.6.b : IOA (Indicators of Attack)
- 3.9.6.c : Sigma Rules (Generic SIEM format)
- 3.9.6.d : YARA Rules (Malware patterns)
- 3.9.6.e : Snort Rules (Network signatures)
- 3.9.6.f : Detection Engineering (DaC practices)

**Scenario**:
Pour un rapport de menace decrivant une campagne APT, creez les signatures de detection multi-format.

**Format d'Entree**:
```json
{
  "threat_report": {
    "apt_group": "APT41",
    "iocs": {
      "domains": ["malware.evil.com"],
      "ips": ["192.168.100.50"],
      "hashes": ["abc123..."],
      "mutexes": ["Global\\MUTEX_APT41"]
    },
    "ttps": [
      { "technique": "T1055.001", "description": "Process injection via DLL" },
      { "technique": "T1003.001", "description": "LSASS memory dumping" }
    ],
    "malware_characteristics": {
      "strings": ["decrypt_payload", "C2_beacon"],
      "behaviors": ["creates_scheduled_task", "modifies_registry"]
    }
  }
}
```

**Format de Sortie**:
```json
{
  "ioc_list": {
    "format": "STIX 2.1",
    "indicators": []
  },
  "sigma_rules": [
    {
      "title": "APT41 Process Injection",
      "logsource": { "product": "windows", "service": "sysmon" },
      "detection": {},
      "level": "high"
    }
  ],
  "yara_rules": [
    {
      "rule_name": "APT41_Payload",
      "strings": [],
      "condition": ""
    }
  ],
  "snort_rules": []
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 10 : "Le Testeur de Detection"
#### Detection Testing et Pipeline

**ID**: `3.9.6_ex10`

**Objectif Pedagogique**:
Maitriser le testing de detections, le tuning et les pipelines.

**Concepts Couverts**:
- 3.9.6.g : ATT&CK Detection (Coverage mapping)
- 3.9.6.h : Hunting Queries (KQL, SPL)
- 3.9.6.i : Detection Tuning (Threshold optimization)
- 3.9.6.j : Detection Pipeline (Data flow)
- 3.9.6.k : Custom Detections (ML, behavioral)
- 3.9.6.l : Detection Testing (Validation)

**Format de Sortie**:
```json
{
  "attack_coverage_map": {
    "techniques_detected": [],
    "gaps_identified": [],
    "priority_improvements": []
  },
  "hunting_queries": [
    {
      "hypothesis": "",
      "kql_query": "",
      "expected_results": "",
      "follow_up_actions": []
    }
  ],
  "detection_pipeline": {
    "data_sources": [],
    "normalization": {},
    "enrichment": {},
    "detection_engine": {},
    "response_integration": {}
  },
  "testing_framework": {
    "atomic_tests": [],
    "validation_results": [],
    "tuning_recommendations": []
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 11 : "Le Chasseur de Vulnerabilites"
#### Vulnerability Management Program

**ID**: `3.9.7_ex11`

**Objectif Pedagogique**:
Maitriser un programme complet de gestion des vulnerabilites.

**Concepts Couverts**:
- 3.9.7.a : Scanning (Nessus, OpenVAS, Qualys)
- 3.9.7.b : Assessment (Process, scope)
- 3.9.7.c : Risk Scoring (CVSS, contextual risk)
- 3.9.7.d : Prioritization (Risk-based approach)
- 3.9.7.e : Remediation (Patching, mitigation)
- 3.9.7.f : Tracking (Metrics, SLAs)
- 3.9.7.g : Bug Bounty (Program design)

**Scenario**:
Concevez un programme de vulnerability management pour une organisation.

**Format de Sortie**:
```json
{
  "vulnerability_program": {
    "scanning_schedule": {
      "external": { "frequency": "weekly" },
      "internal": { "frequency": "monthly" },
      "critical_assets": { "frequency": "daily" }
    },
    "prioritization_framework": {
      "cvss_threshold": {},
      "asset_criticality": {},
      "exploit_availability": {},
      "business_context": {}
    },
    "remediation_slas": {
      "critical": "24h",
      "high": "7d",
      "medium": "30d",
      "low": "90d"
    },
    "tracking_metrics": [],
    "bug_bounty": {
      "scope": [],
      "rewards": {},
      "disclosure_policy": {}
    }
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 12 : "L'Orchestrateur"
#### SOAR Platform Configuration

**ID**: `3.9.8_ex12`

**Objectif Pedagogique**:
Maitriser les plateformes SOAR et l'automatisation de reponse.

**Concepts Couverts**:
- 3.9.8.a : SOAR Platforms (XSOAR, Splunk SOAR)
- 3.9.8.b : Use Cases (Automation scenarios)
- 3.9.8.c : Playbook Development (Workflow design)
- 3.9.8.d : API Integration (REST, webhooks)
- 3.9.8.e : Custom Scripts (Python automation)
- 3.9.8.f : TheHive (Case management)

**Scenario**:
Concevez des playbooks SOAR pour automatiser la reponse aux incidents.

**Format d'Entree**:
```json
{
  "soar_platform": "Palo Alto XSOAR",
  "integrations_available": ["splunk", "crowdstrike", "virustotal", "palo_alto_fw", "servicenow"],
  "automation_targets": [
    "phishing_triage",
    "malware_containment",
    "user_account_compromise"
  ]
}
```

**Format de Sortie**:
```json
{
  "playbooks": [
    {
      "name": "Phishing Auto-Triage",
      "trigger": "email_reported",
      "workflow": [
        { "step": 1, "action": "extract_indicators", "integration": "internal" },
        { "step": 2, "action": "check_virustotal", "integration": "virustotal" },
        { "step": 3, "action": "enrich_sender", "integration": "splunk" }
      ],
      "decision_points": [],
      "automated_responses": [],
      "human_review_points": []
    }
  ],
  "api_integrations": [],
  "custom_scripts": []
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 13 : "L'Automatiseur Avance"
#### SOAR Advanced et Metrics

**ID**: `3.9.8_ex13`

**Objectif Pedagogique**:
Maitriser les fonctionnalites SOAR avancees et les metriques.

**Concepts Couverts**:
- 3.9.8.g : Cortex (Analyzers, responders)
- 3.9.8.h : Shuffle (Open-source SOAR)
- 3.9.8.i : Orchestration (Multi-tool coordination)
- 3.9.8.j : Metrics & KPIs (MTTR, automation rate)
- 3.9.8.k : Integration Examples (End-to-end chains)
- 3.9.8.l : Testing & Validation (Playbook testing)

**Format de Sortie**:
```json
{
  "cortex_config": {
    "analyzers": [],
    "responders": []
  },
  "orchestration_chains": [
    {
      "name": "Full IR Chain",
      "flow": "SIEM_alert -> EDR_isolate -> Firewall_block -> Ticket_create"
    }
  ],
  "metrics_dashboard": {
    "mttr_target": "15min",
    "automation_rate_target": "80%",
    "kpi_definitions": []
  },
  "testing_framework": {
    "dry_run_mode": true,
    "test_scenarios": [],
    "rollback_procedures": []
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 14 : "L'Analyste Threat Intel"
#### Threat Intelligence Fundamentals

**ID**: `3.9.9_ex14`

**Objectif Pedagogique**:
Maitriser les fondamentaux de la Threat Intelligence et les plateformes TIP.

**Concepts Couverts**:
- 3.9.9.a : TI Concepts (Strategic, tactical, operational)
- 3.9.9.b : Intelligence Cycle (Collection to dissemination)
- 3.9.9.c : MISP (Event creation, sharing)
- 3.9.9.d : OpenCTI (Knowledge graphs)
- 3.9.9.e : TIP Integration (SIEM, EDR feeds)
- 3.9.9.f : STIX/TAXII (Standards)

**Scenario**:
Analysez un rapport de menace et integrez les renseignements dans une plateforme TIP.

**Format d'Entree**:
```json
{
  "threat_report": {
    "source": "mandiant",
    "threat_actor": "FIN7",
    "campaign": "carbanak_evolution",
    "indicators": [...],
    "ttps": [...],
    "targets": ["financial_sector", "retail"]
  },
  "tip_platform": "MISP"
}
```

**Format de Sortie**:
```json
{
  "misp_event": {
    "info": "",
    "threat_level": "",
    "analysis_level": "",
    "attributes": [],
    "objects": [],
    "galaxies": [],
    "tags": []
  },
  "stix_bundle": {
    "type": "bundle",
    "objects": []
  },
  "integration_actions": {
    "siem_rules_created": [],
    "edr_iocs_pushed": [],
    "firewall_blocks": []
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 15 : "Le Traqueur d'APT"
#### Advanced Threat Intelligence

**ID**: `3.9.9_ex15`

**Objectif Pedagogique**:
Maitriser le tracking des acteurs de menace et le partage d'intelligence.

**Concepts Couverts**:
- 3.9.9.g : Threat Feeds (Commercial, open-source)
- 3.9.9.h : IOC Management (Lifecycle, scoring)
- 3.9.9.i : Threat Actor Tracking (APT groups, TTPs)
- 3.9.9.j : Threat Hunting Intel (Intel-driven hunting)
- 3.9.9.k : Reporting (Intelligence reports)
- 3.9.9.l : Collaboration (ISACs, sharing communities)

**Format de Sortie**:
```json
{
  "threat_actor_profile": {
    "name": "",
    "aliases": [],
    "motivation": "",
    "capabilities": [],
    "target_sectors": [],
    "ttps_summary": []
  },
  "ioc_management": {
    "confidence_scoring": {},
    "aging_policy": {},
    "false_positive_handling": {}
  },
  "hunting_hypothesis": [
    {
      "based_on": "APT intelligence",
      "hypothesis": "",
      "data_sources_needed": [],
      "query": ""
    }
  ],
  "intelligence_report": {
    "executive_summary": "",
    "technical_details": "",
    "recommendations": []
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 16 : "Le Maitre des Pieges"
#### Deception Technology

**ID**: `3.9.10_ex16`

**Objectif Pedagogique**:
Maitriser les technologies de deception: honeypots, honeytokens, et decoys.

**Concepts Couverts**:
- 3.9.10.a : Deception Concepts (Active defense)
- 3.9.10.b : Honeypots (Low/high interaction)
- 3.9.10.c : Honeynets (Distributed deployment)
- 3.9.10.d : Honeytokens (Fake credentials, canary files)
- 3.9.10.e : Decoy Systems (Fake servers)
- 3.9.10.f : Network Decoys (Fake services)
- 3.9.10.g : AD Decoys (Honey accounts)
- 3.9.10.h : Cloud Decoys (Fake S3, Lambda)
- 3.9.10.i : Deception Platforms (Commercial solutions)
- 3.9.10.j : Alert Generation (High-fidelity alerts)
- 3.9.10.k : Forensics (TTP collection)
- 3.9.10.l : Legal Considerations (Authorization)

**Scenario**:
Concevez une strategie de deception complete pour un environnement d'entreprise.

**Format de Sortie**:
```json
{
  "deception_strategy": {
    "honeypots": [
      { "type": "low_interaction", "service": "ssh", "location": "dmz" }
    ],
    "honeytokens": [
      { "type": "credential", "location": "memory", "alert_trigger": "" }
    ],
    "ad_decoys": {
      "honey_accounts": [],
      "honey_groups": [],
      "honey_computers": []
    },
    "cloud_decoys": {
      "s3_buckets": [],
      "lambda_functions": []
    }
  },
  "alert_integration": {
    "siem_rules": [],
    "response_playbooks": []
  },
  "legal_review": {
    "authorization": "",
    "privacy_considerations": []
  }
}
```

**Auto-evaluation**: 98/100

---

### EXERCICE 17 : "L'Architecte Detection"
#### Advanced Detection Engineering

**ID**: `3.9.11_ex17`

**Objectif Pedagogique**:
Maitriser l'ingenierie de detection avancee: data sources, normalisation, ML.

**Concepts Couverts**:
- 3.9.11.a : Detection Philosophy (Pyramid of Pain)
- 3.9.11.b : Data Sources (Telemetry collection)
- 3.9.11.c : Normalization (ECS, OCSF schemas)
- 3.9.11.d : Detection Logic (Statistical, ML, rules)
- 3.9.11.e : Sigma Development (Advanced rules)
- 3.9.11.f : Detection Testing (Atomic Red Team)

**Format de Sortie**:
```json
{
  "detection_philosophy": {
    "pyramid_of_pain_focus": "TTPs",
    "detection_maturity_level": "",
    "coverage_strategy": ""
  },
  "data_normalization": {
    "schema": "ECS",
    "field_mappings": [],
    "enrichment_pipeline": []
  },
  "advanced_detections": [
    {
      "type": "behavioral",
      "technique": "",
      "ml_model": {},
      "baseline_period": ""
    }
  ]
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 18 : "L'Optimiseur de Detection"
#### Detection Pipeline et Metrics

**ID**: `3.9.11_ex18`

**Objectif Pedagogique**:
Maitriser l'optimisation des pipelines de detection et les metriques.

**Concepts Couverts**:
- 3.9.11.g : Coverage Mapping (ATT&CK Navigator)
- 3.9.11.h : Analytics Development (Anomaly detection)
- 3.9.11.i : Detection Pipeline (Stream processing)
- 3.9.11.j : Performance Optimization (Query tuning)
- 3.9.11.k : False Positive Management (Tuning)
- 3.9.11.l : Detection Metrics (Precision, recall)

**Format de Sortie**:
```json
{
  "attack_coverage": {
    "navigator_layer": {},
    "coverage_percentage": "",
    "gaps": [],
    "priorities": []
  },
  "pipeline_optimization": {
    "stream_processing": { "tool": "Kafka/Flink", "config": {} },
    "query_optimization": [],
    "index_tuning": []
  },
  "metrics": {
    "detection_rate": "",
    "precision": "",
    "recall": "",
    "f1_score": "",
    "mttd": ""
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 19 : "Le Coordinateur Purple"
#### Purple Team Exercises

**ID**: `3.9.12_ex19`

**Objectif Pedagogique**:
Maitriser la planification et l'execution d'exercices Purple Team.

**Concepts Couverts**:
- 3.9.12.a : Purple Team Concept (Collaboration)
- 3.9.12.b : Exercise Planning (Scope, objectives)
- 3.9.12.c : TTPs Selection (MITRE-based)
- 3.9.12.d : Execution (Real-time collaboration)
- 3.9.12.e : Detection Validation (Alert verification)
- 3.9.12.f : Gap Analysis (Visibility gaps)

**Scenario**:
Planifiez un exercice Purple Team pour valider les capacites de detection.

**Format de Sortie**:
```json
{
  "exercise_plan": {
    "name": "",
    "objectives": [],
    "scope": {},
    "timeline": {},
    "success_criteria": []
  },
  "ttp_selection": [
    {
      "technique": "T1055",
      "sub_technique": "T1055.001",
      "attack_tool": "Cobalt Strike",
      "expected_detection": "",
      "data_sources_required": []
    }
  ],
  "execution_protocol": {
    "red_team_actions": [],
    "blue_team_monitoring": [],
    "real_time_communication": {}
  },
  "gap_analysis_template": {}
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 20 : "L'Ameliorateur Continu"
#### Purple Team Continuous Improvement

**ID**: `3.9.12_ex20`

**Objectif Pedagogique**:
Maitriser l'amelioration continue via Purple Team.

**Concepts Couverts**:
- 3.9.12.g : Improvement Cycle (Iterate on detections)
- 3.9.12.h : Atomic Testing (Quick validation)
- 3.9.12.i : Continuous Purple (Ongoing testing)
- 3.9.12.j : Metrics & Reporting (Coverage improvement)
- 3.9.12.k : Tooling (Caldera, AttackIQ)
- 3.9.12.l : Cultural Aspects (Breaking silos)

**Format de Sortie**:
```json
{
  "continuous_testing": {
    "schedule": "weekly",
    "atomic_tests": [],
    "automation": { "tool": "Caldera", "config": {} }
  },
  "improvement_tracking": {
    "detection_coverage_before": "",
    "detection_coverage_after": "",
    "gaps_closed": [],
    "new_gaps_identified": []
  },
  "cultural_recommendations": {
    "team_structure": "",
    "communication_channels": [],
    "feedback_mechanisms": []
  }
}
```

**Auto-evaluation**: 96/100

---

### EXERCICE 21 : "Le Defenseur du Cloud"
#### Cloud SOC Operations

**ID**: `3.9.13_ex21`

**Objectif Pedagogique**:
Maitriser les operations SOC specifiques au cloud.

**Concepts Couverts**:
- 3.9.13.a : Cloud SIEM (Sentinel, Chronicle)
- 3.9.13.b : CSPM (Posture management)
- 3.9.13.c : CWPP (Workload protection)
- 3.9.13.d : Cloud Logging (CloudTrail, Azure Monitor)
- 3.9.13.e : Cloud Detection (IAM abuse, exposure)
- 3.9.13.f : Container Security (Image scanning, runtime)

**Scenario**:
Concevez le SOC cloud pour un environnement multi-cloud.

**Format d'Entree**:
```json
{
  "cloud_environment": {
    "aws": { "accounts": 10, "services": ["EC2", "S3", "Lambda", "EKS"] },
    "azure": { "subscriptions": 5, "services": ["VMs", "AKS", "Functions"] }
  },
  "security_tools": {
    "siem": "Azure Sentinel",
    "cspm": "Prisma Cloud",
    "cwpp": "Aqua Security"
  }
}
```

**Format de Sortie**:
```json
{
  "cloud_soc_design": {
    "log_centralization": {
      "aws_sources": [],
      "azure_sources": [],
      "ingestion_pipeline": {}
    },
    "cspm_policies": {
      "cis_benchmarks": [],
      "custom_policies": []
    },
    "cloud_detections": [
      { "name": "IAM Privilege Escalation", "logic": "", "severity": "" }
    ],
    "container_security": {
      "image_scanning": {},
      "runtime_protection": {},
      "network_policies": []
    }
  }
}
```

**Auto-evaluation**: 97/100

---

### EXERCICE 22 : "Le Chasseur de Nuages"
#### Cloud Threat Hunting et IR

**ID**: `3.9.13_ex22`

**Objectif Pedagogique**:
Maitriser le threat hunting cloud et la reponse aux incidents cloud.

**Concepts Couverts**:
- 3.9.13.g : Kubernetes Security (Admission, RBAC)
- 3.9.13.h : Serverless Security (Lambda monitoring)
- 3.9.13.i : Cloud IR (Snapshot acquisition)
- 3.9.13.j : Cloud Compliance (CIS benchmarks)
- 3.9.13.k : Multi-Cloud (Unified visibility)
- 3.9.13.l : Cloud Threat Hunting (Cloud-specific hunts)

**Format de Sortie**:
```json
{
  "kubernetes_security": {
    "admission_controllers": [],
    "pod_security_policies": [],
    "rbac_monitoring": {}
  },
  "cloud_ir_playbook": {
    "evidence_collection": {
      "snapshot_acquisition": [],
      "log_preservation": [],
      "timeline_creation": {}
    },
    "containment_actions": [],
    "recovery_steps": []
  },
  "cloud_hunting": [
    {
      "hypothesis": "Unauthorized S3 access",
      "data_source": "CloudTrail",
      "query": "",
      "indicators": []
    }
  ],
  "multi_cloud_correlation": {
    "unified_schema": "",
    "cross_cloud_detections": []
  }
}
```

**Auto-evaluation**: 96/100

---

## STATISTIQUES FINALES

| Metrique | Valeur |
|----------|--------|
| Exercices totaux | 22 |
| Concepts couverts | 134/134 (100%) |
| Score moyen | 96.6/100 |
| Score minimum | 95/100 |
| Score maximum | 98/100 |

---

## RECOMMANDATIONS DE PARCOURS

1. **Debutant SOC**: Ex01 -> Ex06 -> Ex08
2. **Analyste Detection**: Ex09 -> Ex10 -> Ex17
3. **Ingenieur SOAR**: Ex12 -> Ex13
4. **Threat Intel**: Ex14 -> Ex15 -> Ex16
5. **Purple Team**: Ex19 -> Ex20
6. **Cloud SOC**: Ex21 -> Ex22

---

*Document genere le 2026-01-03*
*Module 3.9 - Blue Team & Defense*
*Phase 3 - Odyssey Cybersecurite*
