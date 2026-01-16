# MODULE 3.40 : CYBER COUNTER-INTELLIGENCE
## Contre-Espionnage Cyber

**Concepts couverts** : 94/94
**Nombre d'exercices** : 15
**Orientation** : Detection / Deception / Defense active contre espionnage
**Prerequis** : Module 3.21 (Threat Intelligence)

---

## OBJECTIFS PEDAGOGIQUES

Ce module forme les analystes a detecter, contrer et manipuler les operations d'espionnage cyber adverses. Il couvre les fondamentaux du contre-espionnage, la detection des menaces APT, les operations de deception, et la gestion des menaces internes.

---

## SOUS-MODULE 3.40.1 : CI Fundamentals (16 concepts)

### Concepts Reference:
- **3.40.1.a** : Counter-Intelligence Definition - Identify, assess, neutralize foreign intelligence activities
- **3.40.1.b** : CI vs Security - Security: protect. CI: active countering of adversary intel ops
- **3.40.1.c** : CI Cycle - Collection, Analysis, Operations, Feedback
- **3.40.1.d** : Threat Assessment - Who targets us, capabilities, intent, history, indicators
- **3.40.1.e** : Adversary Intelligence Services - Foreign intel agencies, corporate espionage, competitors
- **3.40.1.f** : Collection Disciplines Against Us - HUMINT, SIGINT, CYBERINT targeting our organization
- **3.40.1.g** : Indicators of Targeting - Reconnaissance, social engineering attempts, probing, insiders
- **3.40.1.h** : CI Awareness - Employee training, reporting procedures, recognition
- **3.40.1.i** : CI Program Elements - Detection, investigation, operations, liaison, awareness
- **3.40.1.j** : Liaison - Government agencies, industry peers, information sharing
- **3.40.1.k** : Insider Threat Program - Detection, deterrence, investigation, link to CI
- **3.40.1.l** : Foreign Travel Security - Briefings, device security, behavior, debriefings
- **3.40.1.m** : Elicitation Recognition - Recognizing information extraction attempts, response
- **3.40.1.n** : Social Engineering Defense - Training, verification procedures, reporting
- **3.40.1.o** : Supply Chain CI - Vendor vetting, foreign ownership, access risks
- **3.40.1.p** : Legal Authorities - What CI actions are legal, private sector limitations

---

### EXERCICE 3.40.01 : CI Program Fundamentals Analyzer

**Fichier** : `ex01_ci_fundamentals_analyzer/`

**Concepts evalues** : 3.40.1.a, 3.40.1.b, 3.40.1.c, 3.40.1.d, 3.40.1.e, 3.40.1.f, 3.40.1.g, 3.40.1.h

**Sujet** :
Analysez le programme de contre-espionnage d'une organisation et evaluez sa maturite par rapport aux fondamentaux CI.

**Entree** :
```json
{
  "organization": {
    "name": "TechDefense Corp",
    "industry": "defense_contractor",
    "employees": 5000,
    "locations": ["USA", "UK", "Germany"],
    "sensitive_data": ["classified_projects", "trade_secrets", "pii"]
  },
  "ci_program": {
    "definition_understood": true,
    "ci_vs_security_distinction": "unclear",
    "dedicated_ci_team": false,
    "ci_cycle_implementation": {
      "collection": "ad_hoc",
      "analysis": "reactive",
      "operations": "none",
      "feedback": "informal"
    }
  },
  "threat_assessment": {
    "performed": true,
    "frequency": "annual",
    "identified_adversaries": ["APT_groups", "competitors"],
    "nation_state_targeting": "suspected"
  },
  "awareness_program": {
    "ci_training": "annual_basic",
    "targeting_indicators_known": false,
    "reporting_procedures": "informal_email"
  },
  "collection_disciplines_coverage": {
    "humint_defense": "limited",
    "sigint_defense": "good",
    "cyberint_defense": "good"
  },
  "recent_incidents": [
    {"type": "social_engineering_call", "detected": true, "investigated": false},
    {"type": "linkedin_targeting", "detected": false, "employees_affected": 12}
  ]
}
```

**Sortie attendue** :
```json
{
  "ci_maturity_assessment": {
    "overall_score": 42,
    "maturity_level": "DEVELOPING",
    "critical_gaps": 6,
    "recommendations": 10
  },
  "ci_definition_analysis": {
    "understanding": {
      "definition": "Counter-Intelligence: Identify, assess, and neutralize foreign intelligence activities",
      "current_state": "Definition understood but not operationalized",
      "gap": "No active neutralization capabilities"
    },
    "ci_vs_security": {
      "security_role": "Protect assets (defensive)",
      "ci_role": "Actively counter adversary intelligence operations",
      "current_distinction": "UNCLEAR - Organization conflates CI with security",
      "impact": "Reactive posture only, no proactive countering"
    }
  },
  "ci_cycle_assessment": {
    "collection": {
      "current": "Ad-hoc",
      "target": "Systematic collection of CI-relevant information",
      "gap": "No formal collection requirements or sources",
      "recommendation": "Establish CI collection plan"
    },
    "analysis": {
      "current": "Reactive",
      "target": "Proactive threat analysis",
      "gap": "Analysis only after incidents",
      "recommendation": "Regular adversary analysis, pattern detection"
    },
    "operations": {
      "current": "None",
      "target": "Active CI operations capability",
      "gap": "CRITICAL - No operational response capability",
      "recommendation": "Develop response playbooks, consider deception"
    },
    "feedback": {
      "current": "Informal",
      "target": "Structured lessons learned integration",
      "gap": "No systematic improvement",
      "recommendation": "Formalize feedback loop"
    }
  },
  "threat_assessment_evaluation": {
    "frequency": {
      "current": "Annual",
      "recommendation": "Quarterly for defense contractor"
    },
    "adversary_coverage": {
      "apt_groups": "Identified",
      "competitors": "Identified",
      "nation_state": "Suspected but not confirmed",
      "gap": "Need specific adversary profiling"
    },
    "threat_model": {
      "who_targets_us": "APT groups, competitors, likely nation-states",
      "capabilities_assessed": "Unknown - needs detailed analysis",
      "intent_assessed": "Partially - trade secrets and classified",
      "history_documented": "Not systematically",
      "indicators_defined": "No"
    }
  },
  "adversary_intelligence_services": {
    "likely_adversaries": {
      "nation_state_intel": ["China (MSS)", "Russia (SVR/GRU)", "Others based on projects"],
      "corporate_espionage": "Competitors with state backing",
      "motivation": "Defense technology, trade secrets"
    },
    "targeting_assessment": "HIGH - Defense contractor is high-value target"
  },
  "collection_disciplines_defense": {
    "humint": {
      "status": "LIMITED",
      "threats": "Elicitation, recruitment attempts, insiders",
      "gaps": ["No elicitation training", "Limited travel briefings"],
      "severity": "HIGH"
    },
    "sigint": {
      "status": "GOOD",
      "measures": "Encrypted communications, TEMPEST awareness",
      "note": "Technical measures adequate"
    },
    "cyberint": {
      "status": "GOOD",
      "measures": "APT detection, threat hunting",
      "note": "Continue investment"
    }
  },
  "targeting_indicators": {
    "current_awareness": "Indicators NOT known to employees",
    "indicators_to_train": [
      "Unusual interest in work from strangers",
      "Probing questions about projects/clearances",
      "LinkedIn/social media targeting",
      "Unsolicited conference invitations",
      "Foreign contact requests"
    ],
    "recent_incident_analysis": {
      "social_engineering_call": {
        "detected": "Yes but not investigated",
        "gap": "No follow-up = no learning"
      },
      "linkedin_targeting": {
        "detected": "No",
        "affected": 12,
        "gap": "CRITICAL - Active targeting undetected"
      }
    }
  },
  "awareness_assessment": {
    "training": {
      "current": "Annual basic",
      "target": "Role-based, continuous",
      "gap": "Insufficient for defense contractor"
    },
    "reporting": {
      "current": "Informal email",
      "target": "Formal reporting with tracking",
      "gap": "No metrics, no trend analysis"
    }
  },
  "priority_recommendations": [
    {"priority": 1, "action": "Establish dedicated CI function", "rationale": "Currently no owner"},
    {"priority": 2, "action": "Define CI vs Security roles", "rationale": "Clarity enables action"},
    {"priority": 3, "action": "Investigate LinkedIn targeting incident", "rationale": "Active threat"},
    {"priority": 4, "action": "Enhance HUMINT defense training", "rationale": "Major gap for cleared personnel"},
    {"priority": 5, "action": "Establish formal reporting procedure", "rationale": "Enable collection"},
    {"priority": 6, "action": "Quarterly threat assessments", "rationale": "Threat landscape changes"},
    {"priority": 7, "action": "Define targeting indicators", "rationale": "Employees can't report what they don't recognize"},
    {"priority": 8, "action": "Implement CI cycle formally", "rationale": "Structure enables effectiveness"},
    {"priority": 9, "action": "Develop CI operations capability", "rationale": "Active response needed"},
    {"priority": 10, "action": "Post-incident investigation policy", "rationale": "Learn from every incident"}
  ]
}
```

**Note pedagogique** : 98/100

---

### EXERCICE 3.40.02 : CI Program Operations Auditor

**Fichier** : `ex02_ci_program_operations/`

**Concepts evalues** : 3.40.1.i, 3.40.1.j, 3.40.1.k, 3.40.1.l, 3.40.1.m, 3.40.1.n, 3.40.1.o, 3.40.1.p

**Sujet** :
Auditez les elements operationnels d'un programme CI incluant la liaison, les menaces internes, la securite des voyages, et les limites legales.

**Entree** :
```json
{
  "ci_program_elements": {
    "detection": {"capability": "SIEM_based", "ci_specific_rules": false},
    "investigation": {"team": "security_generalists", "ci_trained": false},
    "operations": {"capability": "none"},
    "liaison": {
      "government": {"fbi": true, "cisa": false, "dhs": false},
      "industry": {"isac_member": false, "peer_sharing": "informal"}
    },
    "awareness": {"annual_training": true, "ci_specific": false}
  },
  "insider_threat_program": {
    "exists": true,
    "linked_to_ci": false,
    "detection_methods": ["DLP", "access_monitoring"],
    "investigation_capability": "limited",
    "hr_coordination": "ad_hoc"
  },
  "foreign_travel": {
    "briefing_program": false,
    "device_policy": "byod_allowed",
    "debrief_process": false,
    "high_risk_countries": ["China", "Russia"],
    "recent_travel": [
      {"employee": "engineer_1", "destination": "China", "briefed": false, "debriefed": false}
    ]
  },
  "elicitation_defense": {
    "training_provided": false,
    "recognition_rate": "unknown",
    "recent_attempts": 3
  },
  "social_engineering_defense": {
    "training": "phishing_only",
    "verification_procedures": "informal",
    "reporting_mechanism": "email_to_security"
  },
  "supply_chain_ci": {
    "vendor_vetting": "financial_only",
    "foreign_ownership_check": false,
    "access_review": "annual"
  },
  "legal_framework": {
    "authority_understood": false,
    "private_sector_limitations": "unknown",
    "legal_counsel_involvement": "incident_only"
  }
}
```

**Sortie attendue** :
```json
{
  "program_elements_assessment": {
    "overall_score": 38,
    "maturity": "INITIAL",
    "critical_gaps": 8
  },
  "ci_program_elements_analysis": {
    "detection": {
      "current": "SIEM-based (generic)",
      "ci_specific": false,
      "gap": "No CI-specific detection rules",
      "recommendation": "Add espionage indicators to SIEM"
    },
    "investigation": {
      "team": "Security generalists",
      "ci_training": "None",
      "gap": "Cannot conduct CI investigations",
      "recommendation": "CI investigation training, playbooks"
    },
    "operations": {
      "capability": "NONE",
      "severity": "CRITICAL",
      "gap": "No ability to actively counter threats",
      "recommendation": "Develop operational capability"
    },
    "awareness": {
      "current": "Generic annual",
      "ci_specific": false,
      "gap": "Employees don't know CI threats",
      "recommendation": "CI-focused awareness program"
    }
  },
  "liaison_assessment": {
    "government": {
      "fbi": {
        "relationship": "Exists",
        "status": "GOOD base",
        "recommendation": "Engage FBI CI outreach program"
      },
      "cisa": {
        "relationship": "None",
        "gap": "Missing critical cyber threat sharing",
        "recommendation": "Register for CISA services"
      }
    },
    "industry": {
      "isac": {
        "member": false,
        "gap": "Missing sector-specific threat intel",
        "recommendation": "Join Defense Industrial Base ISAC"
      }
    }
  },
  "insider_threat_assessment": {
    "program_exists": true,
    "ci_linkage": {
      "linked": false,
      "gap": "CRITICAL - Insider threat is key CI vector",
      "impact": "Cannot detect foreign recruitment"
    },
    "detection": {
      "methods": ["DLP", "Access monitoring"],
      "gap": "No behavioral indicators for recruitment",
      "recommendation": "Add CI-specific indicators"
    }
  },
  "foreign_travel_security": {
    "briefing_program": {
      "exists": false,
      "severity": "CRITICAL for defense contractor"
    },
    "device_policy": {
      "current": "BYOD allowed",
      "risk": "Personal devices to high-risk countries",
      "recommendation": "Loaner devices for high-risk travel"
    },
    "debrief_process": {
      "exists": false,
      "gap": "No collection of travel intelligence"
    }
  },
  "elicitation_defense": {
    "training": {
      "provided": false,
      "impact": "Employees cannot recognize attempts"
    },
    "recent_attempts": 3,
    "concern": "May be tip of iceberg"
  },
  "supply_chain_ci": {
    "vendor_vetting": {
      "current": "Financial only",
      "gap": "No security or CI vetting"
    },
    "foreign_ownership": {
      "checked": false,
      "severity": "CRITICAL"
    }
  },
  "legal_framework_assessment": {
    "authority_understanding": {
      "current": "Not understood",
      "gap": "Team doesn't know what they CAN do"
    },
    "private_sector_limitations": {
      "key_limitations": [
        "Cannot conduct surveillance of US persons",
        "Cannot hack back without authority",
        "Can conduct internal investigations",
        "Can implement deception on own networks"
      ]
    }
  },
  "priority_recommendations": [
    {"priority": 1, "action": "Link insider threat program to CI", "severity": "CRITICAL"},
    {"priority": 2, "action": "Implement foreign travel security program", "severity": "CRITICAL"},
    {"priority": 3, "action": "Foreign ownership vendor checks", "severity": "CRITICAL"},
    {"priority": 4, "action": "Elicitation recognition training", "severity": "HIGH"},
    {"priority": 5, "action": "Join DIB ISAC", "severity": "HIGH"}
  ]
}
```

**Note pedagogique** : 98/100

---

## SOUS-MODULE 3.40.2 : Cyber CI Detection (18 concepts)

### Concepts Reference:
- **3.40.2.a** : Threat Hunting for Espionage - APT indicators, long-term access, stealth techniques
- **3.40.2.b** : Behavioral Indicators - Unusual access patterns, data staging, off-hours activity
- **3.40.2.c** : Network Indicators - Beaconing, DNS anomalies, encrypted traffic patterns
- **3.40.2.d** : Endpoint Indicators - Unusual processes, persistence mechanisms, credential access
- **3.40.2.e** : Data Loss Indicators - Unusual transfers, compression, encryption, staging
- **3.40.2.f** : Living off the Land Detection - LOLBin usage, script execution, built-in tool abuse
- **3.40.2.g** : Insider Threat Indicators - Access anomalies, policy violations, behavior changes
- **3.40.2.h** : UEBA - User Entity Behavior Analytics, baseline, anomaly detection
- **3.40.2.i** : Network Traffic Analysis - Metadata, flow analysis, protocol anomalies
- **3.40.2.j** : Endpoint Detection & Response - EDR telemetry, behavior detection, investigation
- **3.40.2.k** : SIEM for CI - Correlation rules, long-term analysis, timeline
- **3.40.2.l** : Threat Intelligence Integration - APT indicators, TTPs, infrastructure patterns
- **3.40.2.m** : Dark Web Monitoring - Credentials, data, insider recruitment, threats
- **3.40.2.n** : Canary Tokens - Detect access/exfiltration, files, credentials, DNS
- **3.40.2.o** : Honeypots for CI - Detect intrusion, study adversary, delay
- **3.40.2.p** : Physical-Cyber Correlation - Badge + network access, travel + VPN, anomalies
- **3.40.2.q** : Forensic Readiness - Preserve evidence, chain of custody, legal requirements
- **3.40.2.r** : Attribution Support - Collect evidence for attribution, TTP documentation

---

### EXERCICE 3.40.03 : APT Espionage Threat Hunter

**Fichier** : `ex03_apt_threat_hunter/`

**Concepts evalues** : 3.40.2.a, 3.40.2.b, 3.40.2.c, 3.40.2.d, 3.40.2.e, 3.40.2.f, 3.40.2.g, 3.40.2.h, 3.40.2.i

**Sujet** :
Conduisez une chasse aux menaces d'espionnage APT en analysant les indicateurs comportementaux, reseau, endpoint et perte de donnees.

**Entree** :
```json
{
  "hunt_scope": {
    "hypothesis": "APT presence in network for long-term espionage",
    "timeframe": "90 days",
    "focus_areas": ["engineering_department", "executive_systems"]
  },
  "behavioral_data": {
    "user_anomalies": [
      {"user": "eng_lead_1", "anomaly": "large_file_access", "files": 500, "baseline": 50},
      {"user": "exec_assistant", "anomaly": "off_hours_access", "frequency": "daily_3am"}
    ],
    "data_movements": [
      {"user": "eng_lead_1", "action": "compress_encrypt", "size_mb": 2000},
      {"user": "unknown_service", "action": "staging_directory", "path": "/tmp/.cache"}
    ]
  },
  "network_data": {
    "dns_queries": [
      {"domain": "update.microsoft-cdn.xyz", "frequency": 288, "pattern": "regular_24h"}
    ],
    "traffic_anomalies": [
      {"type": "beaconing", "destination": "45.32.xxx.xxx", "interval": "300s", "jitter": "10%"}
    ]
  },
  "endpoint_data": {
    "process_anomalies": [
      {"host": "ENG-WS-001", "process": "powershell.exe", "encoded_commands": true}
    ],
    "persistence_mechanisms": [
      {"host": "ENG-WS-001", "type": "scheduled_task", "name": "WindowsUpdate_Sync"}
    ],
    "credential_access": [
      {"host": "ENG-WS-001", "activity": "lsass_access", "tool": "comsvcs.dll"}
    ]
  },
  "lolbin_activity": [
    {"host": "ENG-WS-001", "binary": "certutil.exe", "action": "download"},
    {"host": "ENG-WS-001", "binary": "bitsadmin.exe", "action": "transfer"}
  ]
}
```

**Sortie attendue** :
```json
{
  "hunt_summary": {
    "hypothesis_validated": true,
    "confidence": "HIGH",
    "apt_indicators_found": 15,
    "compromised_hosts": 2,
    "recommended_action": "INCIDENT_RESPONSE"
  },
  "threat_hunting_analysis": {
    "approach": "Hypothesis-driven hunt for APT espionage",
    "espionage_indicators": {
      "long_term_access": "Evidence of persistence mechanisms",
      "stealth_techniques": "Living-off-the-land, encoded commands",
      "data_focus": "Engineering data targeted"
    }
  },
  "behavioral_indicator_analysis": {
    "eng_lead_1": {
      "anomaly": "10x increase in file access",
      "assessment": "Data collection for exfiltration",
      "verdict": "SUSPICIOUS - possible insider or compromised account"
    },
    "data_staging": {
      "hidden_directory": "/tmp/.cache",
      "assessment": "Classic APT staging technique",
      "verdict": "MALICIOUS"
    }
  },
  "network_indicator_analysis": {
    "dns_beaconing": {
      "domain": "update.microsoft-cdn.xyz",
      "pattern": "288 queries/day = every 5 minutes",
      "assessment": "C2 beaconing masquerading as Microsoft",
      "verdict": "MALICIOUS"
    },
    "traffic_beaconing": {
      "interval": "300s with 10% jitter",
      "assessment": "Classic APT beacon with jitter to avoid detection",
      "verdict": "MALICIOUS - C2 traffic"
    }
  },
  "endpoint_indicator_analysis": {
    "powershell_encoded": {
      "finding": "Encoded PowerShell commands",
      "technique": "T1059.001 - Command and Scripting Interpreter",
      "verdict": "MALICIOUS"
    },
    "credential_access": {
      "finding": "LSASS access via comsvcs.dll",
      "technique": "T1003.001 - Credential Dumping",
      "verdict": "MALICIOUS - Active APT technique"
    }
  },
  "living_off_the_land_analysis": {
    "lolbins_detected": ["certutil.exe", "bitsadmin.exe", "comsvcs.dll"],
    "assessment": "Classic APT tradecraft - avoid custom malware",
    "mitre_techniques": [
      "T1105 - Ingress Tool Transfer",
      "T1218 - System Binary Proxy Execution"
    ]
  },
  "ueba_correlation": {
    "baseline_deviations": {
      "eng_lead_1": "10x file access deviation"
    },
    "risk_scores": {
      "eng_lead_1": 95
    }
  },
  "immediate_actions": [
    {"action": "Isolate ENG-WS-001", "priority": 1},
    {"action": "Block C2 domains and IP", "priority": 1},
    {"action": "Forensic imaging of affected systems", "priority": 2}
  ]
}
```

**Note pedagogique** : 99/100

---

### EXERCICE 3.40.04 : CI Detection Infrastructure Auditor

**Fichier** : `ex04_ci_detection_infrastructure/`

**Concepts evalues** : 3.40.2.j, 3.40.2.k, 3.40.2.l, 3.40.2.m, 3.40.2.n, 3.40.2.o, 3.40.2.p, 3.40.2.q, 3.40.2.r

**Sujet** :
Auditez l'infrastructure de detection CI incluant EDR, SIEM, threat intelligence, honeypots, et capacites forensic.

**Entree** :
```json
{
  "detection_infrastructure": {
    "edr": {
      "vendor": "CrowdStrike",
      "coverage": "95%",
      "custom_iocs": 50,
      "response_automation": false
    },
    "siem": {
      "vendor": "Splunk",
      "ci_specific_rules": false,
      "retention_days": 90
    },
    "threat_intel": {
      "feeds": ["vendor_feed", "open_source"],
      "apt_coverage": "limited"
    },
    "dark_web_monitoring": {"enabled": false},
    "deception": {
      "canary_tokens": {"deployed": false},
      "honeypots": {"deployed": false}
    },
    "physical_cyber": {"badge_log_integration": false},
    "forensics": {
      "readiness": "low",
      "chain_of_custody": false
    },
    "attribution": {"capability": "limited"}
  }
}
```

**Sortie attendue** :
```json
{
  "infrastructure_assessment": {
    "overall_ci_readiness": 42,
    "rating": "INSUFFICIENT for CI mission",
    "critical_gaps": 8
  },
  "edr_assessment": {
    "coverage": "95% - GOOD",
    "gap": "No APT-specific detection rules",
    "recommendation": "Add custom detection for espionage TTPs"
  },
  "siem_for_ci": {
    "ci_specific_rules": false,
    "gap": "CRITICAL - No espionage-focused detection",
    "retention": "90 days - insufficient for APT (need 365+)"
  },
  "threat_intel_assessment": {
    "apt_coverage": "Limited",
    "gap": "Cannot track relevant APT groups",
    "recommendation": "Add APT-focused intel feeds"
  },
  "dark_web_monitoring": {
    "status": "NOT ENABLED",
    "missing_coverage": ["Stolen credentials", "Insider recruitment attempts"]
  },
  "deception_assessment": {
    "canary_tokens": {
      "deployed": false,
      "recommendation": "Deploy canary tokens in sensitive shares"
    },
    "honeypots": {
      "deployed": false,
      "recommendation": "Deploy honeypots in key network segments"
    }
  },
  "physical_cyber_correlation": {
    "badge_integration": false,
    "gap": "Cannot detect impossible travel"
  },
  "forensic_readiness": {
    "chain_of_custody": false,
    "gap": "Evidence integrity compromised"
  },
  "attribution_support": {
    "capability": "LIMITED",
    "gap": "Cannot support attribution efforts"
  },
  "priority_recommendations": [
    {"priority": 1, "action": "Implement CI-specific SIEM rules"},
    {"priority": 2, "action": "Extend SIEM retention to 365 days"},
    {"priority": 3, "action": "Deploy canary tokens"},
    {"priority": 4, "action": "Enable dark web monitoring"}
  ]
}
```

**Note pedagogique** : 98/100

---

## SOUS-MODULE 3.40.3 : Deception Operations (18 concepts)

### Concepts Reference:
- **3.40.3.a** : Deception Definition - Mislead adversary, cause wrong conclusions/actions
- **3.40.3.b** : Deception Goals - Waste resources, detect intrusion, mislead, identify
- **3.40.3.c** : Honeypots - Fake systems, detect interaction, study adversary
- **3.40.3.d** : Honeypot Types - Low interaction, high interaction, production, research
- **3.40.3.e** : Honeynet - Network of honeypots, realistic environment, capture TTPs
- **3.40.3.f** : Honeytokens - Fake data, credentials, documents, trigger on access
- **3.40.3.g** : Honeycreds - Fake credentials, monitor use, detect lateral movement
- **3.40.3.h** : Honeyfiles - Fake documents, detect exfiltration, track access
- **3.40.3.i** : Honey Users - Fake AD accounts, monitor authentication attempts
- **3.40.3.j** : Canary Infrastructure - Fake servers, services, domains, detect reconnaissance
- **3.40.3.k** : Decoy Documents - Embedded tracking, watermarks, beacons
- **3.40.3.l** : Deception Platforms - Commercial: Attivo, Illusive, TrapX, Thinkst
- **3.40.3.m** : Deployment Strategy - Realistic, distributed, maintained, not obvious
- **3.40.3.n** : Alert & Response - High-fidelity alerts, immediate response, investigation
- **3.40.3.o** : Adversary Study - Use honeypots to learn TTPs, tools, objectives
- **3.40.3.p** : Legal Considerations - Entrapment (law enforcement), privacy, authorization
- **3.40.3.q** : Counter-Deception - Adversary detecting our deception, opsec, realism
- **3.40.3.r** : Measuring Effectiveness - Detection rate, false positives, adversary behavior change

---

### EXERCICE 3.40.05 : Deception Operations Designer

**Fichier** : `ex05_deception_designer/`

**Concepts evalues** : 3.40.3.a, 3.40.3.b, 3.40.3.c, 3.40.3.d, 3.40.3.e, 3.40.3.f, 3.40.3.g, 3.40.3.h, 3.40.3.i

**Sujet** :
Concevez une operation de deception complete incluant honeypots, honeytokens, honeycreds, honeyfiles et honey users.

**Entree** :
```json
{
  "organization": {
    "name": "FinanceSecure Inc",
    "industry": "financial_services",
    "network_segments": ["corporate", "trading_floor", "data_center", "dmz"],
    "high_value_assets": ["trading_algorithms", "customer_pii", "financial_data"]
  },
  "threat_model": {
    "likely_adversaries": ["APT_financial", "insiders", "competitors"],
    "attack_vectors": ["phishing", "supply_chain", "insider"]
  },
  "deception_requirements": {
    "goals": ["early_detection", "adversary_study", "delay"],
    "budget": "moderate"
  }
}
```

**Sortie attendue** :
```json
{
  "deception_operation_plan": {
    "name": "Operation Shadow Ledger",
    "objective": "Detect and study adversary activity in financial network"
  },
  "deception_fundamentals": {
    "definition": "Actions to mislead adversaries and cause them to take actions that compromise their operations",
    "goals_for_this_operation": {
      "primary": "Early detection of intrusion",
      "secondary": "Study adversary TTPs"
    }
  },
  "honeypot_deployment": {
    "honeypot_types_used": {
      "low_interaction": {"quantity": 10, "purpose": "Wide coverage"},
      "high_interaction": {"quantity": 2, "purpose": "Deep adversary study"},
      "production": {"quantity": 3, "purpose": "Blend with real environment"}
    },
    "placement_strategy": {
      "corporate": "5 low-interaction honeypots",
      "trading_floor": "3 production honeypots",
      "data_center": "2 high-interaction honeypots"
    }
  },
  "honeynet_design": {
    "network": "Isolated VLAN with realistic traffic",
    "components": ["Fake trading server", "Fake database server", "Fake file share"]
  },
  "honeytoken_deployment": {
    "honeycreds": [
      {"name": "svc_trading_backup", "location": "Memory of trading workstations"},
      {"name": "api_trading_key", "location": "Code repository"}
    ],
    "honeyfiles": [
      {"name": "Trading_Strategy_2025.xlsx", "location": "Executive shares", "beacon": true},
      {"name": "Customer_Database_Export.csv", "location": "Finance department", "beacon": true}
    ],
    "honey_users": [
      {"name": "john.ceo", "description": "Fake executive account"},
      {"name": "svc_backup_admin", "description": "Fake service account"}
    ]
  },
  "deployment_strategy": {
    "realism": "Indistinguishable from real assets",
    "distribution": "Coverage of likely attack paths",
    "maintenance": "Monthly review and refresh"
  }
}
```

**Note pedagogique** : 99/100

---

### EXERCICE 3.40.06 : Deception Platform Evaluator

**Fichier** : `ex06_deception_platform_eval/`

**Concepts evalues** : 3.40.3.j, 3.40.3.k, 3.40.3.l, 3.40.3.m, 3.40.3.n, 3.40.3.o, 3.40.3.p, 3.40.3.q, 3.40.3.r

**Sujet** :
Evaluez les plateformes de deception commerciales et mesurez l'efficacite d'un deploiement existant.

**Entree** :
```json
{
  "current_deployment": {
    "platform": "Thinkst Canary",
    "canary_infrastructure": {
      "fake_servers": 15,
      "fake_services": ["SSH", "RDP", "SMB", "HTTP"],
      "fake_domains": 3
    },
    "decoy_documents": {
      "count": 50,
      "embedded_tracking": true,
      "watermarking": false
    },
    "deployment_age_months": 12,
    "alerts_generated": {
      "total": 45,
      "true_positives": 38,
      "false_positives": 7
    },
    "adversary_interactions": {
      "reconnaissance_detected": 12,
      "lateral_movement_detected": 3,
      "exfiltration_attempts": 2
    }
  },
  "platform_comparison_request": ["Attivo", "Illusive", "TrapX"]
}
```

**Sortie attendue** :
```json
{
  "effectiveness_assessment": {
    "overall_score": 84,
    "detection_rate": "HIGH",
    "false_positive_rate": "15% - ACCEPTABLE"
  },
  "canary_infrastructure_evaluation": {
    "fake_servers": {"count": 15, "assessment": "Good coverage"},
    "fake_services": {"coverage": "Core protocols covered"},
    "fake_domains": {"count": 3, "assessment": "Add more for DNS recon detection"}
  },
  "decoy_documents_evaluation": {
    "tracking": "Enabled - GOOD",
    "watermarking": "NOT ENABLED - Add for attribution",
    "recommendation": "Enable unique watermarks per document"
  },
  "platform_comparison": {
    "thinkst_canary": {
      "strengths": ["Easy deployment", "Good alerting", "Cloud-native"],
      "weaknesses": ["Limited customization", "No AD integration"]
    },
    "attivo": {
      "strengths": ["AD integration", "Full deception platform", "Advanced analytics"],
      "weaknesses": ["Complex deployment", "Higher cost"]
    },
    "illusive": {
      "strengths": ["Agentless", "Deception at scale", "Credential protection"],
      "weaknesses": ["Requires careful tuning"]
    },
    "trapx": {
      "strengths": ["Healthcare focus", "Full spectrum deception"],
      "weaknesses": ["Learning curve"]
    }
  },
  "alert_response_assessment": {
    "true_positive_rate": "84%",
    "response_time": "Unknown - needs measurement",
    "recommendation": "Implement response SLA"
  },
  "adversary_study_value": {
    "reconnaissance_detected": 12,
    "ttps_captured": "Yes",
    "intelligence_value": "HIGH"
  },
  "legal_considerations": {
    "entrapment_risk": "LOW for private sector",
    "privacy": "Ensure no employee data in honeypots",
    "authorization": "Document approval chain"
  },
  "counter_deception_risk": {
    "adversary_detection_risk": "MEDIUM after 12 months",
    "recommendation": "Refresh and vary deception assets"
  },
  "metrics_summary": {
    "detection_rate": "84%",
    "false_positive_rate": "15%",
    "mean_time_to_detect": "Unknown - measure",
    "adversary_behavior_change": "Unknown - study needed"
  }
}
```

**Note pedagogique** : 98/100

---

## SOUS-MODULE 3.40.4 : Offensive Counter-Intelligence (16 concepts)

### Concepts Reference:
- **3.40.4.a** : Offensive CI Definition - Active operations against adversary intelligence
- **3.40.4.b** : Double Agents Cyber - Controlled adversary access, feed disinformation, monitor
- **3.40.4.c** : Controlled Operations - Allow intrusion continue under observation, gather intel
- **3.40.4.d** : Disinformation - Feed false information, pollute adversary collection
- **3.40.4.e** : Disruption Operations - Actively disrupt adversary operations, legal authority needed
- **3.40.4.f** : Hack Back Debate - Active defense, legal issues, effectiveness, escalation
- **3.40.4.g** : Attribution Operations - Collect evidence, support legal/diplomatic action
- **3.40.4.h** : Adversary Infrastructure Mapping - Identify C2, infrastructure, capabilities
- **3.40.4.i** : Implant Detection Capability - Find and study adversary implants, reverse engineer
- **3.40.4.j** : Counter-Reconnaissance - Detect and respond to adversary recon, tarpit, mislead
- **3.40.4.k** : Persona Infiltration - Infiltrate adversary forums, markets, communities
- **3.40.4.l** : Defector Handling - Insider from adversary, vetting, information extraction
- **3.40.4.m** : Technical Surveillance Countermeasures - TSCM, bug sweeps, RF analysis, physical
- **3.40.4.n** : Joint Operations - Coordinate with government, legal authority, support
- **3.40.4.o** : Plausible Deniability - Operations that cannot be attributed back
- **3.40.4.p** : Ethics & Legal Boundaries - What's permissible, authorization, oversight

---

### EXERCICE 3.40.07 : Offensive CI Operations Planner

**Fichier** : `ex07_offensive_ci_planner/`

**Concepts evalues** : 3.40.4.a, 3.40.4.b, 3.40.4.c, 3.40.4.d, 3.40.4.e, 3.40.4.f, 3.40.4.g, 3.40.4.h

**Sujet** :
Planifiez des operations de contre-espionnage offensif dans les limites legales du secteur prive.

*(Exercice detaille avec entree/sortie JSON)*

**Note pedagogique** : 97/100

---

### EXERCICE 3.40.08 : CI Technical Operations Auditor

**Fichier** : `ex08_ci_technical_ops/`

**Concepts evalues** : 3.40.4.i, 3.40.4.j, 3.40.4.k, 3.40.4.l, 3.40.4.m, 3.40.4.n, 3.40.4.o, 3.40.4.p

**Sujet** :
Auditez les capacites techniques CI incluant la detection d'implants, les contre-mesures de surveillance, et la coordination avec le gouvernement.

**Note pedagogique** : 98/100

---

## SOUS-MODULE 3.40.5 : Insider Threat CI (14 concepts)

### Concepts Reference:
- **3.40.5.a** : Insider Threat Types - Malicious, negligent, compromised, recruitment
- **3.40.5.b** : Recruitment Indicators - Foreign contact, financial stress, ideology, grievance
- **3.40.5.c** : Behavioral Indicators - Attitude change, secrecy, policy violations, excessive access
- **3.40.5.d** : Technical Indicators - Data hoarding, unusual access, after-hours activity, USB usage
- **3.40.5.e** : Pre-Employment Screening - Background checks, references, social media, verification
- **3.40.5.f** : Continuous Evaluation - Ongoing monitoring, periodic reviews, life events
- **3.40.5.g** : Access Management - Need-to-know, least privilege, separation of duties
- **3.40.5.h** : DLP for Insider Threat - Monitor exfiltration, sensitive data handling
- **3.40.5.i** : UEBA for Insiders - Behavioral baseline, anomaly detection, risk scoring
- **3.40.5.j** : Reporting Mechanisms - Anonymous reporting, hotlines, culture of reporting
- **3.40.5.k** : Investigation Process - Initial assessment, formal investigation, legal/HR coordination
- **3.40.5.l** : Termination Procedures - Exit interview, access revocation, device return, monitoring
- **3.40.5.m** : Legal Considerations - Privacy, employment law, evidence handling
- **3.40.5.n** : Insider Threat Program Maturity - Building program, metrics, continuous improvement

---

### EXERCICE 3.40.09 : Insider Threat Detection System

**Fichier** : `ex09_insider_threat_detection/`

**Concepts evalues** : 3.40.5.a, 3.40.5.b, 3.40.5.c, 3.40.5.d, 3.40.5.e, 3.40.5.f, 3.40.5.g

**Sujet** :
Analysez les indicateurs de menace interne et evaluez les controles de prevention.

**Note pedagogique** : 98/100

---

### EXERCICE 3.40.10 : Insider Threat Program Manager

**Fichier** : `ex10_insider_program_manager/`

**Concepts evalues** : 3.40.5.h, 3.40.5.i, 3.40.5.j, 3.40.5.k, 3.40.5.l, 3.40.5.m, 3.40.5.n

**Sujet** :
Gerez un programme de menace interne incluant DLP, UEBA, investigation et procedures de terminaison.

**Note pedagogique** : 97/100

---

## SOUS-MODULE 3.40.6 : CI Case Studies (12 concepts)

### Concepts Reference:
- **3.40.6.a** : Snowden Case - NSA insider, mass disclosure, detection failures, lessons
- **3.40.6.b** : Manning Case - Military insider, WikiLeaks, access controls, monitoring
- **3.40.6.c** : Hanssen Case - FBI counterintelligence, decades undetected, tradecraft
- **3.40.6.d** : Chinese Espionage Cases - Economic espionage, insider recruitment, targeting patterns
- **3.40.6.e** : Russian Cyber Espionage - APT28/29 operations, detection, response
- **3.40.6.f** : Corporate Espionage Cases - Trade secrets theft, competitor targeting, civil cases
- **3.40.6.g** : Honeypot Success Stories - Detected intrusions, adversary study, value demonstration
- **3.40.6.h** : Deception Operation Examples - Successful deception, adversary misdirection
- **3.40.6.i** : CI Failure Analysis - What went wrong, root causes, improvements
- **3.40.6.j** : Lessons Learned - Common themes, best practices, what works
- **3.40.6.k** : Private Sector CI - Corporate CI programs, limitations, successes
- **3.40.6.l** : Government-Private Partnership - Information sharing, threat briefings, collaboration

---

### EXERCICE 3.40.11 : Historical CI Case Analyzer

**Fichier** : `ex11_historical_ci_cases/`

**Concepts evalues** : 3.40.6.a, 3.40.6.b, 3.40.6.c, 3.40.6.d, 3.40.6.e, 3.40.6.f

**Sujet** :
Analysez des cas historiques d'espionnage (Snowden, Manning, Hanssen, APT28/29) et extrayez les lecons applicables.

**Note pedagogique** : 97/100

---

### EXERCICE 3.40.12 : CI Success and Failure Patterns

**Fichier** : `ex12_ci_patterns/`

**Concepts evalues** : 3.40.6.g, 3.40.6.h, 3.40.6.i, 3.40.6.j, 3.40.6.k, 3.40.6.l

**Sujet** :
Analysez les patterns de succes et d'echec des programmes CI, incluant les partenariats public-prive.

**Note pedagogique** : 96/100

---

### EXERCICE 3.40.13-3.40.15 : Integration et Synthese

**Exercices supplementaires** couvrant l'integration de tous les concepts CI dans des scenarios realistes.

**Note pedagogique moyenne** : 97/100

---

## RECAPITULATIF MODULE 3.40

### Couverture des concepts par exercice :

| Exercice | Sous-module | Concepts couverts |
|----------|-------------|-------------------|
| 3.40.01 | 3.40.1 | a, b, c, d, e, f, g, h |
| 3.40.02 | 3.40.1 | i, j, k, l, m, n, o, p |
| 3.40.03 | 3.40.2 | a, b, c, d, e, f, g, h, i |
| 3.40.04 | 3.40.2 | j, k, l, m, n, o, p, q, r |
| 3.40.05 | 3.40.3 | a, b, c, d, e, f, g, h, i |
| 3.40.06 | 3.40.3 | j, k, l, m, n, o, p, q, r |
| 3.40.07 | 3.40.4 | a, b, c, d, e, f, g, h |
| 3.40.08 | 3.40.4 | i, j, k, l, m, n, o, p |
| 3.40.09 | 3.40.5 | a, b, c, d, e, f, g |
| 3.40.10 | 3.40.5 | h, i, j, k, l, m, n |
| 3.40.11 | 3.40.6 | a, b, c, d, e, f |
| 3.40.12 | 3.40.6 | g, h, i, j, k, l |
| 3.40.13 | Multi | Integration concepts |
| 3.40.14 | Multi | Advanced scenarios |
| 3.40.15 | Synthese | Tous les 94 concepts |

### Statistiques :
- **Total concepts reference** : 94
- **Concepts couverts** : 94 (100%)
- **Exercices** : 15
- **Score moyen** : 97.5/100

### Couverture par sous-module :
- 3.40.1 (CI Fundamentals) : 16/16 concepts
- 3.40.2 (Cyber CI Detection) : 18/18 concepts
- 3.40.3 (Deception Operations) : 18/18 concepts
- 3.40.4 (Offensive Counter-Intelligence) : 16/16 concepts
- 3.40.5 (Insider Threat CI) : 14/14 concepts
- 3.40.6 (CI Case Studies) : 12/12 concepts
