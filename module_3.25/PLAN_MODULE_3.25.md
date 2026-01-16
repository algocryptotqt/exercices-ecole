# PLAN MODULE 3.25 : Cyber Threat Intelligence (CTI)

**Concepts totaux** : 92
**Exercices prévus** : 16
**Note moyenne cible** : >= 96/100

---

## TABLE DE COUVERTURE CONCEPTS → EXERCICES

| Sous-module | Concepts | Exercices couvrant |
|-------------|----------|-------------------|
| 3.25.1 Fondamentaux CTI | a-p (16) | Ex01, Ex02, Ex03 |
| 3.25.2 Frameworks Intel | a-n (14) | Ex04, Ex05 |
| 3.25.3 Sources Intel | a-r (18) | Ex06, Ex07, Ex08 |
| 3.25.4 Threat Actors | a-p (16) | Ex09, Ex10, Ex11 |
| 3.25.5 IOCs & Detection | a-n (14) | Ex12, Ex13 |
| 3.25.6 TIPs & Outils | a-n (14) | Ex14, Ex15, Ex16 |

---

## MATRICE DÉTAILLÉE

| Ex | Concepts couverts | Thème |
|----|-------------------|-------|
| 01 | 3.25.1: a,b,c,d,e,f | Types et niveaux d'intelligence |
| 02 | 3.25.1: g,h,i,j,k,l | Cycle du renseignement |
| 03 | 3.25.1: m,n,o,p | Produits et équipes CTI |
| 04 | 3.25.2: a,b,c,d,e,f,g | ATT&CK, Kill Chain, Diamond, STIX |
| 05 | 3.25.2: h,i,j,k,l,m,n | F3EAD, VERIS, CAPEC, Pyramid, OODA |
| 06 | 3.25.3: a,b,c,d,e,f | Sources internes et externes |
| 07 | 3.25.3: g,h,i,j,k,l | Sources humaines et techniques |
| 08 | 3.25.3: m,n,o,p,q,r | Sharing communities et OPSEC |
| 09 | 3.25.4: a,b,c,d,e,f | Types d'acteurs et attribution |
| 10 | 3.25.4: g,h,i,j,k,l | Profilage et tracking |
| 11 | 3.25.4: m,n,o,p | Victimology et scénarios |
| 12 | 3.25.5: a,b,c,d,e,f,g | IOCs lifecycle et enrichissement |
| 13 | 3.25.5: h,i,j,k,l,m,n | Detection rules et métriques |
| 14 | 3.25.6: a,b,c,d,e | TIPs open source (MISP, OpenCTI, TheHive) |
| 15 | 3.25.6: f,g,h,i,j | TIPs commerciaux |
| 16 | 3.25.6: k,l,m,n | Outils d'analyse (VT, OTX, Maltego, YARA) |

---

## EXERCICE 01 : Intelligence Classification Engine

**Concepts couverts** : 3.25.1.a (Definition CTI), 3.25.1.b (Intel vs Data vs Info), 3.25.1.c (Strategic), 3.25.1.d (Operational), 3.25.1.e (Tactical), 3.25.1.f (Technical)

**Contexte** : Un analyste CTI reçoit différents éléments et doit les classifier par niveau d'intelligence.

**Entrée JSON** :
```json
{
  "raw_inputs": [
    {"id": 1, "content": "IP 185.220.101.34 seen in firewall logs", "source": "internal_siem"},
    {"id": 2, "content": "APT29 shifting from COVID lures to diplomatic targets in Q3", "source": "vendor_report"},
    {"id": 3, "content": "Domain evil.example.com resolves to 192.168.1.1", "source": "passive_dns"},
    {"id": 4, "content": "Ransomware groups increasingly targeting healthcare sector, recommend board-level risk review", "source": "strategic_assessment"},
    {"id": 5, "content": "Cobalt Strike beacon C2 pattern: /visit.js with 60s jitter, malleable profile X", "source": "malware_analysis"},
    {"id": 6, "content": "Expected Lazarus campaign against financial institutions next 2 weeks based on infrastructure staging", "source": "intel_partner"}
  ],
  "organization_context": {
    "sector": "financial_services",
    "geopolitical_exposure": "US_Europe",
    "threat_profile": ["APT29", "Lazarus", "FIN7"]
  }
}
```

**Sortie attendue** :
```json
{
  "classification": [
    {
      "id": 1,
      "original_type": "data",
      "processed_type": "technical_indicator",
      "intelligence_level": "technical",
      "actionability": "automated_blocking",
      "consumer": "SOC_tier1",
      "confidence": "low_single_source",
      "transformation_needed": "enrichment_context"
    },
    {
      "id": 2,
      "original_type": "information",
      "processed_type": "operational_intelligence",
      "intelligence_level": "operational",
      "actionability": "update_detection_rules",
      "consumer": "threat_intel_team",
      "confidence": "medium_vendor_source",
      "relevance_to_org": "high_APT29_in_threat_profile"
    },
    {
      "id": 3,
      "original_type": "data",
      "processed_type": "technical_indicator",
      "intelligence_level": "technical",
      "actionability": "siem_correlation",
      "consumer": "detection_engineering",
      "confidence": "medium_needs_validation",
      "transformation_needed": "none_raw_ioc"
    },
    {
      "id": 4,
      "original_type": "intelligence",
      "processed_type": "strategic_intelligence",
      "intelligence_level": "strategic",
      "actionability": "board_briefing_risk_assessment",
      "consumer": "CISO_executives",
      "horizon": "6_12_months",
      "decision_support": "budget_prioritization_sector_exposure"
    },
    {
      "id": 5,
      "original_type": "information",
      "processed_type": "tactical_intelligence",
      "intelligence_level": "tactical",
      "actionability": "yara_sigma_rule_creation",
      "consumer": "SOC_detection_engineering",
      "ttps_mapped": ["T1071.001", "T1573"],
      "immediate_use": true
    },
    {
      "id": 6,
      "original_type": "intelligence",
      "processed_type": "operational_intelligence",
      "intelligence_level": "operational",
      "actionability": "heightened_monitoring_threat_hunting",
      "consumer": "SOC_manager_IR_team",
      "horizon": "weeks",
      "relevance_to_org": "critical_lazarus_targets_financial"
    }
  ],
  "intelligence_hierarchy": {
    "data_to_information": "processing_parsing_normalization",
    "information_to_intelligence": "analysis_context_actionability",
    "levels": {
      "technical": {"horizon": "immediate", "consumers": ["SOC", "automation"]},
      "tactical": {"horizon": "hours_days", "consumers": ["detection", "hunting"]},
      "operational": {"horizon": "weeks_months", "consumers": ["IR", "threat_intel"]},
      "strategic": {"horizon": "months_years", "consumers": ["executives", "board"]}
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (6 concepts CTI fondamentaux)
- Intelligence pédagogique : 24/25 (hiérarchie claire data→intel)
- Originalité : 19/20 (classification multi-niveau)
- Testabilité : 14/15 (règles dérivables)
- Clarté : 15/15 (concepts bien séparés)

---

## EXERCICE 02 : Intelligence Cycle Orchestrator

**Concepts couverts** : 3.25.1.g (Intelligence Cycle), 3.25.1.h (Requirements), 3.25.1.i (Collection Mgmt), 3.25.1.j (Source Evaluation), 3.25.1.k (Analysis Techniques), 3.25.1.l (Confidence Levels)

**Entrée JSON** :
```json
{
  "scenario": "new_intelligence_requirement",
  "requirement": {
    "question": "What TTPs is APT28 currently using against European defense contractors?",
    "requester": "CISO",
    "priority": "high",
    "deadline": "2_weeks"
  },
  "available_sources": [
    {"id": "src_1", "type": "vendor_feed", "name": "Mandiant", "reliability": "A", "access": "subscribed"},
    {"id": "src_2", "type": "osint", "name": "twitter_infosec", "reliability": "C", "access": "free"},
    {"id": "src_3", "type": "government", "name": "CISA_alerts", "reliability": "B", "access": "public"},
    {"id": "src_4", "type": "internal", "name": "siem_logs", "reliability": "A", "access": "full"},
    {"id": "src_5", "type": "dark_web", "name": "forum_monitoring", "reliability": "D", "access": "limited"},
    {"id": "src_6", "type": "human", "name": "industry_peer", "reliability": "B", "access": "relationship"}
  ],
  "collected_data": [
    {"source": "src_1", "content": "APT28 using Graphite malware with OneDrive C2", "date": "2024-01-10"},
    {"source": "src_2", "content": "Researcher tweet: possible APT28 spearphishing defense sector", "date": "2024-01-12"},
    {"source": "src_3", "content": "CISA: Russian actors targeting defense contractors via VPN vulns", "date": "2024-01-05"},
    {"source": "src_6", "content": "Peer company saw credential phishing pretending to be NATO updates", "date": "2024-01-08"}
  ]
}
```

**Sortie attendue** :
```json
{
  "intelligence_cycle_execution": {
    "phase_1_direction": {
      "pir_defined": "APT28_TTPs_European_defense",
      "scope": "TTPs_infrastructure_indicators",
      "consumers": ["CISO", "SOC", "detection_engineering"],
      "success_criteria": "actionable_detection_rules"
    },
    "phase_2_collection": {
      "collection_plan": [
        {"source": "src_1", "priority": "high", "expected_yield": "detailed_ttp_analysis"},
        {"source": "src_3", "priority": "high", "expected_yield": "government_attribution"},
        {"source": "src_6", "priority": "medium", "expected_yield": "sector_specific_context"},
        {"source": "src_4", "priority": "high", "expected_yield": "internal_exposure_check"}
      ],
      "gaps_identified": ["no_direct_malware_samples", "limited_infrastructure_data"]
    },
    "phase_3_processing": {
      "normalization": "stix_format",
      "deduplication": true,
      "timeline_creation": true
    },
    "phase_4_analysis": {
      "technique": "ACH",
      "hypotheses": [
        {"h1": "APT28_actively_targeting_defense", "evidence_for": 4, "evidence_against": 0},
        {"h2": "generic_russian_activity_misattributed", "evidence_for": 1, "evidence_against": 3}
      ],
      "structured_techniques_used": ["link_analysis", "timeline_analysis", "ttp_mapping"],
      "conclusion": "high_confidence_apt28_campaign_active"
    }
  },
  "source_evaluation": {
    "admiralty_ratings": [
      {"source": "src_1", "reliability": "A", "credibility": "1", "rating": "A1_confirmed"},
      {"source": "src_2", "reliability": "C", "credibility": "3", "rating": "C3_possibly_true"},
      {"source": "src_3", "reliability": "B", "credibility": "2", "rating": "B2_probably_true"},
      {"source": "src_6", "reliability": "B", "credibility": "2", "rating": "B2_probably_true"}
    ],
    "corroboration": "3_independent_sources_confirm_campaign"
  },
  "confidence_assessment": {
    "overall_confidence": "high",
    "confidence_factors": {
      "source_reliability": "high_multiple_A_B_sources",
      "corroboration": "high_4_sources_aligned",
      "recency": "high_within_2_weeks",
      "specificity": "medium_some_details_missing"
    },
    "analytic_confidence_statement": "We assess with HIGH confidence that APT28 is actively conducting operations against European defense contractors using credential phishing and Graphite malware."
  },
  "phase_5_dissemination": {
    "products": [
      {"type": "tactical_alert", "audience": "SOC", "tlp": "AMBER"},
      {"type": "executive_brief", "audience": "CISO", "tlp": "AMBER"},
      {"type": "detection_rules", "audience": "engineering", "tlp": "GREEN"}
    ]
  },
  "phase_6_feedback": {
    "metrics_to_track": ["detection_rate", "false_positives", "time_to_detect"],
    "review_scheduled": "2_weeks"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 03 : CTI Products & Team Designer

**Concepts couverts** : 3.25.1.m (Intelligence Products), 3.25.1.n (Dissemination), 3.25.1.o (Feedback Loop), 3.25.1.p (CTI Team Structure)

**Entrée JSON** :
```json
{
  "organization": {
    "size": "5000_employees",
    "sector": "healthcare",
    "maturity": "developing_cti_program",
    "current_team": 2,
    "budget": "expanding"
  },
  "stakeholders": [
    {"role": "CISO", "needs": "risk_decisions", "frequency": "monthly"},
    {"role": "SOC_Manager", "needs": "detection_priorities", "frequency": "weekly"},
    {"role": "IR_Lead", "needs": "threat_context", "frequency": "on_incident"},
    {"role": "Board", "needs": "threat_landscape", "frequency": "quarterly"},
    {"role": "Detection_Engineering", "needs": "IOCs_rules", "frequency": "daily"}
  ],
  "recent_incident": {
    "type": "ransomware",
    "actor": "suspected_BlackCat",
    "impact": "3_days_downtime",
    "lessons_learned": "lacked_threat_context_delayed_attribution"
  }
}
```

**Sortie attendue** :
```json
{
  "cti_products_framework": {
    "strategic_products": [
      {
        "name": "Quarterly_Threat_Landscape",
        "audience": "Board_CISO",
        "content": ["sector_threats", "risk_trends", "recommendations"],
        "format": "executive_brief_5pages",
        "tlp": "AMBER",
        "frequency": "quarterly"
      },
      {
        "name": "Annual_Threat_Assessment",
        "audience": "Board",
        "content": ["year_review", "emerging_threats", "strategic_recommendations"],
        "format": "report_20pages",
        "tlp": "RED",
        "frequency": "annual"
      }
    ],
    "operational_products": [
      {
        "name": "Weekly_Threat_Brief",
        "audience": "SOC_Manager_IR",
        "content": ["relevant_campaigns", "sector_targeting", "actor_updates"],
        "format": "brief_2pages",
        "tlp": "AMBER",
        "frequency": "weekly"
      },
      {
        "name": "Campaign_Report",
        "audience": "SOC_IR_Engineering",
        "content": ["actor_profile", "ttps", "iocs", "mitigations"],
        "format": "detailed_report",
        "tlp": "AMBER",
        "frequency": "as_needed"
      }
    ],
    "tactical_products": [
      {
        "name": "Daily_IOC_Feed",
        "audience": "Detection_Engineering",
        "content": ["validated_iocs", "yara_rules", "sigma_rules"],
        "format": "stix_feed",
        "tlp": "GREEN",
        "frequency": "daily"
      },
      {
        "name": "Threat_Alerts",
        "audience": "SOC_all",
        "content": ["immediate_threats", "detection_guidance"],
        "format": "alert_1page",
        "tlp": "AMBER",
        "frequency": "realtime"
      }
    ]
  },
  "dissemination_framework": {
    "tlp_policy": {
      "RED": "named_recipients_only",
      "AMBER": "organization_only",
      "GREEN": "community_sharing_ok",
      "WHITE": "public"
    },
    "channels": {
      "strategic": "email_encrypted_sharepoint",
      "operational": "ticketing_system_confluence",
      "tactical": "siem_integration_api"
    },
    "timeliness_sla": {
      "critical_threat": "1_hour",
      "high_threat": "4_hours",
      "medium_threat": "24_hours",
      "routine": "weekly_cycle"
    }
  },
  "feedback_loop_design": {
    "mechanisms": [
      {"method": "detection_metrics", "frequency": "weekly", "owner": "SOC"},
      {"method": "consumer_survey", "frequency": "quarterly", "owner": "CTI_lead"},
      {"method": "post_incident_review", "frequency": "per_incident", "owner": "IR"}
    ],
    "metrics_tracked": [
      "intel_to_detection_time",
      "false_positive_rate",
      "consumer_satisfaction",
      "requirements_fulfilled_rate"
    ],
    "improvement_cycle": "quarterly_review_adjust_products"
  },
  "recommended_team_structure": {
    "current_state": {"analysts": 2, "gaps": ["collection", "strategic_analysis"]},
    "target_state": {
      "cti_manager": {"focus": "strategy_stakeholder_management", "count": 1},
      "tactical_analysts": {"focus": "iocs_detection_rules", "count": 2},
      "strategic_analyst": {"focus": "threat_landscape_actor_profiling", "count": 1},
      "collection_specialist": {"focus": "osint_dark_web_feeds", "count": 1}
    },
    "integration": {
      "soc": "embedded_analyst_rotation",
      "ir": "on_call_support",
      "vuln_management": "prioritization_intel"
    },
    "growth_path": "2→5_analysts_over_18_months"
  },
  "post_incident_improvement": {
    "gap_identified": "lacked_ransomware_actor_context",
    "solution": "subscribe_to_ransomware_focused_feed",
    "playbook_update": "include_cti_in_initial_triage"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 04 : Framework Fusion Analyzer

**Concepts couverts** : 3.25.2.a (MITRE ATT&CK), 3.25.2.b (ATT&CK Tactics), 3.25.2.c (ATT&CK Navigator), 3.25.2.d (Cyber Kill Chain), 3.25.2.e (Diamond Model), 3.25.2.f (STIX), 3.25.2.g (TAXII)

**Contexte** : Un analyste doit mapper un incident réel sur plusieurs frameworks CTI et produire une sortie STIX standardisée.

**Entrée JSON** :
```json
{
  "incident": {
    "id": "INC-2024-0342",
    "description": "Compromission via spearphishing suivi de mouvement latéral",
    "timeline": [
      {"time": "2024-01-15T09:23:00Z", "event": "Phishing email received targeting CFO"},
      {"time": "2024-01-15T09:45:00Z", "event": "Malicious macro executed in Word document"},
      {"time": "2024-01-15T09:47:00Z", "event": "PowerShell download cradle detected"},
      {"time": "2024-01-15T10:12:00Z", "event": "Cobalt Strike beacon established"},
      {"time": "2024-01-15T14:30:00Z", "event": "Credential dumping via Mimikatz"},
      {"time": "2024-01-16T02:15:00Z", "event": "Lateral movement to domain controller"},
      {"time": "2024-01-16T03:00:00Z", "event": "Data exfiltration to external IP"}
    ],
    "indicators": {
      "ips": ["185.174.101.55", "94.232.41.12"],
      "domains": ["update-service.example.com"],
      "hashes": ["a1b2c3d4e5f67890abcdef1234567890"],
      "email_sender": "invoice@legitcompany-update.com"
    },
    "suspected_actor": "APT29"
  },
  "frameworks_to_map": ["attack", "kill_chain", "diamond"]
}
```

**Sortie attendue** :
```json
{
  "mitre_attack_mapping": {
    "tactics_techniques": [
      {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "techniques": [
          {"id": "T1566.001", "name": "Spearphishing Attachment", "evidence": "Word document with macro"}
        ]
      },
      {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "techniques": [
          {"id": "T1204.002", "name": "Malicious File", "evidence": "Macro executed"},
          {"id": "T1059.001", "name": "PowerShell", "evidence": "Download cradle"}
        ]
      },
      {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "techniques": [
          {"id": "T1071.001", "name": "Web Protocols", "evidence": "Cobalt Strike HTTP beacon"}
        ]
      },
      {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "techniques": [
          {"id": "T1003.001", "name": "LSASS Memory", "evidence": "Mimikatz usage"}
        ]
      },
      {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "techniques": [
          {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "evidence": "DC access"}
        ]
      },
      {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "techniques": [
          {"id": "T1041", "name": "Exfiltration Over C2 Channel", "evidence": "Data to external IP"}
        ]
      }
    ],
    "navigator_layer": {
      "name": "INC-2024-0342_Coverage",
      "domain": "enterprise-attack",
      "techniques": [
        {"techniqueID": "T1566.001", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1204.002", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1059.001", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1071.001", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1003.001", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1021.002", "score": 100, "color": "#ff0000"},
        {"techniqueID": "T1041", "score": 100, "color": "#ff0000"}
      ],
      "gradient": {"minValue": 0, "maxValue": 100}
    }
  },
  "kill_chain_mapping": {
    "framework": "lockheed_martin",
    "phases": [
      {"phase": "reconnaissance", "status": "inferred", "evidence": "CFO targeted specifically"},
      {"phase": "weaponization", "status": "confirmed", "evidence": "Macro-enabled document created"},
      {"phase": "delivery", "status": "confirmed", "evidence": "Spearphishing email"},
      {"phase": "exploitation", "status": "confirmed", "evidence": "Macro execution"},
      {"phase": "installation", "status": "confirmed", "evidence": "Cobalt Strike beacon"},
      {"phase": "command_and_control", "status": "confirmed", "evidence": "C2 established"},
      {"phase": "actions_on_objectives", "status": "confirmed", "evidence": "Data exfiltration"}
    ],
    "detection_opportunities": {
      "left_of_boom": ["email filtering", "macro blocking", "user awareness"],
      "right_of_boom": ["EDR detection", "network monitoring", "SIEM correlation"]
    }
  },
  "diamond_model": {
    "vertices": {
      "adversary": {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "confidence": "medium",
        "nation_state": "Russia"
      },
      "capability": {
        "malware": ["Cobalt Strike", "custom loader"],
        "tools": ["Mimikatz"],
        "sophistication": "high"
      },
      "infrastructure": {
        "c2_servers": ["185.174.101.55", "94.232.41.12"],
        "domains": ["update-service.example.com"],
        "hosting": "bulletproof"
      },
      "victim": {
        "sector": "inferred_from_cfo_target",
        "geography": "unspecified",
        "data_targeted": "corporate_financial"
      }
    },
    "meta_features": {
      "timestamp": "2024-01-15/16",
      "phase": "attack_execution",
      "result": "data_exfiltration_success",
      "direction": "adversary_to_victim"
    },
    "activity_thread": "APT29_campaign_2024Q1"
  },
  "stix_bundle": {
    "type": "bundle",
    "id": "bundle--uuid-generated",
    "spec_version": "2.1",
    "objects": [
      {
        "type": "attack-pattern",
        "id": "attack-pattern--uuid-1",
        "name": "Spearphishing Attachment",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}]
      },
      {
        "type": "indicator",
        "id": "indicator--uuid-2",
        "pattern": "[ipv4-addr:value = '185.174.101.55']",
        "pattern_type": "stix",
        "valid_from": "2024-01-15T00:00:00Z"
      },
      {
        "type": "threat-actor",
        "id": "threat-actor--uuid-3",
        "name": "APT29",
        "threat_actor_types": ["nation-state"]
      },
      {
        "type": "relationship",
        "id": "relationship--uuid-4",
        "relationship_type": "uses",
        "source_ref": "threat-actor--uuid-3",
        "target_ref": "attack-pattern--uuid-1"
      }
    ]
  },
  "taxii_ready": {
    "collection_id": "incident-feed-2024",
    "content_type": "stix_2.1",
    "objects_count": 4,
    "api_endpoint": "/collections/incident-feed-2024/objects/"
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (7 concepts frameworks majeurs)
- Intelligence pédagogique : 25/25 (multi-framework réaliste)
- Originalité : 19/20 (fusion pratique)
- Testabilité : 14/15 (structure vérifiable)
- Clarté : 15/15 (mappings explicites)

---

## EXERCICE 05 : Advanced Frameworks & Decision Cycles

**Concepts couverts** : 3.25.2.h (F3EAD), 3.25.2.i (Intelligence-Driven Defense), 3.25.2.j (Threat Modeling Integration), 3.25.2.k (VERIS), 3.25.2.l (CAPEC), 3.25.2.m (Pyramid of Pain), 3.25.2.n (OODA Loop)

**Entrée JSON** :
```json
{
  "threat_hunt_operation": {
    "target_actor": "FIN7",
    "known_ttps": ["T1059.001", "T1566.001", "T1071.001"],
    "available_iocs": [
      {"type": "hash", "value": "abc123...", "age_days": 45},
      {"type": "ip", "value": "203.0.113.50", "age_days": 10},
      {"type": "domain", "value": "payment-portal.evil.com", "age_days": 5},
      {"type": "tool", "value": "Carbanak", "age_days": 0},
      {"type": "ttp", "value": "PowerShell obfuscation pattern", "age_days": 0}
    ],
    "organization_threat_model": {
      "critical_assets": ["payment_system", "customer_database"],
      "likely_attack_vectors": ["phishing", "supply_chain"],
      "current_controls": ["email_gateway", "edr", "siem"]
    }
  },
  "incident_for_veris": {
    "actor": "external_organized_crime",
    "action": "hacking_phishing",
    "asset": "server_database",
    "attribute": "confidentiality_integrity"
  },
  "decision_scenario": {
    "current_state": "suspicious_activity_detected",
    "time_pressure": "high",
    "adversary_moving": true
  }
}
```

**Sortie attendue** :
```json
{
  "f3ead_cycle": {
    "find": {
      "intelligence_gap": "FIN7 current infrastructure",
      "collection_sources": ["dark_web", "passive_dns", "siem_logs"],
      "target_criteria": "financially_motivated_hospitality_retail"
    },
    "fix": {
      "confirmed_targets": ["payment-portal.evil.com"],
      "actor_location": "infrastructure_identified",
      "pattern_locked": "PowerShell execution from Word"
    },
    "finish": {
      "action_type": "detection_and_block",
      "edr_rules_deployed": true,
      "network_blocks_applied": true
    },
    "exploit": {
      "intelligence_collected": ["c2_patterns", "tool_signatures", "timing"],
      "new_iocs_extracted": 12,
      "malware_samples": 3
    },
    "analyze": {
      "ttp_evolution": "new_obfuscation_technique_identified",
      "actor_capability_update": "using_new_packer",
      "campaign_assessment": "ongoing_targeting_retail"
    },
    "disseminate": {
      "products_created": ["threat_brief", "detection_rules", "ioc_feed"],
      "shared_with": ["internal_soc", "isac_peers"],
      "tlp": "AMBER"
    }
  },
  "intelligence_driven_defense": {
    "threat_informed_priorities": [
      {"control": "PowerShell_logging", "reason": "FIN7_uses_T1059.001", "priority": 1},
      {"control": "email_attachment_sandboxing", "reason": "primary_vector", "priority": 1},
      {"control": "network_segmentation_payment", "reason": "critical_asset_protection", "priority": 2}
    ],
    "proactive_hunting": {
      "hypothesis": "FIN7 may have initial foothold via phishing",
      "hunt_queries": ["PowerShell encoded commands", "Word spawning processes"],
      "data_sources": ["process_creation", "network_connections"]
    },
    "anticipatory_defense": {
      "likely_next_moves": ["credential_theft", "lateral_to_payment"],
      "pre_positioned_detection": ["Carbanak signatures", "Mimikatz patterns"]
    }
  },
  "threat_model_integration": {
    "intel_enriched_model": {
      "attack_scenarios": [
        {
          "scenario": "FIN7 targets payment system",
          "likelihood": "high",
          "intel_basis": "FIN7 profile + targeting match",
          "ttps_expected": ["T1566.001", "T1059.001", "T1041"],
          "controls_tested": ["email_gateway", "edr", "dlp"]
        }
      ],
      "stride_per_intel": {
        "spoofing": "phishing impersonation vendor",
        "tampering": "modify payment records",
        "repudiation": "cover tracks after exfil",
        "information_disclosure": "customer data theft",
        "denial_of_service": "unlikely for FIN7",
        "elevation_of_privilege": "credential theft for access"
      }
    },
    "control_gap_analysis": {
      "gaps_identified": ["no DLP on payment data", "limited PS logging"],
      "intel_based_remediation": "prioritize based on FIN7 TTPs"
    }
  },
  "veris_classification": {
    "actor": {
      "variety": "Organized crime",
      "motive": "Financial",
      "external": true
    },
    "action": {
      "hacking": {"variety": ["Use of stolen creds"], "vector": ["Web application"]},
      "social": {"variety": ["Phishing"], "target": ["Finance"]}
    },
    "asset": {
      "variety": ["Server - Database"],
      "cloud": false
    },
    "attribute": {
      "confidentiality": {"data": ["Payment"], "data_disclosure": "Yes"},
      "integrity": {"variety": ["Modify data"]}
    },
    "timeline": {
      "compromise": {"unit": "Hours", "value": 2},
      "exfiltration": {"unit": "Days", "value": 1}
    },
    "discovery_method": "Int - security alarm"
  },
  "capec_mapping": {
    "patterns_identified": [
      {"id": "CAPEC-98", "name": "Phishing", "phase": "initial_access"},
      {"id": "CAPEC-549", "name": "Local Execution of Code", "phase": "execution"},
      {"id": "CAPEC-560", "name": "Use of Known Credentials", "phase": "privilege_escalation"}
    ],
    "attack_surface": "user_interaction_email"
  },
  "pyramid_of_pain_analysis": {
    "indicators_ranked": [
      {"value": "abc123...", "level": "hash", "pain": "trivial", "action": "block_short_term", "adversary_cost": "seconds_to_change"},
      {"value": "203.0.113.50", "level": "ip", "pain": "easy", "action": "block_moderate_term", "adversary_cost": "minutes_to_change"},
      {"value": "payment-portal.evil.com", "level": "domain", "pain": "simple", "action": "block_monitor", "adversary_cost": "hours_to_change"},
      {"value": "Carbanak", "level": "tool", "pain": "challenging", "action": "detect_behavioral", "adversary_cost": "weeks_to_retool"},
      {"value": "PowerShell obfuscation pattern", "level": "ttp", "pain": "tough", "action": "detect_generic", "adversary_cost": "months_to_change"}
    ],
    "defense_strategy": {
      "recommendation": "focus_on_ttps_and_tools",
      "rationale": "higher_adversary_cost_more_durable_detection",
      "quick_wins": "block_known_infra_iocs"
    }
  },
  "ooda_loop_execution": {
    "observe": {
      "current_data": "suspicious PowerShell activity matching FIN7",
      "sources": ["edr", "siem", "network"],
      "gaps": "attribution uncertain"
    },
    "orient": {
      "context_applied": "FIN7 known to target our sector",
      "previous_experience": "similar pattern in industry",
      "cultural_factors": "high risk tolerance due to downtime cost",
      "analysis": "likely FIN7 intrusion early stage"
    },
    "decide": {
      "options": [
        {"option": "contain_immediately", "risk": "business disruption", "benefit": "stop attack"},
        {"option": "monitor_gather_intel", "risk": "adversary progresses", "benefit": "better response"}
      ],
      "decision": "contain_immediately",
      "rationale": "adversary_moving_time_critical"
    },
    "act": {
      "actions": ["isolate_endpoint", "block_c2_ip", "preserve_evidence"],
      "execution_speed": "minutes",
      "feedback_loop": "monitor for lateral movement attempts"
    },
    "tempo_advantage": {
      "our_cycle_time": "15_minutes",
      "estimated_adversary_cycle": "hours",
      "advantage": "inside_adversary_loop"
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (7 frameworks avancés)
- Intelligence pédagogique : 24/25 (cycles décisionnels intégrés)
- Originalité : 19/20 (OODA + F3EAD combinés)
- Testabilité : 14/15 (structures définies)
- Clarté : 15/15 (logique claire)

---

## EXERCICE 06 : Multi-Source Collection Manager

**Concepts couverts** : 3.25.3.a (Internal Sources), 3.25.3.b (OSINT), 3.25.3.c (Commercial Feeds), 3.25.3.d (Government Sources), 3.25.3.e (Dark Web Monitoring), 3.25.3.f (Technical Collection)

**Contexte** : Un CTI manager doit concevoir et optimiser un plan de collecte multi-sources pour une organisation ciblée.

**Entrée JSON** :
```json
{
  "organization": {
    "sector": "banking",
    "geography": "EU",
    "threat_profile": ["APT groups", "ransomware", "fraud"],
    "budget": "medium",
    "current_sources": ["basic_siem", "one_commercial_feed"]
  },
  "intelligence_requirements": [
    {"pir": "What ransomware groups are targeting EU banks?", "priority": "critical"},
    {"pir": "Are there credentials for our domains on dark web?", "priority": "high"},
    {"pir": "What new vulnerabilities affect our tech stack?", "priority": "medium"}
  ],
  "tech_stack": ["SAP", "Oracle DB", "Windows Server", "Citrix"],
  "available_data": {
    "siem_logs": true,
    "edr_telemetry": true,
    "email_gateway": true,
    "dns_logs": false,
    "proxy_logs": true
  }
}
```

**Sortie attendue** :
```json
{
  "collection_plan": {
    "internal_sources": {
      "siem_logs": {
        "value": "high",
        "intel_use": ["baseline_behavior", "anomaly_detection", "attack_timeline"],
        "gaps": "no_dns_visibility",
        "recommendations": ["enable_dns_logging", "increase_retention_90d"]
      },
      "edr_telemetry": {
        "value": "critical",
        "intel_use": ["ttp_detection", "malware_analysis", "lateral_movement"],
        "integration": "feed_to_tip_platform"
      },
      "email_gateway": {
        "value": "high",
        "intel_use": ["phishing_campaigns", "bec_detection", "attachment_analysis"],
        "sandboxing": "required_for_samples"
      },
      "proxy_logs": {
        "value": "medium",
        "intel_use": ["c2_detection", "data_exfil_patterns"]
      }
    },
    "osint_sources": {
      "twitter_infosec": {
        "accounts": ["@vaboronova", "@GossiTheDog", "@malaborabora"],
        "value": "rapid_awareness",
        "automation": "twitter_list_monitoring"
      },
      "github_monitoring": {
        "queries": ["SAP exploit", "Oracle CVE POC", "Citrix vulnerability"],
        "value": "exploit_early_warning"
      },
      "paste_sites": {
        "monitoring": ["pastebin", "ghostbin", "dpaste"],
        "patterns": ["bank_name", "employee_emails"],
        "value": "credential_leak_detection"
      },
      "vendor_blogs": {
        "sources": ["Mandiant", "Recorded Future", "Krebs on Security"],
        "focus": "financial_sector_threats"
      },
      "government_sources_public": {
        "cisa_alerts": "automated_ingestion",
        "ncsc_uk": "weekly_review",
        "cert_eu": "critical_alerts"
      }
    },
    "commercial_feeds": {
      "recommended_primary": {
        "vendor": "Recorded Future",
        "rationale": "strong_financial_sector_coverage",
        "modules": ["threat_intelligence", "dark_web", "geopolitical"],
        "cost_tier": "medium_budget_fit"
      },
      "alternative": {
        "vendor": "Intel471",
        "rationale": "deep_underground_coverage",
        "best_for": "credential_monitoring"
      },
      "existing_optimization": {
        "current_feed": "basic_feed",
        "gaps": "no_actor_context_only_iocs",
        "enhancement": "upgrade_to_contextual_intel"
      }
    },
    "government_sources": {
      "isac_membership": {
        "recommended": "FS-ISAC",
        "value": "sector_specific_sharing_early_warning",
        "requirement": "formal_membership"
      },
      "cisa": {
        "products": ["alerts", "advisories", "malware_reports"],
        "automation": "stix_taxii_feed"
      },
      "national_cert": {
        "primary": "CERT-EU",
        "secondary": "local_national_cert",
        "engagement": "establish_relationship"
      }
    },
    "dark_web_collection": {
      "priority": "high_for_credential_pir",
      "approach": {
        "option_1": {
          "method": "commercial_service",
          "vendor": "Digital Shadows or Flashpoint",
          "coverage": ["forums", "marketplaces", "paste"],
          "opsec": "handled_by_vendor"
        },
        "option_2": {
          "method": "internal_capability",
          "requirements": ["trained_analyst", "sock_puppets", "tor_infrastructure"],
          "opsec_considerations": ["attribution_risk", "legal_review"]
        }
      },
      "monitoring_targets": [
        "credential_sales_bank_domain",
        "access_broker_offerings",
        "ransomware_victim_lists"
      ]
    },
    "technical_collection": {
      "honeypots": {
        "recommendation": "deploy_sector_specific_honeypots",
        "types": ["ssh_honeypot", "web_app_honeypot", "rdp_honeypot"],
        "value": "early_attack_detection"
      },
      "passive_dns": {
        "service": "Farsight DNSDB or DomainTools",
        "use_cases": ["infrastructure_tracking", "domain_pivoting"]
      },
      "cert_transparency": {
        "monitoring": "new_certs_for_bank_domains",
        "tool": "crt.sh automation"
      },
      "malware_sandbox": {
        "internal": "Cuckoo or CAPE",
        "commercial": "Any.Run or Hybrid Analysis",
        "use": "phishing_attachment_analysis"
      }
    }
  },
  "collection_gaps_analysis": {
    "gaps": [
      {"gap": "no_dns_logging", "impact": "c2_blind_spot", "priority": "high"},
      {"gap": "no_dark_web_coverage", "impact": "credential_exposure_unknown", "priority": "critical"},
      {"gap": "single_commercial_feed", "impact": "limited_context", "priority": "medium"}
    ],
    "budget_allocation": {
      "immediate": "dark_web_monitoring_service",
      "next_quarter": "upgrade_commercial_feed",
      "long_term": "passive_dns_capability"
    }
  },
  "source_priority_matrix": [
    {"source": "Internal SIEM/EDR", "priority": 1, "pir_coverage": ["all"]},
    {"source": "Dark web monitoring", "priority": 2, "pir_coverage": ["credential_exposure"]},
    {"source": "FS-ISAC", "priority": 3, "pir_coverage": ["ransomware_banking"]},
    {"source": "Commercial feed upgrade", "priority": 4, "pir_coverage": ["all"]}
  ]
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (6 types sources)
- Intelligence pédagogique : 24/25 (plan actionnable)
- Originalité : 19/20 (approche budget-aware)
- Testabilité : 14/15 (structures vérifiables)
- Clarté : 15/15 (priorités claires)

---

## EXERCICE 07 : Human & Technical HUMINT-TECHINT Fusion

**Concepts couverts** : 3.25.3.g (Human Sources), 3.25.3.h (Vendor Reports), 3.25.3.i (Vulnerability Sources), 3.25.3.j (Social Media Monitoring), 3.25.3.k (Code Repositories), 3.25.3.l (Paste Sites)

**Entrée JSON** :
```json
{
  "investigation": {
    "target": "emerging_ransomware_group",
    "group_name": "BlackShadow",
    "known_aliases": ["DarkExtort", "ShadowCrypt"],
    "language": "Russian"
  },
  "available_humint": [
    {"source": "industry_peer_ciso", "reliability": "B", "info": "heard BlackShadow hit company in our sector"},
    {"source": "security_researcher_twitter", "reliability": "C", "info": "posted about new ransomware sample"},
    {"source": "conference_contact_leo", "reliability": "B", "info": "group may have insider access brokers"}
  ],
  "monitoring_scope": {
    "social_media_accounts": ["@infosec_researcher_1", "@malware_hunter_x"],
    "github_keywords": ["BlackShadow", "DarkExtort ransomware"],
    "paste_sites": true,
    "vendor_reports": ["mandiant", "recordedfuture", "crowdstrike"]
  },
  "vuln_context": {
    "recent_cves": ["CVE-2024-1234", "CVE-2024-5678"],
    "our_exposure": ["CVE-2024-1234_affects_citrix"]
  }
}
```

**Sortie attendue** :
```json
{
  "humint_processing": {
    "source_evaluation": [
      {
        "source": "industry_peer_ciso",
        "admiralty_code": "B2",
        "interpretation": "usually_reliable_probably_true",
        "action": "seek_corroboration_iocs"
      },
      {
        "source": "security_researcher_twitter",
        "admiralty_code": "C3",
        "interpretation": "fairly_reliable_possibly_true",
        "action": "validate_sample_independently"
      },
      {
        "source": "conference_contact_leo",
        "admiralty_code": "B2",
        "interpretation": "usually_reliable_probably_true",
        "action": "monitor_access_broker_forums"
      }
    ],
    "humint_fusion": {
      "hypothesis": "BlackShadow active targeting our sector with insider access",
      "confidence": "medium",
      "gaps": "need technical corroboration"
    },
    "relationship_management": {
      "actions": [
        {"contact": "peer_ciso", "follow_up": "request_iocs_if_available"},
        {"contact": "leo_contact", "follow_up": "establish_formal_sharing_mou"}
      ]
    }
  },
  "vendor_reports_analysis": {
    "reports_found": [
      {
        "vendor": "Mandiant",
        "title": "BlackShadow Ransomware Operations",
        "relevance": "high",
        "key_insights": [
          "Targets manufacturing and finance",
          "Uses Cobalt Strike with custom loaders",
          "Affiliated with access brokers"
        ],
        "iocs_extracted": 45
      },
      {
        "vendor": "Recorded Future",
        "title": "Underground Intel: DarkExtort Emergence",
        "relevance": "high",
        "key_insights": [
          "Active on Exploit and XSS forums",
          "Recruiting affiliates",
          "RaaS model"
        ]
      }
    ],
    "cross_reference": {
      "humint_corroboration": "vendor reports confirm access broker connection",
      "confidence_update": "medium → high"
    }
  },
  "vulnerability_intelligence": {
    "relevant_cves": [
      {
        "cve": "CVE-2024-1234",
        "product": "Citrix NetScaler",
        "exploitation_status": "actively_exploited",
        "threat_actor_link": "BlackShadow known to use",
        "our_exposure": "critical_we_have_citrix",
        "priority": "immediate_patch"
      },
      {
        "cve": "CVE-2024-5678",
        "product": "Generic product",
        "exploitation_status": "poc_available",
        "threat_actor_link": "no_known_link",
        "our_exposure": "not_affected",
        "priority": "monitor"
      }
    ],
    "vuln_sources_used": [
      {"source": "NVD", "for": "official details"},
      {"source": "Exploit-DB", "for": "poc availability"},
      {"source": "Vendor advisory", "for": "patch guidance"},
      {"source": "CISA KEV", "for": "exploitation confirmation"}
    ],
    "threat_informed_prioritization": "CVE-2024-1234 critical due to actor link"
  },
  "social_media_monitoring": {
    "twitter_findings": [
      {
        "account": "@infosec_researcher_1",
        "post": "New #BlackShadow sample on VT: hash_abc123",
        "date": "2024-01-10",
        "actionable": true,
        "action": "retrieve_sample_analyze"
      },
      {
        "account": "@malware_hunter_x",
        "post": "BlackShadow C2 infrastructure shift observed",
        "date": "2024-01-12",
        "actionable": true,
        "action": "update_network_detections"
      }
    ],
    "telegram_channels": {
      "monitored": ["ransomware_news", "malware_samples"],
      "findings": "no direct BlackShadow activity"
    },
    "automation": {
      "tool": "TweetDeck/custom script",
      "keywords": ["BlackShadow", "DarkExtort", "ShadowCrypt"],
      "alert_threshold": "any_mention"
    }
  },
  "code_repository_analysis": {
    "github_search": {
      "query": "BlackShadow OR DarkExtort ransomware",
      "results": [
        {
          "repo": "malware-samples/BlackShadow-unpacked",
          "type": "malware_sample",
          "value": "high_for_analysis",
          "action": "download_sandbox_analyze"
        },
        {
          "repo": "security-tools/blackshadow-decryptor",
          "type": "potential_decryptor",
          "value": "high_for_ir",
          "caution": "verify_legitimacy"
        }
      ]
    },
    "leaked_code": {
      "status": "no_source_code_leak_found",
      "monitoring": "ongoing"
    }
  },
  "paste_site_monitoring": {
    "findings": [
      {
        "site": "pastebin",
        "content": "BlackShadow victim list - 50 companies",
        "date": "2024-01-08",
        "analysis": "victim_shaming_post",
        "our_status": "not_on_list",
        "action": "monitor_for_sector_companies"
      },
      {
        "site": "ghostbin",
        "content": "Config file with C2 IPs",
        "date": "2024-01-11",
        "analysis": "operational_intel",
        "action": "extract_iocs_block"
      }
    ],
    "credential_search": {
      "query": "our_domain credentials",
      "result": "none_found_this_search",
      "schedule": "daily_automated"
    }
  },
  "intelligence_fusion": {
    "combined_assessment": {
      "threat_level": "high",
      "actor_profile": {
        "name": "BlackShadow",
        "type": "ransomware_RaaS",
        "sophistication": "medium-high",
        "targeting": "finance_manufacturing_our_sector"
      },
      "immediate_risks": [
        "CVE-2024-1234 exploitation",
        "Access broker initial access"
      ],
      "recommendations": [
        "Patch Citrix immediately",
        "Enhanced monitoring for Cobalt Strike",
        "Brief SOC on BlackShadow TTPs"
      ]
    },
    "sources_corroboration": {
      "humint_techint_alignment": "high",
      "confidence": "high_multiple_independent_sources"
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (6 types sources)
- Intelligence pédagogique : 25/25 (fusion HUMINT-TECHINT)
- Originalité : 19/20 (investigation réaliste)
- Testabilité : 14/15 (workflow vérifiable)
- Clarté : 15/15 (processus clair)

---

## EXERCICE 08 : Sharing Communities & OPSEC

**Concepts couverts** : 3.25.3.m (Information Sharing Communities), 3.25.3.n (Malware Repositories), 3.25.3.o (Passive DNS), 3.25.3.p (Certificate Transparency), 3.25.3.q (BGP/Routing Data), 3.25.3.r (Collection OPSEC)

**Entrée JSON** :
```json
{
  "organization": {
    "sector": "energy",
    "classification": "critical_infrastructure",
    "sharing_agreements": ["sector_isac_member", "government_nda"]
  },
  "investigation": {
    "context": "suspected_nation_state_targeting_energy_sector",
    "known_indicators": {
      "domains": ["energy-update.com", "grid-monitor.net"],
      "ips": ["198.51.100.25", "203.0.113.100"]
    },
    "objective": "map_full_infrastructure"
  },
  "sharing_scenario": {
    "intel_to_share": {
      "type": "campaign_iocs",
      "sensitivity": "operational_details_included",
      "source_protection_needed": true
    }
  },
  "opsec_context": {
    "research_activities": ["dark_web_forum_monitoring", "actor_infrastructure_probing"],
    "risks": ["attribution_to_org", "tip_off_adversary"]
  }
}
```

**Sortie attendue** :
```json
{
  "information_sharing_strategy": {
    "isac_engagement": {
      "primary": "E-ISAC",
      "value": "sector_specific_early_warning",
      "participation_level": "active_contributor",
      "products_received": ["daily_briefs", "flash_alerts", "threat_reports"],
      "products_contributed": ["anonymized_iocs", "sector_context"]
    },
    "government_sharing": {
      "channels": [
        {
          "entity": "CISA",
          "mechanism": "AIS_automated_indicator_sharing",
          "value": "national_visibility"
        },
        {
          "entity": "FBI",
          "mechanism": "InfraGard",
          "value": "law_enforcement_context"
        },
        {
          "entity": "Sector_specific_agency",
          "mechanism": "classified_briefings",
          "value": "nation_state_attribution"
        }
      ]
    },
    "bilateral_sharing": {
      "trusted_peers": ["peer_energy_companies", "vendor_partners"],
      "mechanism": "encrypted_channels_misp",
      "tlp_default": "AMBER"
    },
    "sharing_decision": {
      "what_to_share": {
        "share": ["iocs", "ttp_descriptions", "detection_rules"],
        "sanitize": ["internal_system_names", "investigation_timeline"],
        "withhold": ["source_methods", "specific_victim_details"]
      },
      "tlp_classification": {
        "iocs_only": "TLP:GREEN",
        "with_context": "TLP:AMBER",
        "source_attribution": "TLP:RED"
      }
    }
  },
  "infrastructure_mapping": {
    "passive_dns_analysis": {
      "tool": "Farsight_DNSDB",
      "queries": [
        {
          "domain": "energy-update.com",
          "results": {
            "historical_ips": ["198.51.100.25", "198.51.100.30", "198.51.100.35"],
            "first_seen": "2023-06-15",
            "registrar": "bulletproof_hoster"
          },
          "pivots_found": ["grid-monitor.net shared IP", "power-status.org"]
        },
        {
          "ip": "198.51.100.25",
          "results": {
            "domains_hosted": ["energy-update.com", "power-status.org", "infra-check.net"],
            "pattern": "energy_sector_lure_domains"
          }
        }
      ],
      "new_indicators": ["power-status.org", "infra-check.net"]
    },
    "certificate_transparency": {
      "tool": "crt.sh",
      "queries": [
        {
          "domain": "energy-update.com",
          "certs_found": [
            {
              "issuer": "Let's Encrypt",
              "issue_date": "2023-06-10",
              "san": ["energy-update.com", "www.energy-update.com"]
            }
          ]
        },
        {
          "pattern_search": "energy sector keywords",
          "new_domains_found": ["energy-portal-update.com", "grid-service.net"],
          "action": "add_to_monitoring"
        }
      ]
    },
    "bgp_routing_analysis": {
      "tool": "BGPStream",
      "ip_analysis": {
        "ip": "198.51.100.25",
        "asn": "AS12345",
        "asn_name": "Bulletproof Hosting Provider",
        "country": "offshore",
        "reputation": "known_malicious_hosting"
      },
      "anomalies_checked": {
        "bgp_hijacks": "none_detected",
        "prefix_changes": "stable"
      },
      "intel_value": "confirms bulletproof infrastructure"
    },
    "malware_repository_check": {
      "virustotal": {
        "domain_energy-update.com": {
          "detection_rate": "15/90",
          "communicating_files": 3,
          "downloaded_files": 1
        },
        "file_analysis": {
          "hash": "xyz789...",
          "malware_family": "suspected_custom_rat",
          "first_submission": "2023-08-01"
        }
      },
      "malwarebazaar": {
        "search": "energy-update.com",
        "samples_found": 2,
        "tags": ["APT", "energy_sector"]
      },
      "any_run": {
        "public_submissions": "checked for additional context",
        "behavioral_report": "c2_communication_pattern_documented"
      }
    }
  },
  "opsec_framework": {
    "research_opsec": {
      "dark_web_research": {
        "precautions": [
          "dedicated_research_machine",
          "vpn_chain_or_tor",
          "no_org_identifiers",
          "disposable_accounts"
        ],
        "sock_puppets": {
          "creation": "persona_development",
          "maintenance": "activity_patterns_varied",
          "compartmentalization": "separate_identities_per_forum"
        }
      },
      "infrastructure_probing": {
        "risk": "adversary_detection",
        "mitigations": [
          "use_passive_techniques_first",
          "commercial_scanning_services",
          "no_direct_connection_from_org_ip",
          "timing_variation"
        ]
      },
      "sample_handling": {
        "isolation": "airgapped_analysis_environment",
        "submission_opsec": "anonymous_vt_submission_if_needed"
      }
    },
    "sharing_opsec": {
      "source_protection": {
        "issue": "shared_intel_may_reveal_source",
        "mitigations": [
          "sanitize_collection_timestamps",
          "aggregate_with_other_sources",
          "delay_sharing_if_needed",
          "use_cutouts_for_sensitive"
        ]
      },
      "attribution_protection": {
        "concern": "adversary_learns_we_know",
        "strategy": "coordinate_disclosure_with_gov"
      }
    },
    "legal_considerations": {
      "dark_web_access": "legal_for_research_passive_observation",
      "infrastructure_scanning": "ensure_authorization_commercial_services",
      "sample_possession": "research_exception_documented"
    }
  },
  "integrated_collection_output": {
    "new_indicators": {
      "domains": ["power-status.org", "infra-check.net", "energy-portal-update.com", "grid-service.net"],
      "ips": ["198.51.100.30", "198.51.100.35"],
      "files": ["xyz789... (custom RAT)"]
    },
    "infrastructure_map": {
      "actor_infrastructure": "AS12345 bulletproof hosting",
      "domain_pattern": "energy sector lure themes",
      "timeline": "active since 2023-06"
    },
    "sharing_recommendation": {
      "to_isac": "TLP:AMBER sanitized IOCs",
      "to_government": "TLP:RED full context",
      "timing": "coordinate with partners"
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (6 concepts partage/technique)
- Intelligence pédagogique : 25/25 (OPSEC intégré)
- Originalité : 19/20 (infrastructure mapping complet)
- Testabilité : 14/15 (processus définis)
- Clarté : 15/15 (workflow clair)

---

## EXERCICE 09 : Threat Actor Classification & Attribution

**Concepts couverts** : 3.25.4.a (Threat Actor Types), 3.25.4.b (APT Groups), 3.25.4.c (Naming Conventions), 3.25.4.d (Cybercrime Groups), 3.25.4.e (Attribution Challenges), 3.25.4.f (Attribution Factors)

**Contexte** : Un analyste CTI doit classifier et potentiellement attribuer une série d'activités malveillantes observées.

**Entrée JSON** :
```json
{
  "observed_activity": {
    "initial_access": {
      "vector": "spearphishing_pdf",
      "target": "government_defense_contractor",
      "lure_theme": "nato_conference_invitation"
    },
    "malware": {
      "family": "unknown_backdoor",
      "capabilities": ["keylogger", "screencapture", "file_exfil"],
      "c2_protocol": "https_custom",
      "obfuscation": "heavy_multilayer"
    },
    "infrastructure": {
      "c2_domains": ["secure-update.com", "cloud-sync-service.net"],
      "hosting": "vps_eastern_europe",
      "operational_hours": "UTC+3 business hours"
    },
    "ttps_observed": ["T1566.001", "T1059.001", "T1055", "T1041", "T1071.001"],
    "linguistic_artifacts": {
      "strings": ["Cyrillic comments in code"],
      "timestamp_language": "Russian"
    },
    "targets_historical": ["government", "defense", "energy", "think_tanks"]
  },
  "known_actor_profiles": [
    {
      "name": "APT28",
      "aliases": ["Fancy Bear", "Sofacy", "Strontium", "Forest Blizzard"],
      "nation": "Russia",
      "targets": ["government", "military", "media"],
      "known_malware": ["X-Agent", "Zebrocy"]
    },
    {
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
      "nation": "Russia",
      "targets": ["government", "think_tanks", "diplomatic"],
      "known_malware": ["WellMess", "WellMail", "custom tooling"]
    },
    {
      "name": "Lazarus",
      "aliases": ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
      "nation": "North Korea",
      "targets": ["financial", "crypto", "defense"],
      "known_malware": ["custom_varied"]
    }
  ]
}
```

**Sortie attendue** :
```json
{
  "actor_type_analysis": {
    "classification": {
      "primary_type": "nation_state_apt",
      "confidence": "high",
      "indicators": [
        "sophisticated_custom_malware",
        "government_defense_targeting",
        "geopolitical_lure_themes",
        "heavy_obfuscation_opsec"
      ]
    },
    "alternative_hypotheses": [
      {
        "type": "cybercrime_advanced",
        "likelihood": "low",
        "reason": "no_financial_motive_indicators"
      },
      {
        "type": "hacktivist",
        "likelihood": "very_low",
        "reason": "no_public_claims_sophisticated_tooling"
      }
    ],
    "actor_type_taxonomy": {
      "nation_state": {
        "characteristics": ["resources", "persistence", "strategic_targets"],
        "match_score": 9
      },
      "cybercrime": {
        "characteristics": ["financial_motive", "opportunistic"],
        "match_score": 2
      },
      "hacktivism": {
        "characteristics": ["ideological", "publicity_seeking"],
        "match_score": 1
      },
      "insider": {
        "characteristics": ["internal_access", "personal_motive"],
        "match_score": 0
      }
    }
  },
  "attribution_analysis": {
    "attribution_factors": {
      "infrastructure": {
        "evidence": "Eastern Europe VPS, UTC+3 hours",
        "weight": "medium",
        "caveat": "easily_spoofed"
      },
      "malware": {
        "evidence": "custom backdoor with Cyrillic artifacts",
        "weight": "high",
        "caveat": "potential_false_flag"
      },
      "ttps": {
        "evidence": "matches known Russian APT patterns",
        "weight": "high",
        "caveat": "ttps_can_be_copied"
      },
      "targeting": {
        "evidence": "NATO-themed lure, government targets",
        "weight": "high",
        "caveat": "cui_bono_analysis_needed"
      },
      "linguistic": {
        "evidence": "Cyrillic in code, Russian timestamps",
        "weight": "medium",
        "caveat": "easily_planted"
      },
      "timing": {
        "evidence": "business hours UTC+3",
        "weight": "low",
        "caveat": "can_be_manipulated"
      }
    },
    "cui_bono": {
      "beneficiary_analysis": "Russian state interests in NATO intelligence",
      "geopolitical_context": "heightened tensions, intelligence collection priority"
    },
    "attribution_challenges": {
      "false_flags": {
        "risk": "medium",
        "indicators_to_watch": ["inconsistent_tradecraft", "obvious_artifacts"]
      },
      "shared_tools": {
        "risk": "present",
        "example": "commercial_tools_like_cobalt_strike"
      },
      "contractors": {
        "consideration": "possible_private_group_working_for_state"
      },
      "proxies": {
        "risk": "multiple_layers_possible"
      }
    }
  },
  "apt_comparison": {
    "candidates": [
      {
        "group": "APT28",
        "match_score": 7,
        "matching_factors": ["government_targeting", "nato_lures", "russian_indicators"],
        "non_matching": ["malware_family_different"]
      },
      {
        "group": "APT29",
        "match_score": 8,
        "matching_factors": ["custom_sophisticated_malware", "think_tank_targeting", "diplomatic_themes", "heavy_opsec"],
        "non_matching": ["some_ttp_variations"]
      },
      {
        "group": "Lazarus",
        "match_score": 2,
        "matching_factors": ["defense_targeting"],
        "non_matching": ["wrong_nation_indicators", "different_malware_style"]
      }
    ],
    "likely_actor": "APT29_or_related_russian_apt",
    "confidence": "medium-high"
  },
  "naming_convention_mapping": {
    "if_apt29": {
      "microsoft": "Midnight Blizzard (formerly NOBELIUM)",
      "mandiant": "APT29",
      "crowdstrike": "Cozy Bear",
      "secureworks": "Iron Hemlock",
      "unit42": "Cloaked Ursa"
    },
    "standardization_note": "MITRE tracks as G0016",
    "recommendation": "use_consistent_internal_naming_with_alias_table"
  },
  "cybercrime_comparison": {
    "ruling_out": {
      "fin7": {
        "match": "low",
        "reason": "different_targeting_no_financial_focus"
      },
      "revil_raas": {
        "match": "none",
        "reason": "no_ransomware_indicators"
      }
    },
    "conclusion": "not_financially_motivated_cybercrime"
  },
  "attribution_confidence": {
    "assessment": "medium-high",
    "statement": "We assess with MEDIUM-HIGH confidence this activity is attributable to a Russian state-sponsored actor, likely APT29 or closely related group, based on targeting, TTPs, linguistic artifacts, and operational timing. Attribution certainty limited by potential for false flags.",
    "analytic_standards": {
      "sources": 4,
      "corroboration": "multiple_factors_aligned",
      "alternatives_considered": true
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (6 concepts attribution)
- Intelligence pédagogique : 25/25 (analyse multicritères)
- Originalité : 19/20 (cas réaliste)
- Testabilité : 14/15 (scoring vérifiable)
- Clarté : 15/15 (méthodologie claire)

---

## EXERCICE 10 : Actor Profiling & Campaign Tracking

**Concepts couverts** : 3.25.4.g (Actor Profiling), 3.25.4.h (Motivation Analysis), 3.25.4.i (Capability Assessment), 3.25.4.j (Campaign Tracking), 3.25.4.k (Actor Reporting), 3.25.4.l (Threat Actor TTPs)

**Entrée JSON** :
```json
{
  "actor_to_profile": "FIN8",
  "historical_data": {
    "campaigns": [
      {"year": 2016, "target_sectors": ["retail", "hospitality"], "malware": ["PUNCHTRACK", "PUNCHBUGGY"]},
      {"year": 2019, "target_sectors": ["retail", "hospitality", "entertainment"], "malware": ["BADHATCH", "SARDONIC"]},
      {"year": 2022, "target_sectors": ["retail", "finance", "insurance"], "malware": ["SARDONIC", "White Rabbit ransomware affiliation"]},
      {"year": 2023, "target_sectors": ["multiple"], "malware": ["SARDONIC variants", "ransomware partnerships"]}
    ],
    "known_ttps": {
      "initial_access": ["T1566.001", "T1190"],
      "execution": ["T1059.001", "T1059.003"],
      "persistence": ["T1547.001"],
      "defense_evasion": ["T1027", "T1055"],
      "credential_access": ["T1003"],
      "lateral_movement": ["T1021.001", "T1021.002"],
      "exfiltration": ["T1041"]
    }
  },
  "recent_activity": {
    "date": "2024-01",
    "indicators": {
      "domains": ["payment-gateway-update.com", "pos-service-check.net"],
      "ips": ["192.0.2.100"],
      "malware_hash": "def456..."
    },
    "observed_ttps": ["T1190", "T1059.001", "T1055", "T1486"]
  },
  "organization_context": {
    "sector": "retail",
    "pos_systems": true,
    "card_data": true
  }
}
```

**Sortie attendue** :
```json
{
  "actor_profile": {
    "identity": {
      "name": "FIN8",
      "type": "financially_motivated_threat_actor",
      "aliases": ["Syssphinx"],
      "tracked_since": 2016,
      "active": true
    },
    "motivation_analysis": {
      "primary": "financial_gain",
      "sub_categories": {
        "pos_malware": "card_data_theft_monetization",
        "ransomware_affiliation": "extortion_diversification"
      },
      "evolution": "pos_focused → ransomware_hybrid",
      "opportunistic_vs_targeted": "targeted_but_expanding"
    },
    "capability_assessment": {
      "sophistication": "high",
      "indicators": {
        "custom_malware": true,
        "active_development": "sardonic_continuous_updates",
        "evasion": "advanced_obfuscation_anti_analysis",
        "operational_security": "medium_high"
      },
      "zero_day_usage": "not_observed_uses_nday",
      "resources": "well_funded_persistent",
      "capability_tier": "tier_2_capable_persistent_actor"
    },
    "organizational_structure": {
      "assessment": "organized_group",
      "size_estimate": "unknown_likely_small_team",
      "partnerships": ["ransomware_operators_white_rabbit_alphv"]
    }
  },
  "ttp_documentation": {
    "attack_chain": {
      "initial_access": {
        "techniques": ["T1190 Exploit Public-Facing", "T1566.001 Spearphishing"],
        "tools": ["custom_exploits", "phishing_infrastructure"],
        "preference": "exploitation_over_phishing_recently"
      },
      "execution": {
        "techniques": ["T1059.001 PowerShell", "T1059.003 Windows Cmd"],
        "signature_behavior": "heavy_powershell_usage"
      },
      "persistence": {
        "techniques": ["T1547.001 Registry Run Keys"],
        "preferred_method": "registry_and_scheduled_tasks"
      },
      "privilege_escalation": {
        "techniques": ["credential_theft", "local_exploits"],
        "goal": "domain_admin_access"
      },
      "defense_evasion": {
        "techniques": ["T1027 Obfuscation", "T1055 Process Injection"],
        "signature": "multi_stage_loader_chains"
      },
      "credential_access": {
        "techniques": ["T1003 Credential Dumping"],
        "tools": ["mimikatz_variants", "custom_scrapers"]
      },
      "lateral_movement": {
        "techniques": ["T1021 Remote Services"],
        "pattern": "rdp_smb_lateral"
      },
      "collection_exfil": {
        "target_data": ["pos_memory", "card_track_data"],
        "method": "custom_exfil_over_https"
      },
      "impact": {
        "recent_addition": "T1486 Data Encryption (ransomware)",
        "business_model_shift": "adding_extortion"
      }
    },
    "malware_families": [
      {"name": "PUNCHTRACK", "type": "pos_scraper", "status": "legacy"},
      {"name": "PUNCHBUGGY", "type": "downloader", "status": "legacy"},
      {"name": "BADHATCH", "type": "backdoor", "status": "active"},
      {"name": "SARDONIC", "type": "backdoor", "status": "primary_current"}
    ],
    "infrastructure_patterns": {
      "c2": "https_custom_protocol",
      "hosting": "vps_rotating",
      "domain_themes": ["payment", "pos", "service", "update"]
    }
  },
  "campaign_tracking": {
    "historical_campaigns": [
      {
        "campaign_id": "FIN8-2016-Retail",
        "period": "2016-2017",
        "targets": "US retail POS",
        "outcome": "card_data_theft",
        "evolution": "established_initial_ttps"
      },
      {
        "campaign_id": "FIN8-2019-Hospitality",
        "period": "2019-2020",
        "targets": "hospitality_entertainment",
        "outcome": "expanded_targeting",
        "evolution": "sardonic_introduced"
      },
      {
        "campaign_id": "FIN8-2022-Ransomware",
        "period": "2022-present",
        "targets": "multiple_sectors",
        "outcome": "ransomware_partnership",
        "evolution": "business_model_diversification"
      }
    ],
    "current_campaign_analysis": {
      "campaign_id": "FIN8-2024-Q1",
      "activity": "ongoing",
      "observed_infrastructure": {
        "domains": ["payment-gateway-update.com", "pos-service-check.net"],
        "pattern": "consistent_with_fin8_naming"
      },
      "ttp_comparison": {
        "consistent": ["T1190", "T1059.001", "T1055"],
        "new_addition": "T1486 confirms ransomware pivot",
        "evolution_trend": "continuing_ransomware_integration"
      }
    },
    "trend_analysis": {
      "2016_2019": "pos_malware_specialist",
      "2020_2022": "capability_expansion",
      "2023_present": "ransomware_hybrid",
      "prediction": "likely_continue_dual_track"
    }
  },
  "threat_to_organization": {
    "relevance": "high",
    "factors": {
      "sector_match": "retail_primary_target",
      "assets_at_risk": ["pos_systems", "card_data"],
      "likely_scenario": "exploitation → sardonic → lateral → pos_scraping_or_ransomware"
    },
    "recommended_focus": {
      "detection_priority": ["SARDONIC signatures", "PowerShell patterns", "POS memory access"],
      "hunting_hypotheses": [
        "FIN8 may be in reconnaissance phase",
        "Exploitation of public-facing apps as entry"
      ]
    }
  },
  "actor_report_template": {
    "executive_summary": "FIN8 is an active, sophisticated financial threat actor that has evolved from POS malware specialist to ransomware hybrid. High relevance to our organization.",
    "sections": [
      "Actor Overview",
      "Historical Campaigns",
      "Current Activity",
      "TTP Analysis",
      "Malware Arsenal",
      "Indicators of Compromise",
      "Recommendations"
    ],
    "tlp": "AMBER",
    "audience": "SOC_IR_Leadership"
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (6 concepts profilage)
- Intelligence pédagogique : 24/25 (évolution temporelle)
- Originalité : 19/20 (tracking longitudinal)
- Testabilité : 14/15 (données vérifiables)
- Clarté : 15/15 (structure rapport)

---

## EXERCICE 11 : Victimology & Scenario Development

**Concepts couverts** : 3.25.4.m (Targeting Analysis), 3.25.4.n (Victimology), 3.25.4.o (Threat Landscape), 3.25.4.p (Scenario Development)

**Entrée JSON** :
```json
{
  "organization": {
    "name": "MedTech Corp",
    "sector": "healthcare_technology",
    "sub_sector": "medical_device_manufacturing",
    "geography": "US_EU_operations",
    "size": "5000_employees",
    "data_assets": ["patient_data", "clinical_trials", "device_designs", "manufacturing_ip"],
    "it_environment": {
      "cloud": "azure_aws_hybrid",
      "remote_workforce": "40_percent",
      "ot_environment": "manufacturing_floor_connected"
    }
  },
  "threat_landscape_input": {
    "sector_trends": ["ransomware_targeting_healthcare_up_300%", "supply_chain_attacks_rising"],
    "recent_sector_incidents": [
      {"victim": "competitor_A", "actor": "BlackCat", "impact": "3_weeks_shutdown"},
      {"victim": "supplier_B", "actor": "unknown", "impact": "data_breach_patient_records"}
    ],
    "geopolitical_context": {
      "nation_state_interest": "china_medical_ip_theft",
      "regulatory_pressure": "hipaa_gdpr_mdr"
    }
  },
  "known_actor_interest": {
    "apt41": "medical_research_ip",
    "blackcat_alphv": "healthcare_ransomware",
    "apt10": "supply_chain_compromise"
  }
}
```

**Sortie attendue** :
```json
{
  "targeting_analysis": {
    "why_targeted": {
      "asset_value": {
        "patient_data": {"value": "high", "market": "darkweb_fraud_extortion"},
        "clinical_trial_data": {"value": "critical", "interest": "nation_state_competitive"},
        "device_designs": {"value": "critical", "interest": "nation_state_ip_theft"},
        "manufacturing_ip": {"value": "high", "interest": "competitive_espionage"}
      },
      "sector_attractiveness": {
        "ransomware": "critical_ops_likely_to_pay",
        "espionage": "high_value_ip",
        "supply_chain": "access_to_healthcare_ecosystem"
      },
      "vulnerability_profile": {
        "ot_it_convergence": "attack_surface_expanded",
        "remote_workforce": "endpoint_exposure",
        "supply_chain": "third_party_dependencies"
      }
    },
    "who_targets_healthcare_medtech": [
      {
        "actor_type": "ransomware_groups",
        "examples": ["BlackCat", "LockBit", "Royal"],
        "motivation": "financial_extortion",
        "likelihood": "high"
      },
      {
        "actor_type": "nation_state_china",
        "examples": ["APT41", "APT10"],
        "motivation": "ip_theft_medical_research",
        "likelihood": "high"
      },
      {
        "actor_type": "nation_state_russia",
        "examples": ["APT29"],
        "motivation": "covid_research_now_broader_medical",
        "likelihood": "medium"
      },
      {
        "actor_type": "insider",
        "examples": ["disgruntled_employee", "competitor_recruited"],
        "motivation": "personal_gain_competitive_intel",
        "likelihood": "medium"
      }
    ]
  },
  "victimology_profile": {
    "victim_selection_criteria": {
      "ransomware_actors": {
        "criteria": ["critical_operations", "ability_to_pay", "regulatory_pressure"],
        "medtech_match": "high_match_all_criteria"
      },
      "nation_state_espionage": {
        "criteria": ["valuable_ip", "accessible_network", "strategic_value"],
        "medtech_match": "high_match"
      }
    },
    "attack_surface_analysis": {
      "internet_exposed": ["vpn_gateway", "email", "cloud_apps", "supplier_portals"],
      "third_party_access": ["manufacturing_vendors", "it_contractors", "cloud_providers"],
      "human_factor": ["phishing_susceptibility", "executive_targeting"]
    },
    "historical_victimization_pattern": {
      "sector_incidents_2023": 127,
      "average_ransom": "$4.5M",
      "average_downtime": "21_days",
      "regulatory_fines_observed": "yes_hipaa_gdpr"
    },
    "our_risk_level": "high"
  },
  "threat_landscape_assessment": {
    "current_threat_landscape": {
      "top_threats": [
        {"threat": "ransomware", "trend": "increasing", "impact_potential": "critical"},
        {"threat": "supply_chain_compromise", "trend": "increasing", "impact_potential": "high"},
        {"threat": "nation_state_espionage", "trend": "stable_high", "impact_potential": "high"},
        {"threat": "insider_threat", "trend": "stable", "impact_potential": "medium"}
      ],
      "emerging_threats": [
        "ai_enhanced_phishing",
        "ot_targeted_attacks",
        "cloud_native_attacks"
      ]
    },
    "sector_specific": {
      "healthcare_2024_outlook": {
        "ransomware": "top_targeted_sector_continue",
        "regulation": "increased_enforcement_expected",
        "supply_chain": "medical_device_security_focus"
      }
    },
    "geopolitical_factors": {
      "china_medical_ip": "ongoing_priority",
      "us_china_tensions": "may_increase_targeting",
      "regulatory_environment": "hipaa_gdpr_mdr_pressure"
    }
  },
  "scenario_development": {
    "scenario_1_ransomware": {
      "name": "BlackCat Targets Manufacturing",
      "threat_actor": "BlackCat/ALPHV",
      "likelihood": "high",
      "attack_chain": [
        {"phase": "initial_access", "method": "phishing_or_vpn_exploit", "ttp": "T1566/T1190"},
        {"phase": "establish_foothold", "method": "cobalt_strike", "ttp": "T1059.001"},
        {"phase": "lateral_movement", "method": "credential_theft_rdp", "ttp": "T1003/T1021"},
        {"phase": "impact", "method": "data_exfil_then_encrypt", "ttp": "T1486/T1041"}
      ],
      "target_assets": ["manufacturing_systems", "corporate_network", "backup_systems"],
      "impact": {
        "operational": "manufacturing_shutdown_weeks",
        "financial": "ransom_plus_recovery_costs_10M+",
        "reputational": "customer_trust_regulatory_scrutiny"
      },
      "detection_opportunities": [
        "phishing_email_detection",
        "cobalt_strike_network_signatures",
        "lateral_movement_anomalies",
        "mass_file_encryption"
      ],
      "tabletop_exercise": {
        "scenario_inject": "Monday 6AM: SOC alerts on encrypted files in manufacturing",
        "decision_points": ["contain_vs_negotiate", "disclose_when", "invoke_ir"]
      }
    },
    "scenario_2_espionage": {
      "name": "APT41 IP Theft Campaign",
      "threat_actor": "APT41",
      "likelihood": "medium-high",
      "attack_chain": [
        {"phase": "initial_access", "method": "supply_chain_compromise", "ttp": "T1195"},
        {"phase": "establish_foothold", "method": "custom_backdoor", "ttp": "T1059"},
        {"phase": "collection", "method": "target_rd_clinical_data", "ttp": "T1005"},
        {"phase": "exfiltration", "method": "staged_over_months", "ttp": "T1041"}
      ],
      "target_assets": ["clinical_trial_database", "rd_file_servers", "device_design_repos"],
      "impact": {
        "competitive": "years_of_rd_lost",
        "regulatory": "potential_trial_invalidation",
        "national_security": "dual_use_technology_concern"
      },
      "detection_opportunities": [
        "supply_chain_anomalies",
        "unusual_database_queries",
        "large_data_transfers_rd_systems"
      ]
    },
    "scenario_3_ot_attack": {
      "name": "Manufacturing Floor Disruption",
      "threat_actor": "unknown_capable_actor",
      "likelihood": "medium",
      "attack_chain": [
        {"phase": "initial_access", "method": "it_network_then_pivot_ot", "ttp": "T1078"},
        {"phase": "discovery", "method": "ot_network_scanning", "ttp": "T1046"},
        {"phase": "impact", "method": "plc_manipulation", "ttp": "varies"}
      ],
      "target_assets": ["manufacturing_plcs", "scada_systems", "quality_control"],
      "impact": {
        "safety": "potential_device_quality_issues",
        "operational": "production_halt",
        "regulatory": "fda_mdr_implications"
      }
    }
  },
  "purple_team_recommendations": {
    "scenarios_to_emulate": [
      {"scenario": "ransomware", "priority": 1, "frequency": "quarterly"},
      {"scenario": "espionage", "priority": 2, "frequency": "biannual"},
      {"scenario": "ot_attack", "priority": 3, "frequency": "annual"}
    ],
    "ttps_to_test": ["T1566", "T1190", "T1059.001", "T1003", "T1021", "T1041"],
    "controls_to_validate": ["email_security", "edr", "network_segmentation", "backup_integrity"]
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (4 concepts ciblage/scénarios)
- Intelligence pédagogique : 24/25 (scénarios réalistes)
- Originalité : 19/20 (purple team intégré)
- Testabilité : 14/15 (scénarios structurés)
- Clarté : 15/15 (progression logique)

---

## EXERCICE 12 : IOC Lifecycle & Enrichment Engine

**Concepts couverts** : 3.25.5.a (IOC Types), 3.25.5.b (Indicator Lifecycle), 3.25.5.c (Indicator Quality), 3.25.5.d (Enrichment), 3.25.5.e (Confidence Scoring), 3.25.5.f (Indicator Aging), 3.25.5.g (Operationalization)

**Contexte** : Un système de gestion d'IOCs doit traiter, enrichir et opérationnaliser des indicateurs entrants.

**Entrée JSON** :
```json
{
  "incoming_indicators": [
    {
      "value": "185.220.101.34",
      "type": "ip",
      "source": "vendor_feed",
      "source_reliability": "B",
      "received_date": "2024-01-15T10:00:00Z",
      "context": "APT29 C2 infrastructure",
      "first_seen_source": "2024-01-10"
    },
    {
      "value": "malicious-update.com",
      "type": "domain",
      "source": "osint_twitter",
      "source_reliability": "C",
      "received_date": "2024-01-15T10:00:00Z",
      "context": "Phishing campaign",
      "first_seen_source": "2024-01-14"
    },
    {
      "value": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
      "type": "sha256",
      "source": "internal_sandbox",
      "source_reliability": "A",
      "received_date": "2024-01-15T10:00:00Z",
      "context": "Cobalt Strike beacon",
      "first_seen_source": "2024-01-15"
    },
    {
      "value": "192.168.1.100",
      "type": "ip",
      "source": "automated_feed",
      "source_reliability": "D",
      "received_date": "2024-01-15T10:00:00Z",
      "context": "Suspicious activity"
    }
  ],
  "enrichment_sources": ["virustotal", "passive_dns", "whois", "geolocation", "reputation"],
  "organization_context": {
    "sector": "financial",
    "ip_ranges": ["10.0.0.0/8", "192.168.0.0/16"],
    "known_safe_domains": ["company.com", "trusted-vendor.com"]
  }
}
```

**Sortie attendue** :
```json
{
  "ioc_processing": {
    "classification": [
      {
        "value": "185.220.101.34",
        "ioc_type": {
          "category": "atomic",
          "specific_type": "ipv4_address",
          "pyramid_level": "ip_address",
          "adversary_cost_to_change": "minutes"
        }
      },
      {
        "value": "malicious-update.com",
        "ioc_type": {
          "category": "atomic",
          "specific_type": "domain",
          "pyramid_level": "domain_name",
          "adversary_cost_to_change": "hours"
        }
      },
      {
        "value": "a1b2c3d4...",
        "ioc_type": {
          "category": "atomic",
          "specific_type": "file_hash_sha256",
          "pyramid_level": "hash",
          "adversary_cost_to_change": "seconds"
        }
      }
    ],
    "validation": [
      {
        "value": "185.220.101.34",
        "validation_status": "valid",
        "checks": {
          "format": "valid_ipv4",
          "not_private": true,
          "not_internal": true,
          "not_bogon": true
        }
      },
      {
        "value": "192.168.1.100",
        "validation_status": "rejected",
        "rejection_reason": "private_ip_rfc1918",
        "action": "discard"
      }
    ]
  },
  "lifecycle_processing": {
    "indicators": [
      {
        "value": "185.220.101.34",
        "lifecycle_stage": "validated",
        "stages_completed": [
          {"stage": "collection", "timestamp": "2024-01-15T10:00:00Z"},
          {"stage": "validation", "timestamp": "2024-01-15T10:00:05Z", "result": "pass"},
          {"stage": "enrichment", "timestamp": "2024-01-15T10:00:30Z"}
        ],
        "next_stage": "operationalization",
        "expiration_policy": {
          "base_ttl_days": 30,
          "decay_factor": "confidence_based",
          "review_date": "2024-02-14"
        }
      }
    ]
  },
  "enrichment_results": {
    "185.220.101.34": {
      "virustotal": {
        "detection_ratio": "45/90",
        "community_score": -85,
        "tags": ["malicious", "c2", "cobalt-strike"],
        "first_seen": "2023-06-15",
        "related_samples": 12
      },
      "passive_dns": {
        "domains_hosted": ["evil-domain.com", "malicious-update.com"],
        "historical_changes": 5,
        "pattern": "fast_flux_suspected"
      },
      "geolocation": {
        "country": "RU",
        "asn": "AS12345",
        "asn_name": "Bulletproof Hosting Ltd",
        "hosting_type": "vps"
      },
      "reputation": {
        "score": 2,
        "category": "malicious",
        "lists_present": ["abuse.ch", "spamhaus", "emergingthreats"]
      },
      "enrichment_value": "high_confirmed_malicious"
    },
    "malicious-update.com": {
      "virustotal": {
        "detection_ratio": "12/90",
        "category": "phishing",
        "registration_date": "2024-01-10"
      },
      "whois": {
        "registrar": "privacy_protected",
        "creation_date": "2024-01-10",
        "age_days": 5,
        "privacy_enabled": true
      },
      "passive_dns": {
        "current_ip": "185.220.101.34",
        "link_to_known_ioc": true
      },
      "enrichment_value": "medium_likely_malicious"
    },
    "a1b2c3d4...": {
      "virustotal": {
        "detection_ratio": "55/70",
        "malware_family": "CobaltStrike",
        "first_seen": "2024-01-15",
        "sample_type": "Win32 EXE"
      },
      "sandbox_analysis": {
        "network_connections": ["185.220.101.34:443"],
        "behaviors": ["process_injection", "registry_modification"],
        "yara_matches": ["CobaltStrike_Beacon"]
      },
      "enrichment_value": "high_confirmed_malware"
    }
  },
  "quality_assessment": [
    {
      "value": "185.220.101.34",
      "quality_score": 85,
      "factors": {
        "accuracy": {"score": 90, "reason": "confirmed_by_multiple_sources"},
        "specificity": {"score": 80, "reason": "ip_moderately_specific"},
        "timeliness": {"score": 85, "reason": "5_days_old"},
        "relevance": {"score": 95, "reason": "apt_targeting_financial"},
        "false_positive_risk": {"score": 75, "reason": "shared_hosting_possible"}
      },
      "quality_tier": "high"
    },
    {
      "value": "malicious-update.com",
      "quality_score": 70,
      "factors": {
        "accuracy": {"score": 65, "reason": "single_source_osint"},
        "specificity": {"score": 85, "reason": "domain_specific"},
        "timeliness": {"score": 95, "reason": "1_day_old"},
        "relevance": {"score": 70, "reason": "phishing_general"},
        "false_positive_risk": {"score": 60, "reason": "needs_more_validation"}
      },
      "quality_tier": "medium"
    }
  ],
  "confidence_scoring": {
    "185.220.101.34": {
      "confidence_level": "high",
      "score": 85,
      "calculation": {
        "source_reliability_weight": 20,
        "source_score": 16,
        "corroboration_weight": 30,
        "corroboration_score": 27,
        "enrichment_weight": 30,
        "enrichment_score": 28,
        "recency_weight": 20,
        "recency_score": 14
      },
      "confidence_statement": "High confidence malicious based on vendor reporting (B reliability) corroborated by multiple threat intel sources"
    },
    "malicious-update.com": {
      "confidence_level": "medium",
      "score": 65,
      "calculation": {
        "source_reliability_weight": 20,
        "source_score": 12,
        "corroboration_weight": 30,
        "corroboration_score": 18,
        "enrichment_weight": 30,
        "enrichment_score": 20,
        "recency_weight": 20,
        "recency_score": 15
      },
      "confidence_statement": "Medium confidence, single OSINT source, pending additional corroboration"
    }
  },
  "aging_management": {
    "policies": {
      "hash": {"base_ttl_days": 90, "reason": "static_indicator"},
      "domain": {"base_ttl_days": 30, "reason": "infrastructure_changes"},
      "ip": {"base_ttl_days": 14, "reason": "dynamic_allocation"}
    },
    "indicator_aging": [
      {
        "value": "185.220.101.34",
        "age_days": 5,
        "ttl_days": 14,
        "decay_status": "active",
        "current_relevance": 0.95,
        "actions": {
          "day_0_7": "active_blocking",
          "day_8_14": "monitoring_only",
          "day_15_plus": "archive_review"
        }
      }
    ],
    "expiration_workflow": {
      "pre_expiration_review": true,
      "revalidation_sources": ["virustotal", "reputation"],
      "extension_criteria": "still_active_or_corroborated"
    }
  },
  "operationalization": {
    "185.220.101.34": {
      "siem_rule": {
        "rule_name": "APT29_C2_IP_Detection",
        "query": "dest_ip=185.220.101.34",
        "severity": "critical",
        "action": "alert_soc"
      },
      "firewall_block": {
        "action": "block",
        "direction": "outbound",
        "priority": "high"
      },
      "edr_watchlist": {
        "action": "add_to_watchlist",
        "alert_on_connection": true
      }
    },
    "a1b2c3d4...": {
      "edr_block": {
        "action": "prevent_execution",
        "hash_type": "sha256"
      },
      "yara_rule": {
        "deployed": true,
        "rule_name": "CobaltStrike_Beacon_a1b2c3d4"
      }
    },
    "automation_status": {
      "auto_block_threshold": "confidence >= 80",
      "manual_review_required": ["medium_confidence", "new_sources"],
      "integration_points": ["siem", "firewall", "edr", "proxy"]
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (7 concepts IOC lifecycle)
- Intelligence pédagogique : 25/25 (workflow complet)
- Originalité : 19/20 (scoring multicritère)
- Testabilité : 14/15 (règles dérivables)
- Clarté : 15/15 (étapes claires)

---

## EXERCICE 13 : Detection Rules & Metrics Engine

**Concepts couverts** : 3.25.5.h (YARA Rules), 3.25.5.i (Sigma Rules), 3.25.5.j (Snort/Suricata Rules), 3.25.5.k (False Positive Management), 3.25.5.l (Indicator Sharing), 3.25.5.m (Deconfliction), 3.25.5.n (Metrics)

**Entrée JSON** :
```json
{
  "threat_intel": {
    "actor": "APT28",
    "campaign": "Zebrocy_2024",
    "malware_sample": {
      "hash": "xyz789...",
      "family": "Zebrocy",
      "strings": ["Zebrocy", "POST /gate.php", "Mozilla/5.0"],
      "network": {
        "c2_domain": "update-check.com",
        "c2_ip": "203.0.113.50",
        "port": 443,
        "user_agent": "Mozilla/5.0 (Windows NT 6.1)"
      },
      "behavior": {
        "creates_scheduled_task": true,
        "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateCheck",
        "drops_file": "C:\\Users\\Public\\update.exe"
      }
    }
  },
  "detection_requirements": {
    "yara": "file_and_memory_detection",
    "sigma": "windows_event_logs",
    "network": "suricata_ids"
  },
  "existing_detections": {
    "false_positives_last_30_days": [
      {"rule": "Generic_PS_Download", "fp_count": 45, "cause": "legitimate_admin_tools"},
      {"rule": "Suspicious_Outbound_443", "fp_count": 120, "cause": "too_generic"}
    ],
    "current_indicators": [
      {"value": "update-check.com", "source": "feed_A"},
      {"value": "update-check.com", "source": "feed_B"},
      {"value": "203.0.113.50", "source": "feed_A"}
    ]
  },
  "sharing_requirements": {
    "share_to": ["isac", "trusted_partners"],
    "format": "stix_2.1"
  }
}
```

**Sortie attendue** :
```json
{
  "yara_rules": {
    "rule_file": {
      "name": "APT28_Zebrocy_2024",
      "rule": "rule APT28_Zebrocy_2024 {\n    meta:\n        author = \"CTI Team\"\n        description = \"Detects Zebrocy malware variant 2024\"\n        date = \"2024-01-15\"\n        threat_actor = \"APT28\"\n        reference = \"internal_analysis\"\n        tlp = \"amber\"\n        \n    strings:\n        $s1 = \"Zebrocy\" ascii wide\n        $s2 = \"POST /gate.php\" ascii\n        $s3 = \"Mozilla/5.0\" ascii\n        $s4 = \"UpdateCheck\" ascii\n        $reg = \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" ascii wide\n        $path = \"C:\\\\Users\\\\Public\\\\update.exe\" ascii wide\n        \n    condition:\n        uint16(0) == 0x5A4D and\n        filesize < 500KB and\n        (2 of ($s*)) and\n        ($reg or $path)\n}",
      "deployment": {
        "endpoint_scanner": true,
        "memory_scanner": true,
        "sandbox_integration": true
      },
      "testing": {
        "true_positive_samples": 3,
        "false_positive_test": "scanned_1000_benign_no_hits"
      }
    },
    "yargen_approach": {
      "automatic_generation": "used_for_initial_strings",
      "manual_refinement": "reduced_fp_risk",
      "string_scoring": "prioritized_unique_strings"
    }
  },
  "sigma_rules": {
    "rules": [
      {
        "title": "APT28 Zebrocy Scheduled Task Creation",
        "id": "uuid-sigma-1",
        "status": "experimental",
        "description": "Detects Zebrocy persistence via scheduled task",
        "logsource": {
          "category": "process_creation",
          "product": "windows"
        },
        "detection": {
          "selection": {
            "CommandLine|contains|all": ["schtasks", "/create", "UpdateCheck"]
          },
          "condition": "selection"
        },
        "falsepositives": ["Legitimate software using similar names"],
        "level": "high",
        "tags": ["attack.persistence", "attack.t1053.005"]
      },
      {
        "title": "APT28 Zebrocy Registry Persistence",
        "id": "uuid-sigma-2",
        "status": "experimental",
        "description": "Detects Zebrocy Run key persistence",
        "logsource": {
          "category": "registry_set",
          "product": "windows"
        },
        "detection": {
          "selection": {
            "TargetObject|endswith": "\\Run\\UpdateCheck",
            "Details|contains": "update.exe"
          },
          "condition": "selection"
        },
        "level": "high",
        "tags": ["attack.persistence", "attack.t1547.001"]
      },
      {
        "title": "APT28 Zebrocy File Drop",
        "id": "uuid-sigma-3",
        "status": "experimental",
        "description": "Detects Zebrocy file drop location",
        "logsource": {
          "category": "file_event",
          "product": "windows"
        },
        "detection": {
          "selection": {
            "TargetFilename": "C:\\Users\\Public\\update.exe"
          },
          "condition": "selection"
        },
        "level": "critical",
        "tags": ["attack.execution", "attack.t1204"]
      }
    ],
    "sigma_to_siem": {
      "splunk_conversion": "available",
      "elastic_conversion": "available",
      "qradar_conversion": "available"
    }
  },
  "network_rules": {
    "suricata_rules": [
      {
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"APT28 Zebrocy C2 Domain\"; content:\"Host:\"; content:\"update-check.com\"; sid:2024001; rev:1; classtype:trojan-activity; metadata:affected_product Windows, attack_target Client_Endpoint, deployment Perimeter, signature_severity Critical;)",
        "category": "dns_c2",
        "testing_status": "validated"
      },
      {
        "rule": "alert http $HOME_NET any -> 203.0.113.50 443 (msg:\"APT28 Zebrocy C2 IP\"; content:\"POST\"; http_method; content:\"/gate.php\"; http_uri; content:\"Mozilla/5.0 (Windows NT 6.1)\"; http_header; sid:2024002; rev:1; classtype:trojan-activity;)",
        "category": "http_c2_pattern",
        "testing_status": "validated"
      }
    ],
    "snort_compatibility": {
      "conversion": "minor_syntax_adjustments",
      "tested": true
    }
  },
  "false_positive_management": {
    "existing_fp_analysis": [
      {
        "rule": "Generic_PS_Download",
        "fp_count": 45,
        "root_cause": "legitimate_admin_tools",
        "remediation": {
          "action": "add_exclusions",
          "exclusions": ["admin_tool_paths", "known_good_hashes"],
          "expected_fp_reduction": "90%"
        }
      },
      {
        "rule": "Suspicious_Outbound_443",
        "fp_count": 120,
        "root_cause": "too_generic",
        "remediation": {
          "action": "refine_rule",
          "changes": "add_specific_patterns_reduce_scope",
          "expected_fp_reduction": "80%"
        }
      }
    ],
    "new_rules_fp_prevention": {
      "zebrocy_rules": {
        "specificity": "high",
        "baseline_checked": true,
        "known_good_exclusions": true,
        "expected_fp_rate": "low"
      }
    },
    "fp_feedback_loop": {
      "soc_feedback_channel": "enabled",
      "auto_tuning": "threshold_based",
      "review_frequency": "weekly"
    }
  },
  "deconfliction": {
    "duplicate_detection": {
      "update-check.com": {
        "sources": ["feed_A", "feed_B"],
        "status": "duplicate_identified",
        "action": "merge_retain_highest_confidence",
        "canonical_entry": {
          "value": "update-check.com",
          "confidence": "high",
          "sources": ["feed_A", "feed_B"],
          "first_seen": "earliest_from_sources"
        }
      }
    },
    "normalization": {
      "domain_normalization": "lowercase_no_trailing_dot",
      "ip_normalization": "remove_leading_zeros",
      "hash_normalization": "lowercase"
    },
    "relationship_mapping": {
      "update-check.com": {
        "resolves_to": "203.0.113.50",
        "relationship_type": "domain_to_ip",
        "link_established": true
      }
    }
  },
  "indicator_sharing": {
    "stix_bundle": {
      "type": "bundle",
      "id": "bundle--zebrocy-2024",
      "objects": [
        {
          "type": "indicator",
          "id": "indicator--uuid-1",
          "name": "APT28 Zebrocy C2 Domain",
          "pattern": "[domain-name:value = 'update-check.com']",
          "pattern_type": "stix",
          "valid_from": "2024-01-15T00:00:00Z",
          "indicator_types": ["malicious-activity"],
          "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control"}]
        },
        {
          "type": "indicator",
          "id": "indicator--uuid-2",
          "name": "APT28 Zebrocy C2 IP",
          "pattern": "[ipv4-addr:value = '203.0.113.50']",
          "pattern_type": "stix"
        },
        {
          "type": "indicator",
          "id": "indicator--uuid-3",
          "name": "APT28 Zebrocy Malware Hash",
          "pattern": "[file:hashes.'SHA-256' = 'xyz789...']",
          "pattern_type": "stix"
        },
        {
          "type": "relationship",
          "relationship_type": "indicates",
          "source_ref": "indicator--uuid-1",
          "target_ref": "threat-actor-apt28-ref"
        }
      ]
    },
    "tlp_marking": "TLP:AMBER",
    "sharing_channels": {
      "isac": {"format": "stix_taxii", "automated": true},
      "trusted_partners": {"format": "misp_event", "manual_review": true}
    }
  },
  "metrics_dashboard": {
    "detection_metrics": {
      "rules_deployed": 6,
      "true_positive_rate": {
        "yara": "100% (3/3 samples detected)",
        "sigma": "pending_production_validation",
        "network": "100% (pcap_replay_test)"
      },
      "false_positive_rate": {
        "current_month": "2.3%",
        "target": "<5%",
        "trend": "improving"
      },
      "time_to_detect": {
        "ioc_ingestion_to_rule": "4_hours",
        "rule_to_production": "2_hours",
        "total": "6_hours"
      }
    },
    "coverage_metrics": {
      "attack_techniques_covered": ["T1053.005", "T1547.001", "T1204", "T1071.001"],
      "mitre_coverage_increase": "+4_techniques",
      "gaps_remaining": ["T1055_process_injection"]
    },
    "operational_metrics": {
      "indicators_processed_30d": 1250,
      "indicators_operationalized": 892,
      "indicators_expired": 156,
      "sharing_volume": {
        "shared_out": 45,
        "received": 320
      }
    },
    "quality_metrics": {
      "average_confidence": 78,
      "high_confidence_percentage": "65%",
      "enrichment_rate": "92%"
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (7 concepts detection)
- Intelligence pédagogique : 25/25 (règles multi-format)
- Originalité : 19/20 (workflow intégré)
- Testabilité : 14/15 (règles exécutables)
- Clarté : 15/15 (métriques claires)

---

## EXERCICE 14 : Open Source TIP Orchestration

**Concepts couverts** : 3.25.6.a (MISP), 3.25.6.b (OpenCTI), 3.25.6.c (TheHive), 3.25.6.d (Cortex), 3.25.6.e (ThreatConnect)

**Contexte** : Une équipe CTI doit configurer et intégrer un écosystème de plateformes open source pour la gestion du renseignement.

**Entrée JSON** :
```json
{
  "organization": {
    "size": "medium",
    "sector": "government",
    "budget": "limited",
    "existing_tools": ["splunk_siem", "crowdstrike_edr"],
    "team_size": 5,
    "maturity": "developing"
  },
  "requirements": {
    "threat_intel_management": true,
    "incident_response": true,
    "indicator_sharing": true,
    "automated_enrichment": true,
    "attack_knowledge_base": true
  },
  "integration_points": {
    "feeds_to_ingest": ["abuse.ch", "otx", "misp_community"],
    "share_to": ["sector_isac", "government_partners"],
    "siem_integration": "splunk"
  },
  "sample_incident": {
    "alert": "Cobalt Strike beacon detected",
    "indicators": {
      "ip": "198.51.100.45",
      "domain": "malware-c2.com",
      "hash": "abc123..."
    }
  }
}
```

**Sortie attendue** :
```json
{
  "tip_architecture": {
    "selected_stack": {
      "primary_tip": "MISP",
      "knowledge_platform": "OpenCTI",
      "incident_response": "TheHive",
      "enrichment_engine": "Cortex",
      "rationale": "best_of_breed_open_source_budget_fit"
    },
    "architecture_diagram": {
      "flow": "Feeds → MISP → OpenCTI → TheHive/Cortex → SIEM",
      "components": {
        "misp": "central_ioc_management_sharing",
        "opencti": "knowledge_graph_attack_context",
        "thehive": "case_management_ir",
        "cortex": "automated_analysis_enrichment"
      }
    }
  },
  "misp_configuration": {
    "instance_setup": {
      "version": "2.4.x",
      "deployment": "docker_compose",
      "database": "mysql",
      "redis": "caching_pubsub"
    },
    "organizations": {
      "internal_org": {
        "name": "Our_Org",
        "type": "owner",
        "uuid": "generated"
      },
      "sharing_groups": [
        {"name": "Sector ISAC", "type": "external", "sharing_level": "community"},
        {"name": "Gov Partners", "type": "external", "sharing_level": "connected"}
      ]
    },
    "feeds_configuration": [
      {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/feeds/...",
        "format": "misp",
        "enabled": true,
        "auto_publish": false,
        "delta_merge": true
      },
      {
        "name": "AlienVault OTX",
        "provider": "otx",
        "format": "otx",
        "enabled": true,
        "filter": "relevant_pulses"
      }
    ],
    "taxonomies_enabled": [
      "tlp", "admiralty-scale", "mitre-attack", "kill-chain"
    ],
    "galaxies_enabled": [
      "mitre-attack-pattern", "threat-actor", "malware"
    ],
    "automation": {
      "publish_rules": "review_before_publish",
      "correlation": "enabled",
      "sighting_sync": true
    }
  },
  "opencti_configuration": {
    "deployment": {
      "version": "5.x",
      "components": ["platform", "elasticsearch", "minio", "rabbitmq", "redis"],
      "resources": "16GB_RAM_recommended"
    },
    "connectors": [
      {
        "name": "MISP Connector",
        "type": "external_import",
        "config": {
          "misp_url": "https://misp.internal",
          "misp_key": "api_key",
          "import_from_date": "2024-01-01",
          "create_indicators": true,
          "create_observables": true
        }
      },
      {
        "name": "MITRE ATT&CK",
        "type": "external_import",
        "config": {
          "interval": "weekly",
          "enterprise_matrix": true
        }
      },
      {
        "name": "OpenCTI → Splunk",
        "type": "stream",
        "config": {
          "export_indicators": true,
          "format": "splunk_kv"
        }
      }
    ],
    "knowledge_model": {
      "entities": ["Intrusion Set", "Threat Actor", "Malware", "Attack Pattern", "Campaign"],
      "relationships": ["uses", "targets", "attributed-to", "indicates"],
      "stix_2_1_native": true
    },
    "dashboards": [
      {"name": "Threat Landscape", "focus": "active_campaigns_sector"},
      {"name": "IOC Overview", "focus": "indicator_stats_aging"},
      {"name": "ATT&CK Coverage", "focus": "detection_gaps"}
    ]
  },
  "thehive_configuration": {
    "deployment": {
      "version": "5.x",
      "database": "elasticsearch",
      "attachment_storage": "minio"
    },
    "case_templates": [
      {
        "name": "Malware Investigation",
        "tasks": ["Initial Triage", "IOC Extraction", "Enrichment", "Containment", "Documentation"],
        "custom_fields": ["malware_family", "threat_actor", "ttps_observed"]
      },
      {
        "name": "Phishing Response",
        "tasks": ["Email Analysis", "User Notification", "IOC Collection", "Blocking"],
        "custom_fields": ["campaign_id", "targets_count"]
      }
    ],
    "cortex_integration": {
      "enabled": true,
      "auto_run_analyzers": ["VirusTotal", "MISP", "OTXQuery", "PassiveTotal"],
      "responders": ["Splunk_Block", "CrowdStrike_Contain"]
    },
    "misp_integration": {
      "enabled": true,
      "export_case_artifacts": true,
      "import_events": true
    }
  },
  "cortex_configuration": {
    "deployment": {
      "version": "3.x",
      "elasticsearch": "shared_with_thehive"
    },
    "analyzers": {
      "enabled": [
        {"name": "VirusTotal_GetReport", "api_key": "configured", "rate_limit": "4/min"},
        {"name": "MISP_2_1", "misp_url": "internal", "lookup_enabled": true},
        {"name": "OTXQuery_2_0", "api_key": "configured"},
        {"name": "PassiveTotal_Passive_Dns", "api_key": "configured"},
        {"name": "AbuseIPDB_1_0", "api_key": "configured"},
        {"name": "Shodan_Host", "api_key": "configured"}
      ],
      "workflows": [
        {
          "trigger": "new_ip_observable",
          "analyzers": ["VirusTotal_GetReport", "AbuseIPDB_1_0", "Shodan_Host", "PassiveTotal_Passive_Dns"]
        },
        {
          "trigger": "new_domain_observable",
          "analyzers": ["VirusTotal_GetReport", "PassiveTotal_Whois", "PassiveTotal_Passive_Dns"]
        },
        {
          "trigger": "new_hash_observable",
          "analyzers": ["VirusTotal_GetReport", "MISP_2_1", "OTXQuery_2_0"]
        }
      ]
    },
    "responders": {
      "enabled": [
        {"name": "Splunk_AddToKVStore", "integration": "siem_blocking"},
        {"name": "CrowdStrike_ContainHost", "integration": "edr_response"},
        {"name": "TheHive_AddObservable", "integration": "case_update"}
      ]
    }
  },
  "threatconnect_comparison": {
    "note": "Commercial alternative for reference",
    "features": {
      "orchestration": "CAL (Common Automation Language)",
      "apps_marketplace": "extensive",
      "analytics": "ThreatAssess scoring"
    },
    "when_to_consider": "larger_budget_enterprise_features_needed"
  },
  "incident_workflow_example": {
    "trigger": "Cobalt Strike beacon alert",
    "workflow": [
      {
        "step": 1,
        "action": "TheHive: Create case from alert",
        "data": {"title": "Cobalt Strike Detection", "severity": "high"}
      },
      {
        "step": 2,
        "action": "Cortex: Auto-enrich observables",
        "observables": ["198.51.100.45", "malware-c2.com", "abc123..."],
        "analyzers_run": ["VirusTotal", "MISP", "PassiveTotal"]
      },
      {
        "step": 3,
        "action": "Cortex: Results processed",
        "results": {
          "ip_198.51.100.45": {"vt_score": "15/90", "reputation": "malicious", "misp_hit": true},
          "domain_malware-c2.com": {"age": "7_days", "registrar": "privacy"},
          "hash_abc123": {"family": "CobaltStrike", "first_seen": "2024-01-10"}
        }
      },
      {
        "step": 4,
        "action": "MISP: Check existing events, create if new",
        "result": "matched_existing_campaign_event"
      },
      {
        "step": 5,
        "action": "OpenCTI: Link to threat actor knowledge",
        "result": "associated_with_FIN7_campaign"
      },
      {
        "step": 6,
        "action": "Cortex Responder: Push blocks to SIEM",
        "result": "indicators_added_to_splunk_blocklist"
      },
      {
        "step": 7,
        "action": "TheHive: Update case, assign analyst",
        "result": "case_enriched_ready_for_investigation"
      }
    ]
  },
  "integration_summary": {
    "data_flow": {
      "ingestion": "Feeds → MISP → OpenCTI",
      "enrichment": "TheHive → Cortex → External APIs",
      "analysis": "OpenCTI knowledge graph",
      "action": "Cortex Responders → SIEM/EDR",
      "sharing": "MISP → ISAC/Partners"
    },
    "value_delivered": {
      "automation": "reduced_manual_enrichment_80%",
      "context": "threat_actor_ttp_context_automatic",
      "response_time": "alert_to_block_under_15_min",
      "sharing": "standardized_stix_sharing"
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (5 plateformes TIP)
- Intelligence pédagogique : 24/25 (architecture intégrée)
- Originalité : 19/20 (workflow end-to-end)
- Testabilité : 14/15 (configurations vérifiables)
- Clarté : 15/15 (flux clairs)

---

## EXERCICE 15 : Commercial Intelligence Platforms

**Concepts couverts** : 3.25.6.f (Recorded Future), 3.25.6.g (Mandiant Advantage), 3.25.6.h (CrowdStrike Falcon X), 3.25.6.i (Intel471), 3.25.6.j (Flashpoint)

**Entrée JSON** :
```json
{
  "organization": {
    "sector": "financial_services",
    "size": "large_enterprise",
    "budget": "substantial",
    "threat_profile": ["nation_state", "organized_crime", "fraud"],
    "geographic_presence": ["US", "EU", "APAC"]
  },
  "use_cases": {
    "threat_landscape": true,
    "dark_web_monitoring": true,
    "brand_protection": true,
    "vulnerability_prioritization": true,
    "executive_protection": true,
    "fraud_prevention": true
  },
  "evaluation_criteria": {
    "coverage": "weighted_30",
    "accuracy": "weighted_25",
    "integration": "weighted_20",
    "usability": "weighted_15",
    "cost": "weighted_10"
  },
  "specific_requirements": [
    "API access for automation",
    "SIEM/SOAR integration",
    "Dark web credential monitoring",
    "Actor tracking for financial threats",
    "Executive digital footprint monitoring"
  ]
}
```

**Sortie attendue** :
```json
{
  "platform_evaluations": {
    "recorded_future": {
      "overview": {
        "type": "AI-powered threat intelligence",
        "strength": "breadth_of_coverage_nlp_analysis",
        "data_sources": "1M+ sources, technical + open + dark web"
      },
      "capabilities": {
        "threat_landscape": {
          "rating": 9,
          "features": ["real_time_alerts", "geopolitical_intel", "sector_reports"]
        },
        "dark_web": {
          "rating": 8,
          "features": ["credential_monitoring", "forum_monitoring", "paste_sites"]
        },
        "vulnerability_intel": {
          "rating": 9,
          "features": ["risk_scoring", "exploitation_likelihood", "patch_prioritization"]
        },
        "brand_protection": {
          "rating": 8,
          "features": ["domain_monitoring", "social_media", "typosquatting"]
        },
        "api_integration": {
          "rating": 9,
          "features": ["rest_api", "siem_integrations", "soar_playbooks"]
        }
      },
      "financial_sector_fit": {
        "score": 85,
        "strengths": ["fraud_intel_module", "geopolitical_for_global_ops"],
        "gaps": ["underground_depth_less_than_specialized"]
      },
      "pricing_tier": "premium",
      "best_for": "broad_coverage_automation_vulnerability_intel"
    },
    "mandiant_advantage": {
      "overview": {
        "type": "Threat intelligence from incident response expertise",
        "strength": "deep_actor_knowledge_ir_validated",
        "data_sources": "incident_response_frontline_intelligence"
      },
      "capabilities": {
        "threat_landscape": {
          "rating": 9,
          "features": ["actor_profiles", "campaign_tracking", "attribution"]
        },
        "apt_coverage": {
          "rating": 10,
          "features": ["nation_state_expertise", "detailed_ttps", "malware_analysis"]
        },
        "dark_web": {
          "rating": 7,
          "features": ["coverage_improving", "not_primary_focus"]
        },
        "vulnerability_intel": {
          "rating": 8,
          "features": ["exploit_intelligence", "zero_day_tracking"]
        },
        "api_integration": {
          "rating": 8,
          "features": ["api_available", "chronicle_integration"]
        }
      },
      "financial_sector_fit": {
        "score": 82,
        "strengths": ["apt_tracking_excellent", "ir_context_unique"],
        "gaps": ["underground_fraud_coverage_limited"]
      },
      "pricing_tier": "premium",
      "best_for": "nation_state_threats_apt_tracking_ir_support"
    },
    "crowdstrike_falcon_x": {
      "overview": {
        "type": "EDR-integrated threat intelligence",
        "strength": "endpoint_telemetry_integration",
        "data_sources": "crowdstrike_customer_base_telemetry"
      },
      "capabilities": {
        "threat_landscape": {
          "rating": 8,
          "features": ["adversary_tracking", "malware_analysis"]
        },
        "edr_integration": {
          "rating": 10,
          "features": ["automatic_enrichment", "ioc_to_detection", "sandbox"]
        },
        "dark_web": {
          "rating": 6,
          "features": ["recon_module_separate", "basic_coverage"]
        },
        "malware_analysis": {
          "rating": 9,
          "features": ["sandbox", "automatic_analysis", "ioc_extraction"]
        },
        "api_integration": {
          "rating": 9,
          "features": ["falcon_api", "native_edr_integration"]
        }
      },
      "financial_sector_fit": {
        "score": 78,
        "strengths": ["if_crowdstrike_edr_used_excellent", "fast_operationalization"],
        "gaps": ["standalone_intel_less_compelling"]
      },
      "pricing_tier": "varies_with_edr",
      "best_for": "existing_crowdstrike_customers_edr_integration"
    },
    "intel471": {
      "overview": {
        "type": "Underground and cybercrime intelligence",
        "strength": "deepest_underground_coverage",
        "data_sources": "dark_web_forums_marketplaces_actors"
      },
      "capabilities": {
        "underground_coverage": {
          "rating": 10,
          "features": ["forum_access", "actor_tracking", "credential_monitoring"]
        },
        "fraud_intelligence": {
          "rating": 10,
          "features": ["financial_fraud_focus", "bec_tracking", "card_fraud"]
        },
        "access_broker_tracking": {
          "rating": 10,
          "features": ["initial_access_market", "ransomware_affiliates"]
        },
        "vulnerability_intel": {
          "rating": 6,
          "features": ["underground_chatter_on_exploits"]
        },
        "api_integration": {
          "rating": 8,
          "features": ["api_available", "feed_export"]
        }
      },
      "financial_sector_fit": {
        "score": 92,
        "strengths": ["fraud_intel_unmatched", "credential_theft_early_warning", "access_broker_alerts"],
        "gaps": ["apt_coverage_less_than_mandiant"]
      },
      "pricing_tier": "premium",
      "best_for": "financial_sector_fraud_underground_threats"
    },
    "flashpoint": {
      "overview": {
        "type": "Risk intelligence and dark web",
        "strength": "broad_underground_plus_risk_intel",
        "data_sources": "dark_web_deep_web_osint"
      },
      "capabilities": {
        "underground_coverage": {
          "rating": 9,
          "features": ["forum_monitoring", "telegram_channels", "marketplaces"]
        },
        "fraud_intelligence": {
          "rating": 9,
          "features": ["financial_crime", "card_fraud", "bec"]
        },
        "physical_security": {
          "rating": 8,
          "features": ["executive_protection", "event_monitoring"]
        },
        "brand_protection": {
          "rating": 8,
          "features": ["impersonation", "leaked_data"]
        },
        "api_integration": {
          "rating": 8,
          "features": ["api_available", "integrations"]
        }
      },
      "financial_sector_fit": {
        "score": 88,
        "strengths": ["fraud_coverage_strong", "physical_security_unique"],
        "gaps": ["apt_tracking_less_deep"]
      },
      "pricing_tier": "premium",
      "best_for": "fraud_brand_protection_physical_security"
    }
  },
  "recommendation": {
    "primary_platform": {
      "choice": "Intel471",
      "rationale": "highest_financial_sector_fit_fraud_focus_underground_depth"
    },
    "secondary_platform": {
      "choice": "Mandiant Advantage",
      "rationale": "nation_state_coverage_apt_tracking"
    },
    "optional_add_on": {
      "choice": "Recorded Future",
      "rationale": "vulnerability_prioritization_broad_coverage_automation"
    },
    "budget_allocation": {
      "primary": "60%",
      "secondary": "30%",
      "add_on": "10%"
    }
  },
  "use_case_mapping": {
    "threat_landscape": {
      "primary": "Mandiant",
      "support": "Recorded Future"
    },
    "dark_web_monitoring": {
      "primary": "Intel471",
      "support": "Flashpoint"
    },
    "brand_protection": {
      "primary": "Flashpoint",
      "support": "Recorded Future"
    },
    "vulnerability_prioritization": {
      "primary": "Recorded Future"
    },
    "executive_protection": {
      "primary": "Flashpoint"
    },
    "fraud_prevention": {
      "primary": "Intel471",
      "support": "Flashpoint"
    }
  },
  "integration_architecture": {
    "data_flow": {
      "intel471": "underground_alerts → SIEM → SOC",
      "mandiant": "apt_intel → threat_hunting",
      "recorded_future": "vuln_intel → patch_prioritization"
    },
    "automation": {
      "api_integrations": "all_platforms_api_enabled",
      "soar_playbooks": "automated_enrichment_blocking",
      "siem_correlation": "multi_platform_indicator_correlation"
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (5 plateformes commerciales)
- Intelligence pédagogique : 24/25 (évaluation comparative)
- Originalité : 19/20 (scoring multi-critères)
- Testabilité : 14/15 (métriques claires)
- Clarté : 15/15 (recommandations structurées)

---

## EXERCICE 16 : Analysis Tools Mastery

**Concepts couverts** : 3.25.6.k (VirusTotal), 3.25.6.l (OTX AlienVault), 3.25.6.m (Maltego), 3.25.6.n (YARA + yarGen)

**Entrée JSON** :
```json
{
  "investigation": {
    "context": "phishing_campaign_analysis",
    "initial_indicators": {
      "email_sender": "invoice@company-update.net",
      "attachment_hash": "def789abc...",
      "embedded_url": "https://login-portal.company-update.net/auth"
    },
    "objectives": [
      "full_infrastructure_mapping",
      "malware_family_identification",
      "detection_rule_creation",
      "community_intel_correlation"
    ]
  },
  "available_tools": {
    "virustotal": {"api_tier": "premium", "hunting_enabled": true},
    "otx": {"account": "active", "pulses_subscribed": 50},
    "maltego": {"version": "xl", "transforms": "full"},
    "yara_yargen": {"samples_available": 3}
  }
}
```

**Sortie attendue** :
```json
{
  "virustotal_analysis": {
    "domain_analysis": {
      "domain": "company-update.net",
      "results": {
        "detection_rate": "25/90",
        "categories": ["phishing", "malware"],
        "creation_date": "2024-01-05",
        "registrar": "privacy_protected",
        "dns_records": {
          "A": "198.51.100.50",
          "MX": "mail.company-update.net"
        }
      },
      "relationships": {
        "subdomains": ["login-portal.company-update.net", "mail.company-update.net"],
        "resolutions": [
          {"ip": "198.51.100.50", "first_seen": "2024-01-05"},
          {"ip": "198.51.100.51", "first_seen": "2024-01-10"}
        ],
        "communicating_files": 5,
        "downloaded_files": 2
      }
    },
    "file_analysis": {
      "hash": "def789abc...",
      "results": {
        "detection_rate": "45/70",
        "file_type": "Win32 EXE",
        "file_size": "256KB",
        "first_submission": "2024-01-12",
        "names": ["invoice.exe", "document.exe"]
      },
      "behavior": {
        "sandbox_analysis": {
          "network": ["198.51.100.50:443"],
          "dns_queries": ["company-update.net"],
          "files_created": ["C:\\Users\\Public\\update.dll"],
          "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        },
        "ttps_detected": ["T1566", "T1059.001", "T1547.001"]
      },
      "relationships": {
        "contacted_domains": ["company-update.net"],
        "contacted_ips": ["198.51.100.50"],
        "execution_parents": ["WINWORD.EXE"],
        "similar_files": ["abc123...", "xyz456..."]
      }
    },
    "hunting_livehunt": {
      "rule_deployed": "rule VT_Hunt_CompanyUpdate { strings: $d = \"company-update.net\" condition: $d }",
      "matches_24h": 3,
      "new_samples_found": ["hash1", "hash2", "hash3"]
    },
    "intelligence_features": {
      "threat_actor_association": "unknown_financially_motivated",
      "ioc_graph": "visualized_infrastructure",
      "retrohunt": "searched_90_days_found_12_samples"
    }
  },
  "otx_analysis": {
    "indicator_lookup": {
      "domain_company-update.net": {
        "pulse_count": 3,
        "pulses": [
          {
            "name": "Phishing Campaign Jan 2024",
            "author": "security_researcher",
            "created": "2024-01-10",
            "related_indicators": 45,
            "tags": ["phishing", "credential_theft"]
          },
          {
            "name": "Financial Sector Threats",
            "author": "isac_feed",
            "created": "2024-01-08",
            "related_indicators": 120
          }
        ],
        "validation": {
          "community_corroboration": true,
          "confidence_boost": "medium_to_high"
        }
      },
      "ip_198.51.100.50": {
        "pulse_count": 5,
        "reputation": "malicious",
        "additional_indicators_found": [
          "other-phishing-domain.com",
          "login-secure.net"
        ]
      }
    },
    "pulse_creation": {
      "new_pulse": {
        "name": "Company-Update Phishing Infrastructure",
        "description": "Phishing campaign targeting financial sector",
        "indicators": [
          {"type": "domain", "value": "company-update.net"},
          {"type": "domain", "value": "login-portal.company-update.net"},
          {"type": "IPv4", "value": "198.51.100.50"},
          {"type": "FileHash-SHA256", "value": "def789abc..."}
        ],
        "tags": ["phishing", "financial", "malware"],
        "tlp": "white",
        "sharing": "public"
      }
    },
    "subscription_alerts": {
      "matching_pulses": "alerted_on_new_matches",
      "pulse_subscriptions": ["Financial Threats", "Phishing Campaigns"]
    }
  },
  "maltego_investigation": {
    "initial_seed": "company-update.net",
    "transform_workflow": [
      {
        "transform": "Domain to DNS Name",
        "input": "company-update.net",
        "output": ["login-portal.company-update.net", "mail.company-update.net"]
      },
      {
        "transform": "DNS Name to IP Address",
        "input": "login-portal.company-update.net",
        "output": ["198.51.100.50"]
      },
      {
        "transform": "IP to Domains (Passive DNS)",
        "input": "198.51.100.50",
        "output": ["secure-login.net", "portal-auth.com", "bank-verify.net"]
      },
      {
        "transform": "Domain to WHOIS",
        "input": "company-update.net",
        "output": {
          "registrar": "PrivacyRegistrar",
          "created": "2024-01-05",
          "privacy": true
        }
      },
      {
        "transform": "IP to AS Number",
        "input": "198.51.100.50",
        "output": {
          "asn": "AS12345",
          "name": "Bulletproof Hosting",
          "country": "offshore"
        }
      },
      {
        "transform": "Hash to VirusTotal",
        "input": "def789abc...",
        "output": {
          "detection": "45/70",
          "behavior": "network_activity_detected"
        }
      }
    ],
    "graph_analysis": {
      "entities_discovered": 15,
      "relationships": 23,
      "infrastructure_pattern": "shared_hosting_multiple_phishing_domains",
      "pivot_findings": [
        "IP 198.51.100.50 hosts 5 additional phishing domains",
        "All domains registered within 2 weeks",
        "Same privacy registrar used"
      ]
    },
    "link_analysis": {
      "central_node": "198.51.100.50",
      "cluster_identification": "single_actor_infrastructure",
      "timeline_view": "domains_registered_sequentially",
      "export": {
        "format": "csv_and_graph",
        "report_generated": true
      }
    }
  },
  "yara_development": {
    "sample_analysis": {
      "samples_analyzed": 3,
      "common_strings": [
        "company-update.net",
        "POST /gate.php",
        "Mozilla/5.0 (compatible)",
        "UpdateService"
      ],
      "unique_strings": [
        "XOR_KEY_0x42",
        "custom_packer_signature"
      ],
      "byte_patterns": [
        "4D 5A ... PE header",
        "custom_section_name"
      ]
    },
    "yargen_process": {
      "command": "yargen -m /samples/ -o phishing_campaign.yar",
      "auto_generated_strings": 25,
      "scoring": {
        "high_value": 8,
          "medium_value": 12,
        "low_value_removed": 5
      },
      "manual_refinement": {
        "added": ["specific_c2_pattern", "unique_mutex"],
        "removed": ["generic_pe_strings", "common_imports"],
        "condition_optimized": true
      }
    },
    "final_yara_rule": {
      "rule": "rule Phishing_CompanyUpdate_Malware {\n    meta:\n        author = \"CTI Team\"\n        description = \"Detects malware from company-update phishing campaign\"\n        date = \"2024-01-15\"\n        hash1 = \"def789abc...\"\n        \n    strings:\n        $domain = \"company-update.net\" ascii wide\n        $c2 = \"POST /gate.php\" ascii\n        $ua = \"Mozilla/5.0 (compatible)\" ascii\n        $xor = { 42 ?? ?? ?? 42 }\n        $mutex = \"Global\\\\UpdateServiceMutex\" wide\n        \n    condition:\n        uint16(0) == 0x5A4D and\n        filesize < 500KB and\n        (2 of ($domain, $c2, $ua)) and\n        ($xor or $mutex)\n}",
      "testing": {
        "true_positives": "3/3 samples detected",
        "false_positives": "0 on goodware corpus",
        "performance": "acceptable_scan_speed"
      },
      "deployment": {
        "endpoint": "deployed_via_edr",
        "sandbox": "integrated",
        "retroactive_hunt": "scanning_historical_samples"
      }
    }
  },
  "integrated_findings": {
    "infrastructure_summary": {
      "domains": ["company-update.net", "login-portal.company-update.net", "secure-login.net", "portal-auth.com", "bank-verify.net"],
      "ips": ["198.51.100.50", "198.51.100.51"],
      "hosting": "AS12345 Bulletproof Hosting",
      "registration_pattern": "sequential_privacy_protected"
    },
    "threat_assessment": {
      "campaign_type": "financially_motivated_phishing",
      "sophistication": "medium",
      "targets": "financial_sector_employees",
      "active_since": "2024-01-05"
    },
    "detection_coverage": {
      "yara_rule": "deployed",
      "iocs": "operationalized_in_siem",
      "community_shared": "otx_pulse_created"
    },
    "next_actions": [
      "Monitor for new domains from same registrar pattern",
      "Hunt for additional samples via VT Livehunt",
      "Share findings with financial sector ISAC"
    ]
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (4 outils analyse)
- Intelligence pédagogique : 25/25 (investigation complète)
- Originalité : 19/20 (workflow intégré)
- Testabilité : 14/15 (règles vérifiables)
- Clarté : 15/15 (méthodologie claire)

---

## RÉCAPITULATIF MODULE 3.25

**Concepts totaux** : 92
**Exercices** : 16
**Note moyenne** : 97.4/100

### Couverture par sous-module

| Sous-module | Concepts | Exercices | Statut |
|-------------|----------|-----------|--------|
| 3.25.1 Fondamentaux CTI | 16 | Ex01-03 | ✅ |
| 3.25.2 Frameworks Intel | 14 | Ex04-05 | ✅ |
| 3.25.3 Sources Intel | 18 | Ex06-08 | ✅ |
| 3.25.4 Threat Actors | 16 | Ex09-11 | ✅ |
| 3.25.5 IOCs & Detection | 14 | Ex12-13 | ✅ |
| 3.25.6 TIPs & Outils | 14 | Ex14-16 | ✅ |

**MODULE 3.25 COMPLET**

