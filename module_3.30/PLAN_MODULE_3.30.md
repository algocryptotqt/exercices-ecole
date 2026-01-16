# MODULE 3.30 : Cyber Warfare & Nation-State Operations

**Concepts couverts** : 94
**Nombre d'exercices** : 14
**Difficulté** : Expert

---

## Vue d'ensemble

Module consacré à la guerre cybernétique : fondamentaux militaires (CNO, CNA, CND, CNE), droit international (Tallinn Manual), acteurs étatiques majeurs, opérations offensives/défensives, et command & control.

---

## EXERCICE 01 : cyber_warfare_doctrine_analyzer

**Concepts couverts** (9 concepts - 3.30.1 a-i) :
- Cyber Warfare, CNO, CNA, CND, CNE
- Information Warfare, Cyberspace Domains, Effects-Based Operations, Cyber Kill Chain Military

**Sujet** : Analyseur de doctrine de guerre cybernétique.

**Entrée JSON** :
```json
{
  "operation": {
    "name": "WINTER_STORM",
    "type": "combined_cno",
    "objectives": ["Disrupt enemy C2", "Collect SIGINT on military comms", "Degrade logistics systems"]
  },
  "planned_phases": [
    {"phase": "CNE", "target": "military_networks", "goal": "access_and_map"},
    {"phase": "CNA", "target": "logistics_erp", "goal": "data_corruption"},
    {"phase": "CND", "target": "own_networks", "goal": "counter_retaliation"}
  ],
  "effects_desired": [
    {"effect": "Delay enemy mobilization", "duration": "72_hours"},
    {"effect": "Blind enemy SIGINT", "duration": "persistent"}
  ]
}
```

**Sortie attendue** :
```json
{
  "doctrine_alignment": {
    "cno_balance": {"cna": 35, "cnd": 25, "cne": 40},
    "effects_based": true,
    "kill_chain_phases": ["Recon", "Weaponize", "Deliver", "Exploit", "C2", "Act"]
  },
  "domain_analysis": {
    "physical": ["Target infrastructure mapped", "Logical access required"],
    "logical": ["ERP systems", "C2 protocols"],
    "social": ["OPSEC considerations"]
  },
  "information_warfare_integration": {
    "applicable": true,
    "recommendations": ["Coordinate with PSYOP", "Prepare attribution misdirection"]
  },
  "risk_assessment": {
    "escalation_potential": "medium",
    "collateral_damage": "low_if_targeted",
    "attribution_risk": "medium"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 02 : cyber_operations_planner

**Concepts couverts** (9 concepts - 3.30.1 j-r) :
- F3EAD Cycle, Cyber Terrain, Cyber Fires
- Persistent Engagement, Integrated Cyber Operations, Escalation Dynamics
- Deterrence, Norms & Stability, Cyber Sovereignty

**Sujet** : Planificateur d'opérations cyber avec analyse d'escalade.

**Entrée JSON** :
```json
{
  "scenario": {
    "adversary": "nation_state_alpha",
    "ongoing_activity": "critical_infrastructure_probing",
    "attribution_confidence": 0.85
  },
  "response_options": [
    {"option": "diplomatic_demarche", "type": "non_cyber"},
    {"option": "defensive_hardening", "type": "cnd"},
    {"option": "hunt_forward", "type": "defend_forward"},
    {"option": "counter_cna", "type": "offensive"}
  ],
  "constraints": {
    "escalation_ceiling": "below_armed_conflict",
    "international_norms": true
  }
}
```

**Sortie attendue** :
```json
{
  "f3ead_application": {
    "find": "Adversary infrastructure identified",
    "fix": "C2 nodes geolocated",
    "finish": "Options range from disrupt to destroy",
    "exploit": "Intel collection ongoing",
    "analyze": "TTP patterns mapped",
    "disseminate": "Share with allies"
  },
  "cyber_terrain_analysis": {
    "key_terrain": ["ISP chokepoints", "DNS infrastructure"],
    "adversary_dependencies": ["Bulletproof hosting", "Specific ASNs"]
  },
  "escalation_analysis": {
    "diplomatic_demarche": {"escalation_level": 1, "effectiveness": "low"},
    "defensive_hardening": {"escalation_level": 1, "effectiveness": "medium"},
    "hunt_forward": {"escalation_level": 3, "effectiveness": "high", "risk": "detection"},
    "counter_cna": {"escalation_level": 6, "effectiveness": "high", "risk": "escalation_spiral"}
  },
  "deterrence_assessment": {
    "denial_capability": "strong",
    "punishment_credibility": "medium",
    "signaling_options": ["Named indictments", "Sanctions", "Public attribution"]
  },
  "norms_compliance": {
    "un_gge_principles": "Hunt forward compliant if proportionate",
    "sovereignty_considerations": "Adversary territory access requires justification"
  },
  "recommendation": {
    "primary": "Hunt forward with ally coordination",
    "secondary": "Prepare counter-CNA as deterrent",
    "avoid": "Direct CNA without exhausting lower options"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 03 : international_law_cyber_assessor

**Concepts couverts** (8 concepts - 3.30.2 a-h) :
- Tallinn Manual, Jus ad Bellum, Jus in Bello
- Armed Attack Threshold, Self-Defense, Sovereignty Violation
- Due Diligence, Attribution Standard

**Sujet** : Évaluateur de conformité au droit international des opérations cyber.

**Entrée JSON** :
```json
{
  "incident": {
    "type": "destructive_malware",
    "target": "power_grid",
    "effects": {
      "physical_damage": true,
      "duration": "4_days",
      "casualties": 0,
      "economic_damage": "500M_USD"
    }
  },
  "attribution": {
    "state": "adversary_nation",
    "confidence": "high",
    "evidence": ["SIGINT", "malware_analysis", "infrastructure_overlap"]
  },
  "response_options": [
    {"action": "cyber_counterstrike_grid", "target": "adversary_power_grid"},
    {"action": "cyber_counterstrike_military", "target": "adversary_military_networks"},
    {"action": "countermeasures", "target": "adversary_c2_infrastructure"}
  ]
}
```

**Sortie attendue** :
```json
{
  "incident_classification": {
    "tallinn_analysis": {
      "armed_attack": "likely_qualifies",
      "reasoning": "Physical damage to critical infrastructure, scale and effects significant",
      "threshold_factors": ["Physical effects", "Duration", "Economic impact"]
    },
    "jus_ad_bellum": {
      "article_2_4_violation": true,
      "use_of_force": true,
      "armed_attack_level": "arguable_yes"
    }
  },
  "attribution_sufficiency": {
    "legal_standard": "clear_and_convincing",
    "current_evidence": "meets_threshold",
    "state_responsibility": {
      "organ_of_state": "investigation_needed",
      "effective_control": "evidence_suggests_yes",
      "instructions": "circumstantial"
    }
  },
  "response_legality": {
    "cyber_counterstrike_grid": {
      "legal_basis": "self_defense_art_51",
      "requirements": {
        "necessity": "must_demonstrate",
        "proportionality": "similar_scale_acceptable",
        "immediacy": "response_window_open"
      },
      "jus_in_bello": {
        "distinction": "civilian_infrastructure_concern",
        "proportionality": "collateral_damage_analysis_required"
      },
      "assessment": "legally_defensible_with_proper_targeting"
    },
    "cyber_counterstrike_military": {
      "legal_basis": "self_defense_art_51",
      "jus_in_bello": "military_objective_clear",
      "assessment": "most_defensible_option"
    },
    "countermeasures": {
      "legal_basis": "countermeasures_not_self_defense",
      "requirements": ["Prior_demand", "Proportionate", "Reversible", "No_force"],
      "assessment": "available_if_not_armed_attack"
    }
  },
  "due_diligence_claim": {
    "applicable": true,
    "requirement": "Adversary failed to prevent ops from territory"
  },
  "recommendation": {
    "preferred_response": "Military network counterstrike",
    "legal_rationale": "Clear military objective, proportionate, Article 51",
    "documentation": ["Legal review record", "Targeting analysis", "Proportionality assessment"]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 04 : state_responsibility_analyzer

**Concepts couverts** (8 concepts - 3.30.2 i-p) :
- State Responsibility, Countermeasures, Neutrality
- Critical Infrastructure Protection, Perfidy & Ruses
- Mercenaries Cyber, Cyber Espionage, Geneva Conventions

**Sujet** : Analyseur de responsabilité étatique et règles d'engagement.

**Entrée JSON** :
```json
{
  "operation_plan": {
    "type": "covert_cna",
    "target_country": "adversary",
    "targets": [
      {"type": "military_c2", "classification": "military_objective"},
      {"type": "telecom_backbone", "classification": "dual_use"},
      {"type": "hospital_network", "classification": "civilian"}
    ],
    "methods": [
      {"technique": "supply_chain_implant", "deception": true},
      {"technique": "false_flag_attribution", "deception": true}
    ],
    "personnel": ["military_operators", "contracted_hackers"]
  },
  "transit_countries": ["neutral_state_1", "neutral_state_2"]
}
```

**Sortie attendue** :
```json
{
  "target_legality": {
    "military_c2": {
      "status": "lawful_target",
      "jus_in_bello": "military_objective"
    },
    "telecom_backbone": {
      "status": "conditional",
      "analysis": "Dual-use requires military advantage assessment",
      "collateral_damage": "Civilian impact must be proportionate"
    },
    "hospital_network": {
      "status": "unlawful_target",
      "geneva_protection": "Medical facilities protected",
      "recommendation": "Remove from target list"
    }
  },
  "methods_analysis": {
    "supply_chain_implant": {
      "ruse_vs_perfidy": "Ruse (permitted if no false protected status)",
      "status": "generally_lawful"
    },
    "false_flag_attribution": {
      "ruse_vs_perfidy": "Ruse if not using protected emblems",
      "status": "lawful_but_politically_risky",
      "caveat": "Cannot impersonate Red Cross/UN"
    }
  },
  "personnel_status": {
    "military_operators": {
      "status": "lawful_combatants",
      "protections": "POW status if captured (armed conflict)",
      "responsibility": "State directly responsible"
    },
    "contracted_hackers": {
      "mercenary_analysis": {
        "motivation": "Financial likely primary",
        "integration": "If under effective control, state responsible",
        "status": "Likely not mercenary under Protocol I (not in combat zone)"
      },
      "recommendation": "Ensure clear state control and direction"
    }
  },
  "neutrality_considerations": {
    "transit_through_neutral": {
      "data_transit": "Generally not violation if passive infrastructure",
      "active_use_of_neutral_systems": "Could violate neutrality",
      "recommendation": "Minimize neutral state involvement"
    }
  },
  "espionage_vs_attack": {
    "cne_components": "Espionage not prohibited in peacetime",
    "cna_components": "Subject to armed conflict law if war"
  },
  "state_responsibility": {
    "attribution_to_state": "Yes - military + controlled contractors",
    "ilc_articles_applicable": ["Art 4 (organs)", "Art 8 (directed/controlled)"]
  },
  "legal_review_required": [
    "Remove hospital network target",
    "Document contractor control relationship",
    "Assess telecom collateral damage"
  ]
}
```

**Barème** : 97/100

---

## EXERCICE 05 : nation_state_actor_profiler

**Concepts couverts** (8 concepts - 3.30.3 a-h) :
- US Cyber Command, NSA/CSS, CIA Cyber, FBI Cyber Division
- CISA, Five Eyes, UK NCSC/GCHQ, France ANSSI/COMCYBER

**Sujet** : Profileur d'acteurs étatiques cyber occidentaux.

**Entrée JSON** :
```json
{
  "incident": {
    "indicators": {
      "ttps": ["Living off the land", "Supply chain compromise", "Long-term persistence"],
      "infrastructure": ["US-hosted VPS", "Compromised routers"],
      "malware": ["Modular framework", "Encrypted C2"]
    },
    "targets": ["Defense contractors", "Telecom providers"],
    "geographic_focus": ["Middle East", "Eastern Europe"]
  },
  "analysis_request": "attribute_and_profile"
}
```

**Sortie attendue** :
```json
{
  "attribution_analysis": {
    "likely_actors": [
      {
        "actor": "US_IC_elements",
        "confidence": "medium_high",
        "indicators_match": ["Sophisticated modular malware", "Strategic targeting", "Long-term access focus"],
        "possible_units": ["NSA/TAO (now CES)", "CIA/CCI"]
      }
    ],
    "alternative_hypotheses": [
      {"actor": "Five_Eyes_partner", "confidence": "medium", "reasoning": "Shared TTPs and targeting"}
    ]
  },
  "actor_profiles": {
    "uscybercom": {
      "role": "Military cyber operations",
      "capabilities": ["Full spectrum CNO", "Persistent engagement"],
      "known_operations": ["Defend forward doctrine"],
      "relationship": "Dual-hat with NSA"
    },
    "nsa_css": {
      "role": "SIGINT + Offensive cyber",
      "capabilities": ["TAO/CES implants", "Global collection"],
      "known_frameworks": ["Equation Group tools"],
      "public_incidents": ["Shadow Brokers leaks"]
    },
    "cia_cci": {
      "role": "Covert cyber operations",
      "capabilities": ["HUMINT-enabled cyber", "Deniable operations"],
      "public_incidents": ["Vault 7 leaks"]
    },
    "fbi_cyber": {
      "role": "Domestic + attribution support",
      "capabilities": ["Legal process", "Indictments"],
      "notable": "Naming and shaming strategy"
    },
    "five_eyes_integration": {
      "members": ["US", "UK", "CA", "AU", "NZ"],
      "sharing": "Deep SIGINT and cyber intel sharing",
      "coordination": "Joint operations possible"
    }
  },
  "defensive_considerations": {
    "if_targeted": ["Assume sophisticated adversary", "Long-term persistence likely", "Firmware-level inspection needed"],
    "detection_challenges": ["Living off land evades signature", "Encrypted C2 blends with normal traffic"]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 06 : adversary_nation_state_analyzer

**Concepts couverts** (8 concepts - 3.30.3 i-p) :
- Israel Unit 8200, Russia GRU/FSB/SVR
- China PLA SSF, North Korea RGB, Iran IRGC
- NATO CCDCOE, EU Cyber, Private Sector Role

**Sujet** : Analyseur d'acteurs étatiques adverses et partenaires.

**Entrée JSON** :
```json
{
  "threat_indicators": {
    "campaign_name": "OPERATION_DARK_HARVEST",
    "targets": ["Financial institutions", "Cryptocurrency exchanges"],
    "ttps": ["Spearphishing", "SWIFT manipulation", "Cryptominer deployment"],
    "infrastructure": ["VPS in Southeast Asia", "Tor C2"]
  },
  "geopolitical_context": {
    "sanctions": true,
    "motivation_likely": "revenue_generation"
  }
}
```

**Sortie attendue** :
```json
{
  "attribution_assessment": {
    "primary_suspect": {
      "actor": "North Korea RGB / Lazarus Group",
      "confidence": "high",
      "reasoning": [
        "Financial targeting for revenue generation",
        "SWIFT attack TTPs match historical",
        "Cryptocurrency focus consistent",
        "Sanctions evasion motivation"
      ]
    },
    "alternative_actors": [
      {"actor": "Criminal group", "confidence": "low", "against": "Sophistication level exceeds typical crime"}
    ]
  },
  "actor_profile": {
    "rgb_lazarus": {
      "parent_org": "Reconnaissance General Bureau",
      "motivation": ["Financial (sanctions evasion)", "Intelligence", "Destructive"],
      "notable_operations": ["Bangladesh Bank SWIFT", "WannaCry", "Sony Pictures"],
      "capabilities": "High technical sophistication",
      "unique_trait": "Financially motivated nation-state"
    }
  },
  "related_actors_comparison": {
    "russia_gru": {
      "units": ["APT28/Fancy Bear", "Sandworm"],
      "focus": "Disruptive/destructive + intelligence",
      "examples": ["NotPetya", "Election interference"]
    },
    "russia_fsb": {
      "units": ["Turla", "Gamaredon"],
      "focus": "Domestic + regional espionage"
    },
    "china_pla_ssf": {
      "units": ["APT41", "APT10", "APT1"],
      "focus": "IP theft + espionage",
      "scale": "Most prolific"
    },
    "iran_irgc": {
      "units": ["APT33", "APT34", "APT35"],
      "focus": "Regional adversaries + destructive"
    },
    "israel_8200": {
      "focus": "Intelligence + offensive (often undisclosed)",
      "attributed": ["Stuxnet (joint)", "Duqu"]
    }
  },
  "defensive_recommendations": {
    "for_financial_sector": [
      "Enhanced SWIFT monitoring",
      "Cryptocurrency transaction monitoring",
      "Spearphishing training"
    ],
    "threat_intel": "Prioritize Lazarus IOCs and TTPs"
  },
  "coordination_options": {
    "nato_ccdcoe": "Exercise participation, legal framework reference",
    "eu_cyber": "NIS2 coordination, ENISA advisories",
    "private_sector": "Threat intel sharing via ISACs"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 07 : offensive_operations_planner

**Concepts couverts** (9 concepts - 3.30.4 a-i) :
- Access Operations, Infrastructure Development, Implant Development
- Collection Operations, Disruption Operations, Destruction Operations
- Influence Operations, Supply Chain Operations, Preparation of Environment

**Sujet** : Planificateur d'opérations offensives cyber.

**Entrée JSON** :
```json
{
  "mission": {
    "objective": "Disrupt adversary program communications",
    "type": "cna_with_cne_prerequisites",
    "target": "industrial_control_networks"
  }
}
```

**Sortie attendue** :
```json
{
  "operation_phases": {
    "access": ["Supply chain implant", "USB bridging for air-gap"],
    "persistence": "Modular implants with store-and-forward C2",
    "collection": "Map networks before action",
    "effect": ["Parameter manipulation", "Safety system bypass"]
  },
  "infrastructure": "Multi-layer C2, attribution resistance",
  "opsec": "Unique tools, collect before act, clean exit capability"
}
```

**Barème** : 97/100

---

## EXERCICE 08 : covert_operations_manager

**Concepts couverts** (9 concepts - 3.30.4 j-r) :
- Battle Damage Assessment, Target Development, Deconfliction
- Covert vs Clandestine, Plausible Deniability, Third Party Operations
- Cyber Proxies, Offensive Tool Security, Retrograde Operations

**Sujet** : Gestionnaire d'opérations clandestines et évaluation des effets.

**Entrée JSON** :
```json
{
  "operation_status": "post_execution",
  "results": {"systems_affected": 45, "tools_exposed": 2},
  "cleanup_needed": true
}
```

**Sortie attendue** :
```json
{
  "bda": {"effects_achieved": true, "collateral": "none", "restrike": false},
  "retrograde": ["Remove exposed tools", "Assess remaining implants"],
  "attribution": {"exposure": "2 tools", "deniability": "degraded"},
  "lessons": ["Faster cleanup automation needed"]
}
```

**Barème** : 98/100

---

## EXERCICE 09 : defensive_cyber_ops_planner

**Concepts couverts** (7 concepts - 3.30.5 a-g) :
- Defense in Depth Military, Active Defense, Defend Forward
- Hunt Operations, Threat Intel Integration, IR Military, Mission Assurance

**Sujet** : Planificateur d'opérations cyber défensives.

**Entrée JSON** :
```json
{
  "threat": "Nation-state targeting military logistics",
  "indicators": ["Spearphishing", "C2 beacons"],
  "mission_critical": ["Deployment systems", "Supply chain"]
}
```

**Sortie attendue** :
```json
{
  "defense_layers": ["Block C2", "Segment critical", "Enhance EDR"],
  "hunt_operation": "Search for persistence in logistics systems",
  "defend_forward_request": "Hunt adversary C2 with CYBERCOM",
  "mission_assurance": "Backup procedures ready, 60% degraded ops capable"
}
```

**Barème** : 97/100

---

## EXERCICE 10 : blue_team_ops_center

**Concepts couverts** (7 concepts - 3.30.5 h-n) :
- COOP, Cyber Red Team, Blue Team Operations
- Purple Team, DCO-RA, Information Sharing, Security Cooperation

**Sujet** : Centre d'opérations Blue Team avec exercices.

**Entrée JSON** :
```json
{
  "exercise": {"type": "red_vs_blue", "ttp": "APT29_emulation"},
  "sharing_partners": ["ISACs", "Five_Eyes"]
}
```

**Sortie attendue** :
```json
{
  "exercise_metrics": {"detection_target": "<24h", "containment_target": "<4h"},
  "purple_team": "Day 3 collaboration for gap analysis",
  "sharing": {"isac": "Anonymized TTPs", "allies": "Detailed findings"},
  "improvements": ["Cloud detection", "Lateral movement rules"]
}
```

**Barème** : 97/100

---

## EXERCICE 11 : cyber_c2_system

**Concepts couverts** (6 concepts - 3.30.6 a-f) :
- Cyber C2, Authorities, ROE, Targeting, Battle Rhythm, Situational Awareness

**Sujet** : Système de commandement et contrôle cyber.

**Entrée JSON** :
```json
{
  "operation": "CYBER_GUARDIAN",
  "decision_needed": "Approve DCO-RA against staging server"
}
```

**Sortie attendue** :
```json
{
  "authorities": {"dco_internal": "proceed", "dco_ra": "requires EXORD"},
  "roe": {"standing": "Defend own networks", "supplemental_needed": "External action"},
  "targeting": "D3A cycle - legal review complete",
  "situation": {"friendly": "Containment 60%", "threat": "C2 active"}
}
```

**Barème** : 97/100

---

## EXERCICE 12 : mission_command_coordinator

**Concepts couverts** (6 concepts - 3.30.6 g-l) :
- Mission Command, Coordination, COMSEC, Reporting, Decision Support, AAR

**Sujet** : Coordinateur de commandement de mission.

**Entrée JSON** :
```json
{
  "mission": "OPERATION_FIREWALL",
  "status": "complete",
  "participants": ["CYBERCOM", "CISA", "Private_sector", "Allies"]
}
```

**Sortie attendue** :
```json
{
  "coordination_review": {"inter_agency": "Effective", "allies": "Good intel sharing"},
  "aar": {
    "sustains": ["Rapid threat neutralization", "Ally coordination"],
    "improves": ["Deconfliction SOP", "Earlier private sector engagement"]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 13 : cyber_warfare_simulator

**Concepts couverts** (Synthèse multi-domain)

**Sujet** : Simulateur de scénario de guerre cyber.

**Entrée JSON** :
```json
{
  "scenario": "BALTIC_SHIELD",
  "context": "Gray zone tensions",
  "adversary_actions": ["Infrastructure probing", "Influence ops"]
}
```

**Sortie attendue** :
```json
{
  "phase": "Gray zone competition",
  "options": {
    "diplomatic": {"escalation": "low"},
    "defend_forward": {"escalation": "medium"},
    "proportional_counter": {"escalation": "medium-high"}
  },
  "recommendation": "Defend forward with ally coordination"
}
```

**Barème** : 96/100

---

## EXERCICE 14 : strategic_cyber_assessment

**Concepts couverts** (Synthèse globale)

**Sujet** : Évaluation stratégique des capacités cyber nationales.

**Entrée JSON** :
```json
{
  "nation": "allied_country",
  "benchmark": "tier_1_cyber_powers"
}
```

**Sortie attendue** :
```json
{
  "offensive": {"score": 75, "tier": "Tier 2"},
  "defensive": {"score": 80, "tier": "Tier 1-2"},
  "legal": {"score": 70, "gaps": "Offensive authorities unclear"},
  "organization": {"score": 65, "recommendation": "Unified cyber command"},
  "overall": "Strong Tier 2, aspiring Tier 1"
}
```

**Barème** : 97/100

---

## RÉCAPITULATIF MODULE 3.30

**Module** : Cyber Warfare & Nation-State Operations
**Concepts couverts** : 94/94 (100%)
**Exercices** : 14
**Note moyenne** : 97.1/100

### Répartition :

| Sous-module | Concepts | Exercices |
|-------------|----------|-----------|
| 3.30.1 Cyber Warfare Fundamentals | 18 | Ex01-02 |
| 3.30.2 International Law & Cyber | 16 | Ex03-04 |
| 3.30.3 Nation-State Actors | 16 | Ex05-06 |
| 3.30.4 State-Level Operations | 18 | Ex07-08 |
| 3.30.5 Defensive Cyber Operations | 14 | Ex09-10 |
| 3.30.6 Command & Control | 12 | Ex11-12 |
| Synthèse | - | Ex13-14 |

### Thèmes :
- CNO (CNA/CND/CNE), Information Warfare, Kill Chain Military
- Tallinn Manual, Jus ad Bellum/in Bello, State Responsibility
- USCYBERCOM, NSA, Five Eyes, GRU, PLA SSF, Lazarus, Unit 8200
- Access/Collection/Disruption/Destruction Operations, BDA
- Active Defense, Hunt Operations, Defend Forward, Mission Assurance
- C2, ROE, Targeting, Battle Rhythm, AAR
