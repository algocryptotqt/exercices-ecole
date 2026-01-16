# MODULE 3.35 : Cyber Crisis Management

**Concepts couverts** : 82
**Nombre d'exercices** : 14
**Difficulté** : Expert

---

## Vue d'ensemble

Module spécialisé dans la gestion de crise cyber : structure organisationnelle, prise de décision sous pression, système de commandement d'incident, réponse stratégique, exercices et résilience. Couvre le cycle complet de la prévention à la reconstruction.

---

## EXERCICE 01 : crisis_management_foundation_analyzer

**Concepts couverts** (7 concepts - 3.35.1 a-g) :
- Cyber Crisis Definition, Crisis vs Incident, Crisis Lifecycle
- Crisis Team Structure, Crisis Communication, Stakeholder Management, Decision Rights

**Sujet** : Analyseur des fondamentaux de gestion de crise avec structure organisationnelle.

**Entrée JSON** :
```json
{
  "incident": {
    "type": "ransomware",
    "systems_affected": ["ERP", "Manufacturing_Control", "Email"],
    "business_impact": "Operations halted",
    "discovery_time": "2024-01-15T03:00:00Z"
  },
  "organization": {
    "type": "manufacturing",
    "employees": 5000,
    "revenue_daily_usd": 2000000,
    "existing_crisis_team": false
  }
}
```

**Sortie attendue** :
```json
{
  "crisis_classification": {
    "level": "CRITICAL - Full organizational crisis",
    "rationale": [
      "Multiple critical systems affected",
      "Complete operations halt",
      "Immediate revenue impact ($2M/day)"
    ],
    "escalation": "Executive crisis team activation required"
  },
  "incident_vs_crisis_distinction": {
    "this_is_crisis_because": [
      "Exceeds technical team capacity",
      "Requires executive decisions",
      "Reputational implications",
      "Regulatory notification triggered"
    ]
  },
  "crisis_lifecycle_position": {
    "current_phase": "Detection/Response",
    "immediate_actions": ["Contain spread", "Assess scope", "Activate team"],
    "next_phases": ["Full response", "Recovery", "Learning"]
  },
  "crisis_team_structure": {
    "executive_sponsor": {"role": "CEO or delegate", "authority": "Final decisions, resource allocation"},
    "crisis_manager": {"role": "CSO or CISO", "authority": "Operational command"},
    "technical_lead": {"role": "IR Manager", "authority": "Technical decisions"},
    "communications": {"role": "CCO/PR", "authority": "All external messaging"},
    "legal": {"role": "General Counsel", "authority": "Legal/regulatory guidance"},
    "hr": {"role": "CHRO", "authority": "Employee matters, communications"}
  },
  "stakeholder_communication_plan": {
    "board": {"timing": "Within 2 hours", "method": "Direct call from CEO"},
    "employees": {"timing": "Within 4 hours", "method": "Internal all-hands"},
    "customers": {"timing": "Within 24 hours if data affected", "method": "Email/portal"},
    "regulators": {"timing": "Per requirements (72h GDPR)", "method": "Formal notification"}
  },
  "decision_rights_matrix": {
    "pay_ransom": "Board decision",
    "notify_public": "Executive sponsor with legal",
    "technical_containment": "Technical lead",
    "engage_vendors": "Crisis manager"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 02 : crisis_operations_center_simulator

**Concepts couverts** (7 concepts - 3.35.1 h-n) :
- Crisis Playbooks, War Room Operations, Information Management
- External Resources, Regulatory Requirements, Business Continuity, Post-Crisis Review

**Sujet** : Simulateur de centre d'opérations de crise avec gestion des ressources.

**Entrée JSON** :
```json
{
  "crisis_state": {
    "type": "data_breach",
    "data_affected": "customer_pii",
    "records_count": 500000,
    "jurisdictions": ["EU", "California", "New_York"]
  },
  "current_resources": {
    "internal_ir_team": 5,
    "legal": "in_house",
    "pr": "no_dedicated_team"
  },
  "business_operations": {
    "status": "partially_operational",
    "critical_systems": "functioning"
  }
}
```

**Sortie attendue** :
```json
{
  "war_room_setup": {
    "physical_location": "Secure conference room with restricted access",
    "virtual_component": "Secure video bridge for remote participants",
    "tools_required": [
      "Incident tracking system",
      "Secure communication channel",
      "Status dashboard",
      "Document repository"
    ],
    "battle_rhythm": {
      "morning_standup": "09:00 daily",
      "evening_debrief": "18:00 daily",
      "executive_update": "Twice daily + as needed"
    }
  },
  "information_management": {
    "single_source_of_truth": "Crisis management platform",
    "timeline_tracking": "All events logged with timestamp",
    "status_board": {
      "current_situation": "Live update",
      "actions_in_progress": "Assigned with ETA",
      "blockers": "Escalation path defined"
    }
  },
  "external_resources_needed": {
    "ir_firm": {"status": "ENGAGE IMMEDIATELY", "reason": "Team capacity insufficient"},
    "forensics": {"status": "ENGAGE", "reason": "Evidence preservation"},
    "legal_external": {"status": "ENGAGE", "reason": "Multi-jurisdiction breach"},
    "pr_firm": {"status": "ENGAGE", "reason": "No internal PR team"},
    "law_enforcement": {"status": "EVALUATE", "decision_factors": ["Attribution", "Criminal activity"]}
  },
  "regulatory_timeline": {
    "gdpr": {"deadline": "72 hours", "authority": "Lead supervisory authority", "status": "CRITICAL - 48h remaining"},
    "ccpa": {"deadline": "Expedient manner", "status": "Prepare notification"},
    "ny_shield": {"deadline": "Most expedient possible", "status": "Prepare notification"}
  },
  "business_continuity_measures": {
    "status": "Activated",
    "workarounds": ["Manual customer service", "Backup payment processing"],
    "degraded_mode_services": ["Limited e-commerce functionality"]
  },
  "playbook_activation": {
    "playbook": "Data Breach - PII",
    "checklist_items_completed": 12,
    "checklist_items_remaining": 28,
    "critical_path": ["Scope determination", "Notification preparation", "Credit monitoring setup"]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 03 : decision_making_under_pressure_advisor

**Concepts couverts** (8 concepts - 3.35.2 a-h) :
- Cognitive Biases, Stress Effects, Time Pressure
- Information Overload, Incomplete Information, OODA Loop
- Recognition-Primed Decision, Analytical Decision Making

**Sujet** : Conseiller pour la prise de décision sous pression avec gestion des biais.

**Entrée JSON** :
```json
{
  "decision_needed": {
    "type": "pay_ransom_or_not",
    "deadline": "24 hours before data publication threat",
    "ransom_amount_btc": 50
  },
  "available_information": {
    "backup_status": "Partially recoverable (60%)",
    "business_impact_per_day_usd": 500000,
    "threat_actor": "Known ransomware group with history of data leaks",
    "data_at_risk": "Customer contracts, internal financials"
  },
  "team_dynamics": {
    "ceo_position": "Leaning towards paying",
    "ciso_position": "Against payment",
    "legal_position": "Uncertain about legality",
    "time_in_crisis": "72 hours - team fatigued"
  }
}
```

**Sortie attendue** :
```json
{
  "cognitive_bias_assessment": {
    "detected_biases": [
      {"bias": "Anchoring", "evidence": "CEO focused on ransom amount, not total cost", "mitigation": "Calculate total scenario costs"},
      {"bias": "Confirmation bias", "evidence": "Each party seeking supporting evidence", "mitigation": "Assign devil's advocate"},
      {"bias": "Stress-induced tunnel vision", "evidence": "72h fatigue, deadline pressure", "mitigation": "Fresh perspective, break before decision"}
    ]
  },
  "stress_management": {
    "current_team_state": "Fatigued - decision quality at risk",
    "recommendations": [
      "Mandatory rest rotation before final decision",
      "Bring in fresh executive for perspective",
      "Defer non-critical decisions"
    ]
  },
  "decision_framework": {
    "ooda_loop_analysis": {
      "observe": "Backup 60%, $500K/day loss, known threat actor",
      "orient": "Payment may not guarantee decryption, legal implications",
      "decide": "Framework for systematic evaluation",
      "act": "Execute with contingency plans"
    },
    "analytical_approach": {
      "options": [
        {"option": "Pay ransom", "pros": ["Possible recovery", "Faster resolution"], "cons": ["No guarantee", "Legal risk", "Funds criminal enterprise"]},
        {"option": "Rebuild from backup", "pros": ["No criminal funding", "Legal clarity"], "cons": ["40% data loss", "Extended downtime"]},
        {"option": "Negotiate + parallel rebuild", "pros": ["Buys time", "Keeps options open"], "cons": ["Resource intensive", "May not succeed"]}
      ]
    }
  },
  "information_gap_analysis": {
    "critical_unknowns": [
      "Will payment actually result in decryption?",
      "Legal exposure in relevant jurisdictions",
      "Insurance coverage for ransom"
    ],
    "information_gathering_priority": "Legal opinion on payment legality"
  },
  "recommendation": {
    "approach": "Option 3: Negotiate while pursuing parallel rebuild",
    "rationale": "Preserves options, buys information, manages risk",
    "decision_quality_note": "Recommend 8-hour rest period before final commitment"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 04 : decision_process_optimizer

**Concepts couverts** (8 concepts - 3.35.2 i-p) :
- Intuition vs Analysis, Red Team Thinking, Pre-Mortem Analysis
- Decision Documentation, Reversibility, Escalation Decisions
- De-escalation, Decision Review

**Sujet** : Optimiseur du processus décisionnel avec analyse pré-mortem.

**Entrée JSON** :
```json
{
  "proposed_decision": {
    "action": "Publicly disclose breach before full investigation complete",
    "rationale": "Media leaks likely, want to control narrative",
    "reversibility": "low",
    "time_pressure": "24 hours before potential leak"
  },
  "context": {
    "investigation_completion": "40%",
    "scope_certainty": "low",
    "records_affected_estimate": "Between 10K and 1M"
  }
}
```

**Sortie attendue** :
```json
{
  "reversibility_assessment": {
    "classification": "IRREVERSIBLE - Two-way door decision",
    "implications": "Once disclosed, cannot undisclose",
    "recommendation": "Apply rigorous decision process despite time pressure"
  },
  "pre_mortem_analysis": {
    "assume_decision_failed": "Public disclosure backfires",
    "failure_scenarios": [
      {"scenario": "Scope larger than stated", "impact": "Credibility damage, legal exposure", "probability": "High given 40% investigation"},
      {"scenario": "Scope smaller than feared", "impact": "Unnecessary panic, stock impact", "probability": "Medium"},
      {"scenario": "Investigation reveals no breach", "impact": "Severe reputational damage", "probability": "Low but catastrophic"}
    ],
    "mitigation_strategies": [
      "Caveat disclosure heavily ('ongoing investigation')",
      "Prepare multiple scenario communications",
      "Delay disclosure if investigation can accelerate"
    ]
  },
  "red_team_perspective": {
    "devils_advocate_position": "Do NOT disclose yet",
    "arguments": [
      "40% investigation = high uncertainty",
      "Scope range too wide for credible disclosure",
      "May be disclosing non-breach as breach",
      "Leak may not happen - evaluate source"
    ],
    "counter_arguments": [
      "Losing control of narrative may be worse",
      "Proactive disclosure often viewed favorably"
    ]
  },
  "decision_documentation_template": {
    "decision": "[To be recorded]",
    "date_time": "2024-01-18T14:00:00Z",
    "decision_makers": ["CEO", "CISO", "General Counsel"],
    "information_available": "40% investigation, 10K-1M records estimate",
    "options_considered": ["Immediate disclosure", "Delayed disclosure", "No disclosure"],
    "rationale": "[To be documented]",
    "dissenting_views": "[Record any disagreement]"
  },
  "escalation_assessment": {
    "requires_board": "YES - irreversible decision with major implications",
    "notification_needed": "Audit committee at minimum",
    "timeline": "Emergency board call within 4 hours"
  },
  "recommendation": {
    "action": "Request 48-hour investigation sprint before decision",
    "rationale": "Irreversible decision requires higher certainty",
    "if_leak_occurs": "Prepared statement ready, pivot to reactive disclosure"
  }
}
```

**Barème** : 98/100

---

## EXERCICE 05 : incident_command_system_deployer

**Concepts couverts** (7 concepts - 3.35.3 a-g) :
- Incident Command System, Incident Commander Role, Operations Section
- Planning Section, Logistics Section, Finance/Admin Section, Unified Command

**Sujet** : Déployeur du système de commandement d'incident pour cyber.

**Entrée JSON** :
```json
{
  "incident": {
    "type": "critical_infrastructure_attack",
    "sector": "energy",
    "scope": "Regional power grid control systems",
    "agencies_involved": ["Utility company", "CISA", "FBI", "State emergency management"]
  },
  "resources_available": {
    "internal_ir": 10,
    "vendor_support": true,
    "government_assistance": "requested"
  },
  "duration_estimate": "1-2 weeks"
}
```

**Sortie attendue** :
```json
{
  "ics_structure": {
    "command": {
      "incident_commander": {
        "organization": "Utility company CISO",
        "authority": "Overall incident authority for company systems",
        "responsibilities": ["Set objectives", "Approve IAP", "Resource allocation"]
      },
      "unified_command": {
        "members": [
          {"org": "Utility", "role": "Lead for operational systems"},
          {"org": "FBI", "role": "Lead for criminal investigation"},
          {"org": "CISA", "role": "Lead for technical assistance"},
          {"org": "State EM", "role": "Lead for public coordination"}
        ],
        "shared_objectives": "Restore operations while preserving evidence"
      }
    },
    "operations_section": {
      "chief": "IR Team Lead",
      "branches": [
        {"name": "Containment", "tasks": ["Isolate affected systems", "Block C2"]},
        {"name": "Investigation", "tasks": ["Forensic analysis", "Root cause"]},
        {"name": "Eradication", "tasks": ["Remove malware", "Patch vulnerabilities"]}
      ]
    },
    "planning_section": {
      "chief": "Senior Security Analyst",
      "functions": [
        {"name": "Situation Unit", "task": "Maintain current status"},
        {"name": "Documentation Unit", "task": "Record all activities"},
        {"name": "Technical Specialists", "task": "ICS/SCADA expertise"}
      ]
    },
    "logistics_section": {
      "chief": "IT Operations Manager",
      "functions": [
        {"name": "Service", "task": "Food, rest areas, communications"},
        {"name": "Support", "task": "Equipment, supplies, facilities"},
        {"name": "IT Resources", "task": "Laptops, forensic tools, clean systems"}
      ]
    },
    "finance_admin_section": {
      "chief": "CFO Delegate",
      "functions": [
        {"name": "Time Unit", "task": "Track personnel hours"},
        {"name": "Cost Unit", "task": "Track incident costs"},
        {"name": "Procurement", "task": "Emergency purchases, vendor contracts"}
      ]
    }
  },
  "span_of_control": {
    "assessment": "Within 3-7 optimal range",
    "ic_direct_reports": 5,
    "operations_branches": 3
  },
  "unified_command_protocols": {
    "decision_process": "Consensus on objectives, each agency leads own domain",
    "conflict_resolution": "IC has final authority on company systems",
    "information_sharing": "Controlled - criminal investigation sensitivities"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 06 : incident_action_plan_generator

**Concepts couverts** (7 concepts - 3.35.3 h-n) :
- Span of Control, Operational Period, Incident Action Plan
- Situation Reports, Resource Management, Documentation, Demobilization

**Sujet** : Générateur de plan d'action d'incident avec gestion des périodes opérationnelles.

**Entrée JSON** :
```json
{
  "incident_day": 3,
  "operational_period": {
    "number": 5,
    "start": "2024-01-18T08:00:00Z",
    "end": "2024-01-18T20:00:00Z"
  },
  "current_situation": {
    "containment_status": "80%",
    "investigation_status": "60%",
    "systems_affected": 45,
    "systems_restored": 12
  },
  "resources_deployed": {
    "ir_team": 15,
    "vendor_consultants": 5,
    "it_operations": 20
  }
}
```

**Sortie attendue** :
```json
{
  "incident_action_plan": {
    "operational_period": 5,
    "incident_name": "OPERATION_RESTORE",
    "prepared_by": "Planning Section",
    "approved_by": "Incident Commander",
    "objectives": [
      {"id": 1, "objective": "Complete containment of remaining 20% of affected systems", "priority": "High"},
      {"id": 2, "objective": "Restore 15 additional systems to operational status", "priority": "High"},
      {"id": 3, "objective": "Complete forensic analysis of initial compromise vector", "priority": "Medium"}
    ],
    "strategies": {
      "containment": "Focus on network segments 4 and 7",
      "restoration": "Priority order based on business criticality",
      "investigation": "Analyze earliest compromised host"
    },
    "resource_assignments": {
      "containment_team": {"personnel": 5, "tasks": ["Segment isolation", "Rule deployment"]},
      "restoration_team": {"personnel": 12, "tasks": ["Rebuild from images", "Configuration validation"]},
      "forensics_team": {"personnel": 8, "tasks": ["Timeline analysis", "Malware reverse engineering"]}
    },
    "safety_message": "18-hour shifts max, mandatory rest periods, mental health resources available"
  },
  "situation_report": {
    "sitrep_number": 9,
    "period_covered": "OP 4",
    "current_status": {
      "overall": "Progressing - on track for recovery",
      "containment": "80% complete, 9 systems remaining",
      "restoration": "27% complete (12/45 systems)",
      "investigation": "Root cause identified - phishing leading to credential theft"
    },
    "key_developments": [
      "Identified patient zero - Finance workstation",
      "Confirmed lateral movement via RDP",
      "No evidence of data exfiltration (high confidence)"
    ],
    "resource_status": {
      "personnel": "Adequate - fatigue monitored",
      "equipment": "Sufficient",
      "external_support": "Vendor fully engaged"
    },
    "planned_actions_next_period": [
      "Complete containment",
      "Restore 15 systems",
      "Finalize forensic report"
    ]
  },
  "resource_management": {
    "current_resource_status": {
      "total_personnel": 40,
      "on_shift": 25,
      "resting": 15
    },
    "resource_needs": {
      "additional_forensic_specialist": "Requested from vendor",
      "system_images": "20 additional needed from IT"
    },
    "demobilization_planning": {
      "trigger": "95% restoration achieved",
      "first_release": "Vendor consultants",
      "timeline": "Begin demobilization OP 8 (estimated)"
    }
  },
  "documentation_status": {
    "chain_of_custody": "All evidence properly logged",
    "decision_log": "34 decisions documented",
    "timeline": "Complete and continuously updated",
    "evidence_inventory": "156 items cataloged"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 07 : strategic_response_planner

**Concepts couverts** (7 concepts - 3.35.4 a-g) :
- Strategic vs Tactical, Response Options, Proportionality
- Timing Decisions, Public Response, Legal Response, Diplomatic Response

**Sujet** : Planificateur de réponse stratégique aux incidents majeurs.

**Entrée JSON** :
```json
{
  "incident": {
    "type": "state_sponsored_espionage",
    "target": "Defense contractor",
    "data_stolen": "Classified weapons system designs",
    "attributed_to": "Nation_State_X",
    "attribution_confidence": "high"
  },
  "organization_context": {
    "type": "Government contractor",
    "clearance_level": "Top Secret",
    "contracts_value_usd": 500000000
  },
  "government_involvement": {
    "dod_notified": true,
    "fbi_involved": true,
    "nsa_supporting": true
  }
}
```

**Sortie attendue** :
```json
{
  "strategic_vs_tactical_separation": {
    "tactical_actions": {
      "owner": "Company IR team + FBI",
      "actions": ["Containment", "Eradication", "Forensics", "Evidence preservation"]
    },
    "strategic_decisions": {
      "owner": "Government (DoD, State, NSC)",
      "decisions": ["Attribution response", "Diplomatic action", "Policy changes"]
    }
  },
  "response_options_analysis": {
    "technical": {
      "actions": ["Network hardening", "Enhanced monitoring", "Zero trust implementation"],
      "owner": "Company",
      "timeline": "Immediate to 6 months"
    },
    "legal": {
      "actions": ["Criminal referral (complete)", "Civil action (unlikely vs state actor)"],
      "owner": "DOJ",
      "considerations": "Evidence may be classified"
    },
    "diplomatic": {
      "actions": ["Private demarche", "Public attribution", "UN complaint"],
      "owner": "State Department",
      "considerations": "Broader bilateral relationship"
    },
    "economic": {
      "actions": ["Targeted sanctions", "Trade restrictions"],
      "owner": "Treasury/Commerce",
      "considerations": "Economic interdependence"
    }
  },
  "proportionality_assessment": {
    "attack_severity": "High - classified data theft",
    "proportional_response_options": [
      "Public attribution with evidence",
      "Targeted sanctions on responsible individuals",
      "Diplomatic downgrade"
    ],
    "disproportionate_avoided": [
      "Broad economic sanctions (too escalatory)",
      "Cyber retaliation against civilian infrastructure"
    ]
  },
  "timing_considerations": {
    "immediate": "Tactical containment, evidence preservation",
    "short_term": "Attribution confirmation, response decision",
    "delayed_option": "Time response to broader diplomatic moment",
    "signaling_value": "Prompt response demonstrates capability and will"
  },
  "public_response_strategy": {
    "disclosure_decision": "Government-led, coordinated with company",
    "messaging": "Classified specifics protected, general threat acknowledged",
    "timing": "After response actions locked in"
  },
  "company_role": {
    "primary": "Cooperate with investigation, restore operations",
    "secondary": "Support government response as requested",
    "avoid": "Independent public statements on attribution"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 08 : coordinated_response_orchestrator

**Concepts couverts** (7 concepts - 3.35.4 h-n) :
- Economic Response, Cyber Response, Coordinated Response
- Deterrence Signaling, De-escalation Options, Long-Term Strategy, Lessons Integration

**Sujet** : Orchestrateur de réponse coordonnée avec alliés et partenaires.

**Entrée JSON** :
```json
{
  "incident": {
    "type": "destructive_attack",
    "target": "Financial infrastructure",
    "impact": "Major bank operations disrupted 48 hours",
    "attributed_to": "Nation_State_Y",
    "allied_coordination_requested": true
  },
  "coalition_status": {
    "allies_affected": ["UK", "Germany", "Japan"],
    "coordination_forum": "Five_Eyes + partners",
    "unified_position": "Developing"
  }
}
```

**Sortie attendue** :
```json
{
  "coordinated_response_plan": {
    "coalition_building": {
      "participants": ["US", "UK", "Germany", "Japan", "Australia"],
      "coordination_mechanism": "Secure diplomatic channel + technical channels",
      "shared_objectives": ["Attribution", "Deterrence", "Prevent recurrence"]
    },
    "unified_messaging": {
      "joint_statement_elements": [
        "Condemn destructive cyber attack on financial infrastructure",
        "Attribute to Nation_State_Y with high confidence",
        "Announce coordinated sanctions"
      ],
      "timing": "Simultaneous announcement all capitals"
    }
  },
  "economic_response_coordination": {
    "sanctions_package": {
      "us_sanctions": "OFAC designations - cyber actors + enabling entities",
      "eu_sanctions": "Asset freezes, travel bans",
      "coordinated_timing": "Same day announcement"
    },
    "trade_measures": {
      "technology_export_restrictions": "Coordinated denial of sensitive tech",
      "financial_restrictions": "SWIFT limitations considered"
    }
  },
  "cyber_response_options": {
    "defensive": {
      "actions": ["Enhanced monitoring", "Threat intel sharing", "Sector alerts"],
      "classification": "Unilateral authority"
    },
    "active_defense": {
      "actions": ["Disruption of actor infrastructure"],
      "authority_required": "Presidential",
      "coordination": "Inform allies"
    }
  },
  "deterrence_signaling": {
    "capability_demonstration": "Cyber Command statement on capabilities",
    "willingness": "Joint statement on consequences for future attacks",
    "credibility": "Sanctions and indictments demonstrate follow-through"
  },
  "de_escalation_provisions": {
    "off_ramps": ["Diplomatic channel remains open", "Response calibrated to prevent spiral"],
    "communication_channels": "Maintain despite tensions",
    "face_saving": "Focus on behavior change, not regime"
  },
  "long_term_strategy": {
    "policy_changes": ["Enhanced financial sector requirements", "Incident reporting mandates"],
    "capability_development": ["Improved attribution", "Faster response"],
    "lessons_integration": ["After action review", "Update crisis playbooks", "Exercise revised scenarios"]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 09 : crisis_exercise_designer

**Concepts couverts** (6 concepts - 3.35.5 a-f) :
- Tabletop Exercises, Functional Exercises, Full-Scale Exercises
- Red Team Exercises, Purple Team Exercises, Cyber Range

**Sujet** : Concepteur d'exercices de crise avec progression de complexité.

**Entrée JSON** :
```json
{
  "organization": {
    "type": "Healthcare system",
    "size": "5 hospitals, 20000 employees",
    "current_maturity": "Intermediate - basic IR plan exists"
  },
  "exercise_program_request": {
    "goal": "Improve crisis readiness",
    "budget": "moderate",
    "timeline": "12 months"
  },
  "focus_areas": ["Ransomware", "Data breach", "Medical device compromise"]
}
```

**Sortie attendue** :
```json
{
  "exercise_program_design": {
    "philosophy": "Progressive complexity - build muscle memory before stress testing",
    "phases": [
      {
        "phase": 1,
        "timing": "Months 1-3",
        "exercises": [
          {
            "type": "Tabletop",
            "name": "TTX-1: Ransomware Response",
            "participants": "IT, Security, Executives",
            "duration": "4 hours",
            "objectives": ["Validate decision rights", "Test communication flow", "Identify gaps"]
          },
          {
            "type": "Tabletop",
            "name": "TTX-2: Patient Data Breach",
            "participants": "Privacy, Legal, Compliance, Executives",
            "duration": "4 hours",
            "objectives": ["HIPAA notification process", "Media response", "Patient communication"]
          }
        ]
      },
      {
        "phase": 2,
        "timing": "Months 4-6",
        "exercises": [
          {
            "type": "Functional",
            "name": "FUNC-1: IR Process Validation",
            "participants": "IR team, IT operations",
            "duration": "8 hours",
            "objectives": ["Test actual IR procedures", "Validate tool proficiency", "Measure response times"]
          },
          {
            "type": "Purple Team",
            "name": "PURPLE-1: Detection and Response",
            "participants": "Red team, Blue team, SOC",
            "duration": "2 days",
            "objectives": ["Test detection capabilities", "Real-time feedback", "Improve playbooks"]
          }
        ]
      },
      {
        "phase": 3,
        "timing": "Months 7-9",
        "exercises": [
          {
            "type": "Red Team",
            "name": "RED-1: Assumed Breach",
            "participants": "External red team vs all defenses",
            "duration": "2 weeks",
            "objectives": ["Realistic attack simulation", "Test full defensive chain"]
          },
          {
            "type": "Cyber Range",
            "name": "RANGE-1: Medical Device Compromise",
            "participants": "Biomedical engineering, Security",
            "duration": "1 day",
            "objectives": ["Hands-on medical device IR", "Safe environment for learning"]
          }
        ]
      },
      {
        "phase": 4,
        "timing": "Months 10-12",
        "exercises": [
          {
            "type": "Full-Scale",
            "name": "FS-1: Hospital Under Attack",
            "participants": "All stakeholders, external partners",
            "duration": "3 days",
            "objectives": ["Full activation", "Test all systems", "Validate recovery"]
          }
        ]
      }
    ]
  },
  "exercise_types_explained": {
    "tabletop": "Discussion-based, no actual systems, focus on decisions",
    "functional": "Simulate operations, partial activation",
    "full_scale": "Complete activation, maximum realism",
    "red_team": "Adversary simulation without defender knowledge",
    "purple_team": "Collaborative with real-time learning",
    "cyber_range": "Isolated environment for hands-on practice"
  },
  "success_metrics": {
    "baseline_measures": ["Current MTTD", "MTTR", "Decision times"],
    "improvement_targets": ["30% reduction in response times", "Zero critical gaps in exercises"]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 10 : exercise_execution_manager

**Concepts couverts** (6 concepts - 3.35.5 g-l) :
- Exercise Design, Scenario Development, Exercise Evaluation
- After Action Report, Exercise Programs, Multi-Organization Exercises

**Sujet** : Gestionnaire d'exécution d'exercices avec évaluation et AAR.

**Entrée JSON** :
```json
{
  "exercise": {
    "name": "CYBER_STORM_2024",
    "type": "National multi-sector exercise",
    "sectors": ["Financial", "Energy", "Healthcare", "Communications"],
    "duration_days": 3,
    "participants": 500
  },
  "scenario": {
    "threat": "Coordinated nation-state attack on critical infrastructure",
    "initial_condition": "Multiple sector compromises discovered simultaneously",
    "escalation": "Destructive payloads activated day 2"
  }
}
```

**Sortie attendue** :
```json
{
  "exercise_design": {
    "objectives": [
      "Test cross-sector coordination",
      "Validate government-private sector communication",
      "Exercise national crisis response procedures",
      "Identify systemic vulnerabilities"
    ],
    "scope": {
      "in_scope": ["Information sharing", "Coordinated response", "Public communication"],
      "out_of_scope": ["Actual system changes", "Real data", "Production systems"]
    },
    "rules_of_engagement": {
      "exercise_network": "Isolated simulation environment",
      "real_world_interface": "None - clear exercise/real world separation"
    }
  },
  "scenario_development": {
    "master_scenario_events_list": [
      {"time": "Day 1, 09:00", "inject": "Financial sector reports unusual activity", "expected_response": "ISAC notification"},
      {"time": "Day 1, 11:00", "inject": "Energy sector confirms similar indicators", "expected_response": "Cross-sector call"},
      {"time": "Day 1, 15:00", "inject": "Attribution to Nation_X released", "expected_response": "Government coordination"},
      {"time": "Day 2, 08:00", "inject": "Destructive payloads activate - systems wiped", "expected_response": "Crisis escalation"},
      {"time": "Day 2, 14:00", "inject": "Media reports widespread outages", "expected_response": "Public communication"},
      {"time": "Day 3, 09:00", "inject": "Recovery operations begin", "expected_response": "Coordinated restoration"}
    ],
    "realism_factors": ["Based on actual TTPs", "Realistic escalation timeline", "True-to-life constraints"]
  },
  "evaluation_criteria": {
    "categories": [
      {"area": "Detection", "criteria": ["Time to detect", "Accuracy of initial assessment"]},
      {"area": "Communication", "criteria": ["Speed of notification", "Clarity of messaging"]},
      {"area": "Coordination", "criteria": ["Cross-sector collaboration", "Government interface"]},
      {"area": "Decision Making", "criteria": ["Timeliness", "Appropriateness", "Documentation"]}
    ],
    "evaluation_team": "External observers + CISA representatives"
  },
  "after_action_report_structure": {
    "sections": [
      {"section": "Executive Summary", "content": "Key findings and recommendations"},
      {"section": "Exercise Overview", "content": "Objectives, participants, scenario"},
      {"section": "Findings by Objective", "content": "Detailed analysis per objective"},
      {"section": "Strengths Observed", "content": "What worked well"},
      {"section": "Areas for Improvement", "content": "Gaps and weaknesses"},
      {"section": "Recommendations", "content": "Prioritized action items"},
      {"section": "Improvement Plan", "content": "Timeline and ownership"}
    ],
    "distribution": "Participants, sector ISACs, government sponsors"
  },
  "multi_organization_coordination": {
    "coordination_challenges": [
      "Different classification levels",
      "Competing priorities",
      "Legal and liability concerns"
    ],
    "success_factors": [
      "Clear rules of engagement",
      "Pre-established communication channels",
      "Mutual benefit articulation"
    ]
  }
}
```

**Barème** : 98/100

---

## EXERCICE 11 : cyber_resilience_assessor

**Concepts couverts** (6 concepts - 3.35.6 a-f) :
- Cyber Resilience Definition, Resilience vs Security
- Business Continuity Planning, Disaster Recovery, Recovery Prioritization, Backup Strategy

**Sujet** : Évaluateur de résilience cyber avec analyse BCP/DR.

**Entrée JSON** :
```json
{
  "organization": {
    "type": "E-commerce platform",
    "revenue_hourly_usd": 50000,
    "critical_systems": ["Website", "Payment processing", "Inventory", "Fulfillment"]
  },
  "current_state": {
    "backup_strategy": "Daily backup to same datacenter",
    "rto_stated": "4 hours",
    "rpo_stated": "24 hours",
    "dr_site": "None - cloud-native",
    "last_dr_test": "Never"
  }
}
```

**Sortie attendue** :
```json
{
  "resilience_assessment": {
    "definition_applied": "Ability to anticipate, withstand, recover, and adapt to adverse cyber events",
    "current_maturity": "LOW",
    "security_vs_resilience_gap": {
      "security_posture": "Unknown - not assessed",
      "resilience_posture": "Weak - no tested recovery capability",
      "key_insight": "Resilience assumes failure - current state unprepared for failure"
    }
  },
  "business_continuity_analysis": {
    "critical_functions": [
      {"function": "Website availability", "bia_rating": "Critical", "max_downtime": "1 hour"},
      {"function": "Payment processing", "bia_rating": "Critical", "max_downtime": "1 hour"},
      {"function": "Inventory management", "bia_rating": "High", "max_downtime": "4 hours"},
      {"function": "Order fulfillment", "bia_rating": "High", "max_downtime": "8 hours"}
    ],
    "current_gap": "Stated RTO (4h) exceeds critical function tolerance (1h)"
  },
  "disaster_recovery_assessment": {
    "current_state": {
      "backup_location": "CRITICAL RISK - Same datacenter",
      "dr_site": "None - relies on cloud availability",
      "tested": "NEVER - Unknown actual capability"
    },
    "rto_analysis": {
      "stated": "4 hours",
      "realistic_estimate": "Unknown - never tested",
      "recommendation": "Test immediately, assume 24+ hours until proven"
    },
    "rpo_analysis": {
      "stated": "24 hours",
      "business_tolerance": "Likely unacceptable - 1 day of orders lost",
      "recommendation": "Reduce to 1-hour RPO minimum"
    }
  },
  "backup_strategy_critique": {
    "current_3_2_1_compliance": {
      "3_copies": "UNKNOWN",
      "2_different_media": "NO",
      "1_offsite": "NO - Same datacenter"
    },
    "ransomware_resilience": "CRITICAL RISK - No immutable/offline backups",
    "recommendations": [
      "Implement 3-2-1 backup strategy",
      "Add immutable backup copy",
      "Geographic separation required"
    ]
  },
  "recovery_prioritization": {
    "priority_1": ["Website", "Payment processing"],
    "priority_2": ["Inventory management"],
    "priority_3": ["Order fulfillment", "Reporting"],
    "dependency_mapping": "Payment requires Website; Fulfillment requires Inventory"
  },
  "immediate_actions": [
    {"action": "Add offsite backup replication", "timeline": "This week", "impact": "High"},
    {"action": "Test recovery procedure", "timeline": "Within 2 weeks", "impact": "Critical"},
    {"action": "Document and test BCP", "timeline": "Within 30 days", "impact": "High"}
  ]
}
```

**Barème** : 97/100

---

## EXERCICE 12 : resilience_operations_planner

**Concepts couverts** (6 concepts - 3.35.6 g-l) :
- Alternate Operations, Reconstitution, Testing Recovery
- Supply Chain Resilience, Workforce Resilience, Adaptive Capacity

**Sujet** : Planificateur des opérations de résilience avec capacité adaptative.

**Entrée JSON** :
```json
{
  "scenario": {
    "type": "ransomware_total_encryption",
    "systems_affected": "All production systems",
    "backup_status": "Available but 48 hours old"
  },
  "organization": {
    "type": "Manufacturing",
    "critical_operations": ["Production line control", "Supply chain management", "Order processing"],
    "workforce": 2000
  },
  "constraints": {
    "max_tolerable_downtime_days": 5,
    "customer_commitments": "Major orders due in 7 days"
  }
}
```

**Sortie attendue** :
```json
{
  "alternate_operations_plan": {
    "production_line": {
      "normal_mode": "Automated control systems",
      "degraded_mode": "Manual operation with paper procedures",
      "capability": "40% of normal capacity",
      "duration_sustainable": "Up to 7 days"
    },
    "supply_chain": {
      "normal_mode": "Automated ordering and tracking",
      "degraded_mode": "Phone/email with key suppliers",
      "capability": "Critical supplies only",
      "pre_positioned": "Contact list, manual procedures"
    },
    "order_processing": {
      "normal_mode": "ERP system",
      "degraded_mode": "Spreadsheet-based tracking",
      "capability": "New orders only, existing order status unknown",
      "customer_communication": "Proactive delay notification"
    }
  },
  "reconstitution_plan": {
    "strategy": "Clean rebuild, not restore infected systems",
    "phases": [
      {"phase": 1, "duration": "Day 1-2", "action": "Build clean infrastructure", "systems": ["Network", "AD", "Core servers"]},
      {"phase": 2, "duration": "Day 2-3", "action": "Restore critical applications", "systems": ["Production control", "ERP core"]},
      {"phase": 3, "duration": "Day 3-4", "action": "Restore from backup", "systems": ["Data restoration with 48h gap"]},
      {"phase": 4, "duration": "Day 4-5", "action": "Validate and reconnect", "systems": ["Testing", "User access"]}
    ],
    "data_gap_mitigation": "Manual reconciliation of 48-hour transaction gap"
  },
  "recovery_testing_requirements": {
    "frequency": "Quarterly for critical systems",
    "scope": "Full restoration test to isolated environment",
    "metrics_tracked": ["Actual RTO", "Data integrity", "Application functionality"]
  },
  "supply_chain_resilience": {
    "critical_dependencies": ["Raw materials supplier A", "Logistics partner B"],
    "alternate_suppliers": "Pre-qualified list maintained",
    "communication_plan": "Immediate notification with ETA updates",
    "stockpile_status": "7 days of critical materials on-site"
  },
  "workforce_resilience": {
    "cross_training": "All critical roles have backup personnel",
    "remote_work_capability": "70% of workforce can work remotely",
    "succession": "Key person dependencies identified and mitigated",
    "crisis_support": "EAP activated for stress support"
  },
  "adaptive_capacity": {
    "lessons_learned_integration": {
      "from_this_incident": ["Backup frequency inadequate", "Manual procedures outdated"],
      "improvement_actions": ["Increase backup frequency to 4-hour", "Update and test manual procedures quarterly"]
    },
    "defense_evolution": [
      "Implement immutable backups",
      "Add network segmentation",
      "Deploy EDR with ransomware protection"
    ]
  }
}
```

**Barème** : 97/100

---

## EXERCICE 13 : crisis_simulation_engine

**Concepts couverts** (Synthèse - Full crisis simulation) :
- All crisis management concepts integrated

**Sujet** : Moteur de simulation de crise complète avec tous les aspects.

**Entrée JSON** :
```json
{
  "simulation_request": {
    "scenario": "Supply chain compromise leading to mass customer breach",
    "organization_type": "SaaS provider",
    "customers_affected": 5000,
    "data_exposed": "Customer authentication credentials"
  },
  "simulation_phase": "Full lifecycle"
}
```

**Sortie attendue** :
```json
{
  "crisis_simulation": {
    "phase_1_detection": {
      "hour": 0,
      "trigger": "Customer reports unusual activity",
      "initial_assessment": "Potential compromise",
      "escalation_decision": "Activate IR team"
    },
    "phase_2_confirmation": {
      "hour": 2,
      "finding": "Supply chain library compromised",
      "scope_assessment": "All customers potentially affected",
      "crisis_declaration": "Executive crisis team activated"
    },
    "phase_3_containment": {
      "hour": 4,
      "actions": ["Disable compromised library", "Force credential rotation", "Isolate affected systems"],
      "communication": "Internal notification to all hands"
    },
    "phase_4_customer_notification": {
      "hour": 8,
      "decision_point": "When and how to notify",
      "approach": "Immediate transparent disclosure",
      "content": "What happened, what we're doing, what customers should do"
    },
    "phase_5_regulatory_notification": {
      "hour": 24,
      "jurisdictions_notified": ["GDPR authorities", "State AGs"],
      "documentation": "Breach notification package submitted"
    },
    "phase_6_recovery": {
      "day": 2-5,
      "actions": ["Full audit of supply chain", "Credential reset completion", "Enhanced monitoring"],
      "customer_support": "Dedicated support line activated"
    },
    "phase_7_post_crisis": {
      "week": 2,
      "actions": ["After action review", "Root cause analysis complete", "Improvement plan developed"],
      "communication": "Final customer communication with remediation summary"
    }
  },
  "decision_points_evaluated": [
    {"decision": "When to declare crisis", "quality": "Good - timely escalation"},
    {"decision": "Customer notification timing", "quality": "Good - transparent approach"},
    {"decision": "Response proportionality", "quality": "Appropriate - comprehensive but not excessive"}
  ],
  "lessons_learned": [
    "Supply chain security gaps existed",
    "Crisis team performed well",
    "Customer communication template needed improvement",
    "Regulatory notification process was smooth"
  ],
  "improvements_identified": [
    "Implement software bill of materials",
    "Add supply chain security requirements",
    "Update crisis communication templates"
  ]
}
```

**Barème** : 98/100

---

## EXERCICE 14 : crisis_management_maturity_assessor

**Concepts couverts** (Synthèse globale - Maturity assessment) :
- All 82 concepts integrated, Maturity model application

**Sujet** : Évaluateur de maturité de gestion de crise avec roadmap d'amélioration.

**Entrée JSON** :
```json
{
  "organization": {
    "name": "GlobalFinance Corp",
    "type": "Financial services",
    "size": "10000 employees",
    "regulatory_environment": "Highly regulated"
  },
  "assessment_request": "Full crisis management maturity assessment"
}
```

**Sortie attendue** :
```json
{
  "maturity_assessment": {
    "overall_maturity": "DEVELOPING (Level 2 of 5)",
    "dimension_scores": {
      "governance": {"score": 2.5, "level": "Developing", "notes": "Crisis team exists but roles unclear"},
      "planning": {"score": 2.0, "level": "Initial", "notes": "Basic playbooks, not comprehensive"},
      "decision_making": {"score": 2.5, "level": "Developing", "notes": "Ad-hoc processes"},
      "communication": {"score": 3.0, "level": "Defined", "notes": "Templates exist, tested occasionally"},
      "exercises": {"score": 1.5, "level": "Initial", "notes": "Annual tabletop only"},
      "resilience": {"score": 2.0, "level": "Initial", "notes": "Basic BCP, DR untested"},
      "integration": {"score": 2.0, "level": "Initial", "notes": "Siloed functions"}
    }
  },
  "detailed_findings": {
    "strengths": [
      "Executive awareness of cyber risk",
      "Basic crisis communication templates exist",
      "Some regulatory compliance"
    ],
    "weaknesses": [
      "Crisis decision rights unclear",
      "No exercising beyond annual tabletop",
      "DR never tested",
      "No integration with business continuity",
      "ICS framework not implemented"
    ],
    "gaps_critical": [
      "No crisis playbooks for key scenarios",
      "Recovery capabilities unproven",
      "Cross-functional coordination weak"
    ]
  },
  "improvement_roadmap": {
    "phase_1_foundation": {
      "duration": "Months 1-3",
      "objectives": ["Clarify governance", "Document crisis procedures"],
      "actions": [
        "Define crisis team structure and decision rights",
        "Develop playbooks for top 5 scenarios",
        "Establish battle rhythm"
      ]
    },
    "phase_2_capability": {
      "duration": "Months 4-6",
      "objectives": ["Build exercise program", "Test recovery"],
      "actions": [
        "Conduct tabletop for each major scenario",
        "Test DR capabilities",
        "Train crisis team"
      ]
    },
    "phase_3_integration": {
      "duration": "Months 7-9",
      "objectives": ["Integrate functions", "Implement ICS"],
      "actions": [
        "Align security, BC, and DR",
        "Implement ICS structure",
        "Conduct functional exercise"
      ]
    },
    "phase_4_optimization": {
      "duration": "Months 10-12",
      "objectives": ["Continuous improvement", "Advanced exercises"],
      "actions": [
        "Red team exercise",
        "Full-scale exercise",
        "Lessons learned integration"
      ]
    }
  },
  "target_state": {
    "target_maturity": "Level 4 - Managed",
    "timeline": "18 months",
    "key_indicators": [
      "All scenarios playbooked and exercised",
      "DR tested quarterly with proven RTO",
      "Crisis team trained and confident",
      "Continuous improvement culture"
    ]
  },
  "investment_required": {
    "personnel": "Dedicated crisis manager role",
    "technology": "Crisis management platform",
    "training": "Annual training program",
    "exercises": "Quarterly exercises minimum"
  }
}
```

**Barème** : 98/100

---

## RÉCAPITULATIF MODULE 3.35

**Module** : Cyber Crisis Management
**Concepts couverts** : 82/82 (100%)
**Exercices** : 14
**Note moyenne** : 97.4/100

### Répartition des concepts :

| Sous-module | Concepts | Exercices |
|-------------|----------|-----------|
| 3.35.1 Crisis Fundamentals | 14 | Ex01-02 |
| 3.35.2 Decision Making | 16 | Ex03-04 |
| 3.35.3 Incident Command System | 14 | Ex05-06 |
| 3.35.4 Strategic Response | 14 | Ex07-08 |
| 3.35.5 Exercises & Training | 12 | Ex09-10 |
| 3.35.6 Cyber Resilience | 12 | Ex11-12 |
| Synthèse transversale | - | Ex13-14 |

### Thèmes couverts :
- Crisis vs incident distinction
- Crisis team structure and governance
- Cognitive biases and stress management
- OODA loop and decision frameworks
- Incident Command System (ICS)
- Incident Action Plans and SITREPs
- Strategic response options
- Coalition and coordinated response
- Exercise types (TTX, functional, full-scale)
- Business continuity and disaster recovery
- Cyber resilience and adaptive capacity
- Crisis maturity assessment

