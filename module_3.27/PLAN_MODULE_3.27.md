# PLAN MODULE 3.27 : Security Architecture

**Concepts totaux** : 88
**Exercices prévus** : 12
**Note moyenne cible** : >= 96/100

---

## TABLE DE COUVERTURE CONCEPTS → EXERCICES

| Sous-module | Concepts | Exercices couvrant |
|-------------|----------|-------------------|
| 3.27.1 Security Architecture Fundamentals | a-p (16) | Ex01, Ex02 |
| 3.27.2 Zero Trust Deep Dive | a-n (14) | Ex03, Ex04 |
| 3.27.3 Network Security Architecture | a-p (16) | Ex05, Ex06 |
| 3.27.4 Identity & Access Architecture | a-p (16) | Ex07, Ex08 |
| 3.27.5 Data Security Architecture | a-n (14) | Ex09, Ex10 |
| 3.27.6 Application Security Architecture | a-l (12) | Ex11, Ex12 |

---

## MATRICE DÉTAILLÉE

| Ex | Concepts couverts | Thème |
|----|-------------------|-------|
| 01 | 3.27.1: a,b,c,d,e,f,g,h | Frameworks, Zero Trust, Defense in Depth |
| 02 | 3.27.1: i,j,k,l,m,n,o,p | Trust boundaries, fail secure, compliance |
| 03 | 3.27.2: a,b,c,d,e,f,g | Zero Trust principles, BeyondCorp, ZTNA |
| 04 | 3.27.2: h,i,j,k,l,m,n | Device trust, maturity, implementation |
| 05 | 3.27.3: a,b,c,d,e,f,g,h | Network segmentation, firewalls, SASE |
| 06 | 3.27.3: i,j,k,l,m,n,o,p | DDoS, DNS, email, OT network |
| 07 | 3.27.4: a,b,c,d,e,f,g,h | IAM, authentication, PAM |
| 08 | 3.27.4: i,j,k,l,m,n,o,p | API security, CIAM, passwordless |
| 09 | 3.27.5: a,b,c,d,e,f,g | Data classification, encryption, DLP |
| 10 | 3.27.5: h,i,j,k,l,m,n | Backup, masking, secure sharing |
| 11 | 3.27.6: a,b,c,d,e,f | Secure SDLC, threat modeling, APIs |
| 12 | 3.27.6: g,h,i,j,k,l | Serverless, mobile, runtime protection |

---

## EXERCICE 01 : Security Architecture Frameworks & Principles

**Concepts couverts** : 3.27.1.a (SABSA), 3.27.1.b (TOGAF Security), 3.27.1.c (NIST CSF), 3.27.1.d (Zero Trust Architecture), 3.27.1.e (Defense in Depth), 3.27.1.f (Least Privilege), 3.27.1.g (Secure by Design), 3.27.1.h (Security Domains)

**Contexte** : Un architecte sécurité doit concevoir l'architecture de sécurité d'une organisation multinationale en utilisant les frameworks reconnus.

**Entrée JSON** :
```json
{
  "organization": {
    "name": "GlobalBank Corp",
    "industry": "financial_services",
    "employees": 25000,
    "locations": ["us", "eu", "apac"],
    "business_units": ["retail_banking", "corporate_banking", "wealth_management", "trading"]
  },
  "current_state": {
    "security_maturity": "ad_hoc",
    "existing_frameworks": [],
    "pain_points": [
      "siloed_security_decisions",
      "inconsistent_controls",
      "no_business_alignment",
      "reactive_approach"
    ]
  },
  "requirements": {
    "regulatory": ["PCI-DSS", "SOX", "GDPR", "DORA"],
    "business_goals": ["digital_transformation", "cloud_first", "api_economy"]
  }
}
```

**Sortie attendue** :
```json
{
  "framework_selection": {
    "primary": "sabsa",
    "complementary": ["nist_csf", "togaf_security"],
    "rationale": "sabsa_for_business_alignment_nist_for_controls_togaf_for_integration"
  },
  "sabsa_implementation": {
    "definition": {
      "what": "Sherwood Applied Business Security Architecture",
      "approach": "business_driven_risk_based",
      "layers": ["contextual", "conceptual", "logical", "physical", "component", "operational"]
    },
    "contextual_layer_business_view": {
      "business_attributes": [
        {"attribute": "customer_trust", "metric": "brand_reputation_score", "risk_tolerance": "zero"},
        {"attribute": "regulatory_compliance", "metric": "audit_findings", "risk_tolerance": "low"},
        {"attribute": "operational_resilience", "metric": "availability_sla", "risk_tolerance": "99.99%"},
        {"attribute": "transaction_integrity", "metric": "fraud_loss_ratio", "risk_tolerance": "<0.01%"}
      ],
      "stakeholder_mapping": {
        "board": "risk_appetite_governance",
        "ciso": "security_strategy_execution",
        "business_units": "enable_secure_operations",
        "customers": "protect_assets_privacy"
      }
    },
    "conceptual_layer_architect_view": {
      "security_domains": {
        "identity_domain": "who_can_do_what",
        "network_domain": "secure_connectivity",
        "data_domain": "information_protection",
        "application_domain": "secure_services",
        "endpoint_domain": "device_security",
        "cloud_domain": "cloud_security_posture",
        "physical_domain": "facility_security"
      },
      "control_objectives": [
        "authentication_strong_mfa_everywhere",
        "authorization_least_privilege_rbac",
        "encryption_data_at_rest_in_transit",
        "monitoring_continuous_visibility"
      ]
    },
    "logical_layer_designer_view": {
      "services": {
        "identity_services": ["sso", "mfa", "pam", "directory"],
        "network_services": ["segmentation", "firewall", "vpn", "ddos"],
        "data_services": ["encryption", "dlp", "backup", "classification"],
        "security_operations": ["siem", "soar", "threat_intel", "vuln_mgmt"]
      }
    },
    "physical_layer": "technology_product_selection",
    "component_layer": "standards_configurations",
    "operational_layer": "procedures_metrics"
  },
  "togaf_security_integration": {
    "definition": {
      "what": "The Open Group Architecture Framework - Security Extension",
      "integration": "security_views_in_enterprise_architecture"
    },
    "adm_security_integration": {
      "preliminary": "establish_security_architecture_capability",
      "phase_a_vision": "security_requirements_principles",
      "phase_b_business": "security_business_processes",
      "phase_c_information": "data_classification_protection",
      "phase_d_technology": "security_technology_architecture",
      "phase_e_opportunities": "security_solutions_building_blocks",
      "phase_f_migration": "security_implementation_roadmap",
      "phase_g_governance": "security_change_management"
    },
    "security_reference_model": {
      "building_blocks": ["identity_management", "access_control", "cryptography", "audit_logging"]
    }
  },
  "nist_csf_mapping": {
    "functions": {
      "identify": {
        "categories": ["asset_management", "business_environment", "governance", "risk_assessment", "risk_strategy"],
        "globalbank_implementation": {
          "id_am": "cmdb_integration_full_asset_inventory",
          "id_be": "business_impact_analysis_per_unit",
          "id_gv": "security_steering_committee",
          "id_ra": "annual_risk_assessment_continuous_monitoring",
          "id_rm": "risk_appetite_framework"
        }
      },
      "protect": {
        "categories": ["access_control", "awareness_training", "data_security", "information_protection", "maintenance", "protective_technology"],
        "globalbank_implementation": {
          "pr_ac": "zero_trust_mfa_pam",
          "pr_at": "security_awareness_phishing_simulations",
          "pr_ds": "encryption_dlp_classification",
          "pr_pt": "ngfw_edr_casb"
        }
      },
      "detect": {
        "categories": ["anomalies_events", "security_monitoring", "detection_processes"],
        "globalbank_implementation": {
          "de_ae": "siem_correlation_ueba",
          "de_cm": "24x7_soc_threat_hunting",
          "de_dp": "detection_engineering_program"
        }
      },
      "respond": {
        "categories": ["response_planning", "communications", "analysis", "mitigation", "improvements"],
        "globalbank_implementation": {
          "rs_rp": "incident_response_playbooks",
          "rs_co": "crisis_communication_plan",
          "rs_mi": "containment_eradication_procedures"
        }
      },
      "recover": {
        "categories": ["recovery_planning", "improvements", "communications"],
        "globalbank_implementation": {
          "rc_rp": "bcdr_tested_annually",
          "rc_im": "post_incident_reviews"
        }
      }
    },
    "tiers": {
      "current": "tier_2_risk_informed",
      "target": "tier_4_adaptive"
    },
    "profile": {
      "type": "custom_financial_services",
      "baseline": "nist_csf_financial_sector_profile"
    }
  },
  "zero_trust_architecture": {
    "nist_sp_800_207_principles": [
      "all_data_sources_services_are_resources",
      "all_communication_secured_regardless_location",
      "access_granted_per_session_basis",
      "access_determined_by_dynamic_policy",
      "integrity_security_posture_monitored",
      "authentication_authorization_strictly_enforced",
      "collect_information_improve_security_posture"
    ],
    "implementation_approach": {
      "identity_pillar": "strong_authentication_continuous_verification",
      "device_pillar": "device_trust_compliance",
      "network_pillar": "micro_segmentation_software_defined",
      "application_pillar": "secure_by_design_api_gateway",
      "data_pillar": "classification_encryption_dlp"
    },
    "globalbank_roadmap": {
      "phase_1": "identity_centric_mfa_sso_pam",
      "phase_2": "device_trust_endpoint_compliance",
      "phase_3": "micro_segmentation_ztna",
      "phase_4": "continuous_verification_adaptive"
    }
  },
  "defense_in_depth": {
    "definition": "multiple_overlapping_layers_no_single_point_of_failure",
    "layers": {
      "perimeter": ["firewall", "waf", "ddos_protection", "email_gateway"],
      "network": ["segmentation", "ids_ips", "network_access_control"],
      "endpoint": ["edr", "av", "host_firewall", "application_whitelisting"],
      "application": ["secure_coding", "api_security", "runtime_protection"],
      "data": ["encryption", "dlp", "access_controls", "backup"],
      "identity": ["mfa", "pam", "sso", "rbac"],
      "physical": ["access_controls", "cctv", "environmental"]
    },
    "compensating_controls": {
      "principle": "if_one_layer_fails_others_protect",
      "example": "if_firewall_bypassed_ids_detects_edr_blocks"
    }
  },
  "least_privilege": {
    "definition": "minimum_necessary_access_for_job_function",
    "implementation": {
      "rbac": "role_based_access_control_job_functions",
      "jit_access": "just_in_time_temporary_elevated",
      "jea": "just_enough_administration_scoped_admin",
      "regular_review": "quarterly_access_certification",
      "separation_of_duties": "no_single_person_completes_critical_transaction"
    },
    "globalbank_application": {
      "trading_floor": "trader_cannot_approve_own_trades",
      "it_admin": "no_permanent_domain_admin_jit_only",
      "developer": "no_production_access_ci_cd_only"
    }
  },
  "secure_by_design": {
    "principles": [
      "security_from_inception_not_afterthought",
      "threat_modeling_during_design",
      "secure_defaults_not_optional",
      "fail_secure_not_fail_open",
      "minimize_attack_surface"
    ],
    "architectural_decisions": {
      "data_encryption": "default_aes_256_no_option_disable",
      "authentication": "mfa_required_no_password_only_option",
      "logging": "comprehensive_audit_trail_by_design",
      "input_validation": "allowlist_approach_reject_invalid"
    }
  },
  "security_domains": {
    "identity_domain": {
      "scope": "authentication_authorization_identity_lifecycle",
      "owner": "identity_team",
      "technologies": ["azure_ad", "okta", "cyberark"]
    },
    "network_domain": {
      "scope": "connectivity_segmentation_traffic_control",
      "owner": "network_security_team",
      "technologies": ["palo_alto", "cisco", "zscaler"]
    },
    "data_domain": {
      "scope": "classification_encryption_dlp_governance",
      "owner": "data_security_team",
      "technologies": ["microsoft_purview", "varonis", "thales"]
    },
    "application_domain": {
      "scope": "secure_development_api_security_devsecops",
      "owner": "appsec_team",
      "technologies": ["snyk", "checkmarx", "salt_security"]
    },
    "endpoint_domain": {
      "scope": "device_security_protection_detection",
      "owner": "endpoint_security_team",
      "technologies": ["crowdstrike", "microsoft_defender", "tanium"]
    },
    "cloud_domain": {
      "scope": "cloud_security_posture_workload_protection",
      "owner": "cloud_security_team",
      "technologies": ["wiz", "prisma_cloud", "aws_security_hub"]
    },
    "physical_domain": {
      "scope": "facility_access_environmental_security",
      "owner": "physical_security_team",
      "technologies": ["access_control_systems", "cctv", "mantraps"]
    }
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (8 concepts architecture fondamentaux)
- Intelligence pédagogique : 25/25 (frameworks intégrés)
- Originalité : 19/20 (cas financier réaliste)
- Testabilité : 14/15 (structures vérifiables)
- Clarté : 15/15 (organisation claire)

---

## EXERCICE 02 : Architecture Principles - Trust, Resilience & Compliance

**Concepts couverts** : 3.27.1.i (Trust Boundaries), 3.27.1.j (Attack Surface Reduction), 3.27.1.k (Fail Secure), 3.27.1.l (Separation of Duties), 3.27.1.m (Privacy by Design), 3.27.1.n (Resilience), 3.27.1.o (Compliance Architecture), 3.27.1.p (Risk-Based Architecture)

**Entrée JSON** :
```json
{
  "organization": "GlobalBank Corp",
  "architecture_context": {
    "systems": {
      "core_banking": {"trust_level": "highest", "data": "customer_accounts"},
      "trading_platform": {"trust_level": "high", "data": "market_positions"},
      "public_website": {"trust_level": "untrusted", "data": "marketing"}
    },
    "integrations": {
      "swift_network": "external_trusted",
      "open_banking_apis": "external_regulated",
      "third_party_vendors": "external_untrusted"
    }
  },
  "compliance_requirements": ["PCI-DSS", "SOX", "GDPR", "DORA"]
}
```

**Sortie attendue** :
```json
{
  "trust_boundaries": {
    "definition": "where_trust_level_changes_validation_required",
    "identified_boundaries": {
      "external_to_dmz": {
        "from": "internet_untrusted",
        "to": "dmz_semi_trusted",
        "controls": ["waf", "ddos", "rate_limiting", "input_validation"]
      },
      "dmz_to_internal": {
        "from": "dmz_semi_trusted",
        "to": "internal_network_trusted",
        "controls": ["authentication", "authorization", "api_gateway", "logging"]
      },
      "internal_to_core_banking": {
        "from": "internal_trusted",
        "to": "core_banking_highest_trust",
        "controls": ["mfa", "pam", "session_recording", "data_masking"]
      },
      "internal_to_external_partner": {
        "from": "internal_trusted",
        "to": "swift_external_trusted",
        "controls": ["mutual_auth", "encryption", "message_signing", "audit"]
      }
    },
    "validation_at_boundaries": {
      "principle": "never_trust_data_crossing_boundaries",
      "actions": ["validate_input", "sanitize_output", "verify_identity", "check_authorization"]
    }
  },
  "attack_surface_reduction": {
    "definition": "minimize_entry_points_exposure_complexity",
    "strategies": {
      "minimize_services": {
        "action": "disable_unnecessary_services_ports",
        "example": "only_443_from_internet_to_web_tier"
      },
      "hide_implementation": {
        "action": "no_version_disclosure_generic_errors",
        "example": "nginx_server_tokens_off"
      },
      "reduce_complexity": {
        "action": "simplify_architecture_fewer_components",
        "example": "consolidate_10_gateways_to_2"
      },
      "segment_exposure": {
        "action": "different_attack_surfaces_per_tier",
        "example": "database_no_direct_internet_path"
      },
      "default_deny": {
        "action": "whitelist_approach_explicit_allow",
        "example": "firewall_deny_all_allow_specific"
      }
    },
    "measurement": {
      "metric": "attack_surface_score",
      "factors": ["open_ports", "exposed_services", "api_endpoints", "user_interfaces"],
      "target": "reduce_30_percent_annually"
    }
  },
  "fail_secure": {
    "definition": "system_fails_to_secure_state_not_open",
    "implementation": {
      "authentication_failure": {
        "fail_secure": "deny_access_on_auth_service_unavailable",
        "fail_open_bad": "allow_access_if_auth_down"
      },
      "firewall_failure": {
        "fail_secure": "drop_all_traffic_on_failure",
        "fail_open_bad": "allow_all_traffic_on_failure"
      },
      "authorization_failure": {
        "fail_secure": "deny_permission_on_policy_engine_error",
        "fail_open_bad": "grant_permission_on_error"
      },
      "encryption_failure": {
        "fail_secure": "reject_transmission_if_encryption_fails",
        "fail_open_bad": "send_unencrypted_if_encryption_fails"
      }
    },
    "graceful_degradation": {
      "principle": "maintain_security_while_reducing_functionality",
      "example": "trading_read_only_mode_during_incident"
    }
  },
  "separation_of_duties": {
    "definition": "no_single_person_can_complete_critical_transaction",
    "implementation": {
      "trading_operations": {
        "roles": ["trader", "trade_approver", "settlement"],
        "rule": "trader_cannot_approve_own_trade",
        "control": "workflow_enforced_different_user_ids"
      },
      "it_operations": {
        "roles": ["developer", "reviewer", "deployer"],
        "rule": "no_self_review_no_self_deploy",
        "control": "ci_cd_pipeline_mandatory_approval"
      },
      "financial_controls": {
        "roles": ["requestor", "approver", "executor"],
        "rule": "payment_over_threshold_dual_approval",
        "control": "four_eyes_principle_system_enforced"
      },
      "security_operations": {
        "roles": ["alert_triage", "incident_handler", "incident_approver"],
        "rule": "privileged_action_requires_approval",
        "control": "pam_workflow_with_audit"
      }
    },
    "collusion_resistance": {
      "principle": "make_collusion_difficult_detectable",
      "controls": ["random_assignment", "rotation", "anomaly_detection"]
    }
  },
  "privacy_by_design": {
    "principles_cavoukian": {
      "proactive": "anticipate_prevent_privacy_issues",
      "default_privacy": "maximum_privacy_without_action",
      "embedded": "privacy_integral_not_addon",
      "positive_sum": "privacy_and_functionality_not_tradeoff",
      "end_to_end": "full_lifecycle_protection",
      "visibility_transparency": "verifiable_by_stakeholders",
      "user_centric": "user_control_over_data"
    },
    "architectural_implementation": {
      "data_minimization": {
        "principle": "collect_only_necessary",
        "example": "kyc_only_required_fields_not_extra"
      },
      "purpose_limitation": {
        "principle": "use_only_for_stated_purpose",
        "implementation": "purpose_tag_on_data_policy_enforcement"
      },
      "storage_limitation": {
        "principle": "retain_only_necessary_duration",
        "implementation": "automated_retention_policies_deletion"
      },
      "data_subject_rights": {
        "access": "api_for_customer_data_export",
        "rectification": "self_service_correction",
        "erasure": "right_to_be_forgotten_workflow"
      }
    },
    "globalbank_implementation": {
      "customer_data_vault": {
        "encryption": "field_level_encryption_pii",
        "tokenization": "card_numbers_tokenized",
        "access_logging": "all_pii_access_logged"
      }
    }
  },
  "resilience": {
    "definition": "withstand_attacks_recover_rapidly",
    "components": {
      "redundancy": {
        "application": "multi_az_multi_region",
        "data": "synchronous_replication_3_copies",
        "network": "dual_isp_diverse_paths"
      },
      "fault_tolerance": {
        "detection": "health_checks_every_10s",
        "isolation": "circuit_breakers_bulkheads",
        "recovery": "auto_failover_under_30s"
      },
      "graceful_degradation": {
        "approach": "reduce_functionality_maintain_core",
        "example": "disable_non_critical_features_under_attack"
      },
      "recovery": {
        "rpo": "15_minutes_data_loss_acceptable",
        "rto": "4_hours_to_full_recovery",
        "testing": "quarterly_dr_exercises"
      }
    },
    "chaos_engineering": {
      "purpose": "test_resilience_proactively",
      "tools": ["chaos_monkey", "gremlin"],
      "exercises": ["kill_random_instance", "network_partition", "latency_injection"]
    }
  },
  "compliance_architecture": {
    "approach": "compliance_as_code_continuous",
    "regulatory_mapping": {
      "pci_dss": {
        "requirements": ["cardholder_data_protection", "access_control", "network_security"],
        "controls_mapped": {
          "req_3": "encryption_dlp_tokenization",
          "req_7": "rbac_least_privilege",
          "req_8": "mfa_unique_ids"
        },
        "evidence_automation": "config_scanning_audit_trail"
      },
      "sox": {
        "requirements": ["it_general_controls", "access_management", "change_management"],
        "controls_mapped": {
          "access_controls": "pam_access_reviews",
          "change_management": "ci_cd_audit_trail",
          "segregation": "separation_of_duties_workflow"
        }
      },
      "gdpr": {
        "requirements": ["data_protection", "privacy_rights", "breach_notification"],
        "controls_mapped": {
          "article_25": "privacy_by_design_implementation",
          "article_32": "encryption_access_controls",
          "article_33": "72_hour_breach_notification_process"
        }
      },
      "dora": {
        "requirements": ["ict_risk_management", "incident_reporting", "resilience_testing"],
        "controls_mapped": {
          "ict_risk": "integrated_risk_framework",
          "resilience": "tlpt_testing_program",
          "third_party": "tprm_critical_suppliers"
        }
      }
    },
    "continuous_compliance": {
      "scanning": "daily_automated_compliance_checks",
      "dashboard": "real_time_compliance_posture",
      "alerting": "drift_detection_immediate_notification"
    }
  },
  "risk_based_architecture": {
    "principle": "proportional_controls_based_on_risk",
    "crown_jewels_identification": {
      "tier_1_critical": {
        "systems": ["core_banking", "swift", "trading_engine"],
        "data": ["customer_accounts", "card_numbers", "trade_positions"],
        "protection": "maximum_controls_zero_risk_tolerance"
      },
      "tier_2_important": {
        "systems": ["crm", "internal_portals", "analytics"],
        "data": ["customer_contacts", "internal_reports"],
        "protection": "high_controls_low_risk_tolerance"
      },
      "tier_3_standard": {
        "systems": ["public_website", "marketing_tools"],
        "data": ["public_information"],
        "protection": "standard_controls_normal_risk_tolerance"
      }
    },
    "control_selection": {
      "high_risk_high_value": "all_controls_maximum_investment",
      "high_risk_low_value": "standard_controls_accept_some_risk",
      "low_risk_high_value": "targeted_controls_focus_availability",
      "low_risk_low_value": "minimal_controls_cost_effective"
    },
    "cost_benefit_analysis": {
      "principle": "control_cost_should_not_exceed_risk_reduction_value",
      "example": "1m_control_for_10m_risk_reduction_justified"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 03 : Zero Trust Architecture - Principles & Core Components

**Concepts couverts** : 3.27.2.a (Zero Trust Principles), 3.27.2.b (Zero Trust Components), 3.27.2.c (Identity as Perimeter), 3.27.2.d (Micro-segmentation), 3.27.2.e (Software-Defined Perimeter), 3.27.2.f (BeyondCorp), 3.27.2.g (ZTNA)

**Entrée JSON** :
```json
{
  "organization": {
    "name": "TechCorp Industries",
    "workforce": {
      "employees": 5000,
      "remote": "60%",
      "contractors": 500,
      "partners": 200
    },
    "current_state": {
      "vpn": "traditional_full_tunnel",
      "network": "flat_internal_trusted",
      "authentication": "password_plus_optional_mfa"
    }
  },
  "transformation_goals": {
    "eliminate_vpn": true,
    "enable_byod": true,
    "assume_breach": true
  }
}
```

**Sortie attendue** :
```json
{
  "zero_trust_principles": {
    "core_tenets": {
      "never_trust": "no_implicit_trust_based_on_location",
      "always_verify": "authenticate_authorize_every_request",
      "assume_breach": "design_as_if_attacker_inside"
    },
    "nist_800_207_principles": [
      {
        "principle": "all_data_sources_and_computing_services_are_resources",
        "implication": "no_distinction_internal_external_resources"
      },
      {
        "principle": "all_communication_secured_regardless_of_location",
        "implication": "encryption_authentication_everywhere"
      },
      {
        "principle": "access_to_individual_resources_granted_per_session",
        "implication": "no_persistent_access_reevaluate_constantly"
      },
      {
        "principle": "access_determined_by_dynamic_policy",
        "implication": "context_based_adaptive_not_static_rules"
      },
      {
        "principle": "enterprise_monitors_security_posture_continuously",
        "implication": "real_time_assessment_continuous_improvement"
      },
      {
        "principle": "authentication_authorization_strictly_enforced",
        "implication": "strong_auth_granular_authz_no_exceptions"
      },
      {
        "principle": "collect_information_to_improve_security",
        "implication": "analytics_behavior_learning_feedback_loop"
      }
    ],
    "mindset_shift": {
      "from_perimeter_based": "castle_and_moat_trust_inside",
      "to_zero_trust": "verify_everyone_everything_everywhere"
    }
  },
  "zero_trust_components": {
    "policy_engine": {
      "function": "makes_access_decisions",
      "inputs": ["user_identity", "device_trust", "resource_sensitivity", "context"],
      "output": "grant_deny_require_additional_verification",
      "implementation": "centralized_policy_decision_point"
    },
    "policy_administrator": {
      "function": "executes_policy_engine_decisions",
      "actions": ["configure_access_path", "generate_session_credentials", "log_decision"],
      "implementation": "orchestrates_pep_configuration"
    },
    "policy_enforcement_point": {
      "function": "enforces_access_decisions",
      "location": "at_resource_network_application",
      "examples": ["api_gateway", "reverse_proxy", "firewall", "identity_aware_proxy"]
    },
    "data_sources": {
      "identity_provider": "user_authentication_attributes",
      "device_inventory": "device_trust_compliance",
      "threat_intelligence": "known_threats_iocs",
      "behavior_analytics": "ueba_anomaly_detection"
    },
    "techcorp_architecture": {
      "policy_engine": "azure_ad_conditional_access",
      "policy_administrator": "zscaler_ztna_platform",
      "pep_network": "zscaler_zia",
      "pep_application": "azure_ad_app_proxy"
    }
  },
  "identity_as_perimeter": {
    "concept": {
      "traditional": "network_location_determines_trust",
      "zero_trust": "identity_determines_trust"
    },
    "implementation": {
      "strong_authentication": {
        "mfa_mandatory": "all_users_all_access",
        "phishing_resistant": "fido2_webauthn_preferred",
        "continuous": "step_up_for_sensitive_actions"
      },
      "identity_verification": {
        "user_identity": "who_is_requesting_verified",
        "device_identity": "what_device_verified",
        "workload_identity": "which_service_verified"
      },
      "context_enrichment": {
        "factors": ["location", "time", "device_posture", "behavior"],
        "decision": "adaptive_based_on_context"
      }
    },
    "techcorp_implementation": {
      "primary_idp": "azure_ad",
      "mfa": "microsoft_authenticator_fido2",
      "sso": "all_apps_behind_sso",
      "conditional_access": "risk_based_policies"
    }
  },
  "micro_segmentation": {
    "definition": "granular_network_segments_down_to_workload",
    "comparison": {
      "traditional_segmentation": "large_vlans_perimeter_focused",
      "micro_segmentation": "workload_level_east_west_focus"
    },
    "implementation_approaches": {
      "network_based": {
        "technology": "software_defined_networking",
        "tools": ["nsx", "cisco_aci", "illumio"],
        "granularity": "vlan_to_workload"
      },
      "host_based": {
        "technology": "host_firewall_policies",
        "tools": ["windows_firewall_gpo", "iptables", "edr_with_firewall"],
        "granularity": "per_workload"
      },
      "identity_based": {
        "technology": "identity_aware_segmentation",
        "tools": ["zscaler_workload", "service_mesh"],
        "granularity": "per_identity_per_workload"
      }
    },
    "policy_model": {
      "default": "deny_all_allow_specific",
      "rules": {
        "web_to_app": "allow_web_tier_to_app_tier_port_8080",
        "app_to_db": "allow_app_tier_to_db_tier_port_5432",
        "deny_web_to_db": "block_direct_web_to_database"
      }
    },
    "east_west_visibility": {
      "importance": "most_attacks_involve_lateral_movement",
      "monitoring": "flow_logs_service_mesh_telemetry"
    }
  },
  "software_defined_perimeter": {
    "definition": "dynamic_perimeter_hides_infrastructure",
    "principles": {
      "hide_infrastructure": "resources_invisible_until_authorized",
      "single_packet_authorization": "spa_before_connection",
      "dynamic_access": "ephemeral_connections_per_session"
    },
    "architecture": {
      "spa_controller": "validates_user_device_grants_access",
      "accepting_host": "opens_port_only_for_authorized_user",
      "initiating_host": "client_with_sdp_agent"
    },
    "comparison_vpn": {
      "vpn": {
        "visibility": "network_resources_visible_to_vpn_users",
        "access": "often_broad_network_access",
        "lateral_movement": "possible_once_connected"
      },
      "sdp": {
        "visibility": "only_authorized_resources_visible",
        "access": "per_application_granular",
        "lateral_movement": "prevented_no_network_access"
      }
    }
  },
  "beyondcorp": {
    "google_model": {
      "origin": "google_internal_zero_trust_implementation",
      "key_innovations": [
        "no_privileged_internal_network",
        "access_based_on_device_and_user_not_location",
        "all_access_authenticated_authorized_encrypted"
      ]
    },
    "components": {
      "device_inventory": "all_devices_tracked_managed",
      "device_trust": "device_certificate_compliance_check",
      "user_trust": "identity_role_based_access",
      "access_proxy": "identity_aware_proxy_front_door"
    },
    "trust_tiers": {
      "fully_trusted": "managed_device_strong_auth_compliant",
      "partially_trusted": "known_device_missing_some_controls",
      "untrusted": "unknown_device_limited_access"
    },
    "implementation_pattern": {
      "step_1": "inventory_all_devices_users",
      "step_2": "define_trust_levels_policies",
      "step_3": "deploy_identity_aware_proxy",
      "step_4": "migrate_applications_behind_proxy",
      "step_5": "deprecate_vpn"
    }
  },
  "ztna": {
    "definition": "Zero Trust Network Access - VPN alternative",
    "characteristics": {
      "application_level": "access_to_specific_app_not_network",
      "identity_aware": "user_device_context_evaluated",
      "least_privilege": "only_necessary_access_granted",
      "cloaked_infrastructure": "apps_not_visible_until_authorized"
    },
    "deployment_models": {
      "service_initiated": {
        "how": "connector_in_datacenter_initiates_outbound",
        "benefit": "no_inbound_firewall_rules_needed",
        "examples": ["zscaler_private_access", "cloudflare_access"]
      },
      "endpoint_initiated": {
        "how": "agent_on_device_connects_to_broker",
        "benefit": "richer_device_context",
        "examples": ["palo_alto_prisma", "cisco_secure_access"]
      }
    },
    "techcorp_ztna_implementation": {
      "vendor": "zscaler_private_access",
      "architecture": {
        "connector": "deployed_in_datacenter_and_cloud",
        "client": "zscaler_client_connector_on_endpoints",
        "broker": "zscaler_cloud_policy_enforcement"
      },
      "migration_from_vpn": {
        "phase_1": "pilot_non_critical_apps",
        "phase_2": "migrate_business_apps",
        "phase_3": "migrate_all_apps",
        "phase_4": "decommission_vpn"
      }
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 04 : Zero Trust Implementation - Device Trust & Maturity

**Concepts couverts** : 3.27.2.h (Device Trust), 3.27.2.i (Context-Aware Access), 3.27.2.j (Continuous Verification), 3.27.2.k (Data-Centric Security), 3.27.2.l (Zero Trust Maturity), 3.27.2.m (Implementation Challenges), 3.27.2.n (Zero Trust Vendors)

**Entrée JSON** :
```json
{
  "current_assessment": {
    "organization": "TechCorp Industries",
    "device_management": "partial_mdm",
    "access_policies": "static_location_based",
    "data_protection": "perimeter_focused"
  },
  "maturity_goals": {
    "target_level": "advanced",
    "timeline": "24_months"
  }
}
```

**Sortie attendue** :
```json
{
  "device_trust": {
    "definition": "assess_device_security_posture_before_granting_access",
    "trust_signals": {
      "identity": {
        "device_certificate": "issued_by_corporate_ca",
        "hardware_attestation": "tpm_verification",
        "device_id": "unique_immutable_identifier"
      },
      "compliance": {
        "os_patch_level": "within_30_days_of_release",
        "endpoint_protection": "edr_active_updated",
        "encryption": "full_disk_encryption_enabled",
        "firewall": "host_firewall_enabled"
      },
      "management": {
        "mdm_enrolled": "under_corporate_management",
        "policy_compliant": "required_policies_applied",
        "last_check_in": "within_24_hours"
      },
      "health": {
        "no_jailbreak_root": "device_integrity_verified",
        "no_malware": "clean_scan_recent",
        "secure_boot": "enabled_verified"
      }
    },
    "trust_levels": {
      "full_trust": {
        "requirements": ["corporate_owned", "fully_compliant", "all_signals_green"],
        "access": "all_resources_full_functionality"
      },
      "partial_trust": {
        "requirements": ["known_device", "mostly_compliant", "minor_issues"],
        "access": "most_resources_some_restrictions"
      },
      "limited_trust": {
        "requirements": ["byod", "basic_security", "not_fully_compliant"],
        "access": "limited_resources_browser_only"
      },
      "no_trust": {
        "requirements": ["unknown_device", "non_compliant", "high_risk"],
        "access": "denied_or_remediation_required"
      }
    },
    "implementation": {
      "mdm_integration": "microsoft_intune",
      "compliance_check": "real_time_before_access",
      "remediation": "self_service_compliance_portal"
    }
  },
  "context_aware_access": {
    "definition": "dynamic_policy_based_on_multiple_contextual_factors",
    "context_factors": {
      "user_context": {
        "identity": "verified_authenticated_user",
        "role": "job_function_permissions",
        "group": "department_team_membership",
        "risk_level": "user_risk_score_from_ueba"
      },
      "device_context": {
        "trust_level": "device_trust_assessment",
        "type": "corporate_byod_managed_unmanaged",
        "platform": "windows_macos_ios_android"
      },
      "location_context": {
        "network": "corporate_home_public_wifi",
        "geography": "country_region_compliance",
        "ip_reputation": "known_good_suspicious_tor"
      },
      "temporal_context": {
        "time": "business_hours_after_hours",
        "duration": "session_length",
        "frequency": "normal_unusual_access_pattern"
      },
      "resource_context": {
        "sensitivity": "data_classification_level",
        "type": "application_data_service",
        "action": "read_write_admin"
      },
      "behavioral_context": {
        "login_behavior": "normal_anomalous",
        "access_pattern": "typical_unusual",
        "velocity": "impossible_travel"
      }
    },
    "policy_examples": {
      "high_risk_scenario": {
        "context": "new_device_unusual_location_sensitive_app",
        "action": "require_additional_mfa_limit_session"
      },
      "trusted_scenario": {
        "context": "managed_device_office_network_normal_hours",
        "action": "grant_access_standard_session"
      },
      "byod_scenario": {
        "context": "personal_device_home_network",
        "action": "web_access_only_no_download"
      }
    }
  },
  "continuous_verification": {
    "definition": "ongoing_validation_not_just_at_login",
    "verification_points": {
      "session_start": {
        "checks": ["authenticate_user", "verify_device", "evaluate_context"],
        "action": "grant_or_deny_session"
      },
      "during_session": {
        "checks": ["device_compliance_changes", "behavior_anomalies", "risk_score_changes"],
        "frequency": "continuous_real_time",
        "action": "reevaluate_modify_terminate"
      },
      "resource_access": {
        "checks": ["authorization_still_valid", "context_changed"],
        "action": "allow_step_up_deny"
      },
      "sensitive_action": {
        "checks": ["step_up_authentication", "verification_required"],
        "action": "require_additional_verification"
      }
    },
    "triggers_for_reevaluation": [
      "device_compliance_fails",
      "impossible_travel_detected",
      "anomalous_behavior",
      "risk_score_increases",
      "accessing_higher_sensitivity_resource",
      "session_timeout"
    ],
    "implementation": {
      "conditional_access": "azure_ad_continuous_access_evaluation",
      "session_controls": "mcas_session_proxy",
      "monitoring": "siem_ueba_integration"
    }
  },
  "data_centric_security": {
    "principle": "protect_data_itself_not_just_perimeter",
    "layers": {
      "classification": {
        "levels": ["public", "internal", "confidential", "restricted"],
        "automation": "ml_based_discovery_classification",
        "labeling": "persistent_labels_follow_data"
      },
      "encryption": {
        "at_rest": "aes_256_all_sensitive_data",
        "in_transit": "tls_1.3_all_connections",
        "in_use": "confidential_computing_enclaves"
      },
      "access_control": {
        "attribute_based": "abac_data_sensitivity_user_role",
        "rights_management": "irm_persistent_protection",
        "need_to_know": "project_based_access"
      },
      "dlp": {
        "endpoint": "prevent_copy_to_usb_unmanaged",
        "network": "detect_exfiltration_attempts",
        "cloud": "prevent_sharing_external_unauthorized"
      },
      "monitoring": {
        "access_logging": "who_accessed_what_when",
        "analytics": "detect_abnormal_access_patterns",
        "alerting": "real_time_sensitive_data_alerts"
      }
    }
  },
  "zero_trust_maturity": {
    "cisa_maturity_model": {
      "pillars": ["identity", "device", "network", "application_workload", "data"],
      "levels": {
        "traditional": {
          "description": "legacy_static_perimeter_based",
          "characteristics": [
            "password_only_auth",
            "flat_network_implicit_trust",
            "perimeter_security_focus"
          ]
        },
        "initial": {
          "description": "starting_zero_trust_journey",
          "characteristics": [
            "mfa_deployed_selectively",
            "basic_segmentation",
            "some_visibility"
          ]
        },
        "advanced": {
          "description": "significant_zero_trust_adoption",
          "characteristics": [
            "mfa_everywhere",
            "micro_segmentation",
            "context_aware_access",
            "continuous_verification"
          ]
        },
        "optimal": {
          "description": "fully_implemented_automated",
          "characteristics": [
            "passwordless",
            "identity_based_segmentation",
            "real_time_adaptive",
            "automated_response"
          ]
        }
      }
    },
    "techcorp_assessment": {
      "identity": {"current": "initial", "target": "advanced"},
      "device": {"current": "traditional", "target": "advanced"},
      "network": {"current": "traditional", "target": "advanced"},
      "application": {"current": "initial", "target": "advanced"},
      "data": {"current": "traditional", "target": "initial"}
    },
    "roadmap": {
      "year_1": {
        "identity": "deploy_mfa_everywhere_sso",
        "device": "full_mdm_coverage_compliance_checks",
        "network": "basic_segmentation_ztna_pilot"
      },
      "year_2": {
        "identity": "conditional_access_risk_based",
        "device": "device_trust_integration",
        "network": "micro_segmentation_vpn_sunset",
        "application": "app_level_access_controls",
        "data": "classification_encryption_program"
      }
    }
  },
  "implementation_challenges": {
    "technical": {
      "legacy_systems": {
        "challenge": "cannot_support_modern_auth_protocols",
        "mitigation": "identity_aware_proxy_wrapper"
      },
      "complexity": {
        "challenge": "multiple_vendors_integration",
        "mitigation": "platform_approach_phased_rollout"
      },
      "visibility": {
        "challenge": "understanding_all_traffic_flows",
        "mitigation": "discovery_phase_traffic_analysis"
      }
    },
    "organizational": {
      "culture": {
        "challenge": "trust_is_embedded_in_culture",
        "mitigation": "executive_sponsorship_education"
      },
      "resistance": {
        "challenge": "perceived_friction_for_users",
        "mitigation": "focus_on_ux_transparent_security"
      },
      "skills": {
        "challenge": "new_skills_required",
        "mitigation": "training_program_external_expertise"
      }
    },
    "operational": {
      "cost": {
        "challenge": "significant_investment_required",
        "mitigation": "business_case_phased_approach_roi"
      },
      "timeline": {
        "challenge": "multi_year_transformation",
        "mitigation": "quick_wins_visible_progress"
      }
    },
    "phased_approach": {
      "principle": "dont_boil_ocean_incremental_value",
      "phases": [
        "protect_crown_jewels_first",
        "expand_to_critical_apps",
        "general_availability",
        "optimize_automate"
      ]
    }
  },
  "zero_trust_vendors": {
    "identity_centric": {
      "microsoft": {
        "products": ["azure_ad", "conditional_access", "defender_for_identity"],
        "strength": "deep_integration_microsoft_ecosystem"
      },
      "okta": {
        "products": ["universal_directory", "adaptive_mfa", "access_gateway"],
        "strength": "best_of_breed_identity_multi_cloud"
      }
    },
    "network_centric": {
      "zscaler": {
        "products": ["zia", "zpa", "workload_segmentation"],
        "strength": "cloud_native_scalable_performance"
      },
      "palo_alto": {
        "products": ["prisma_access", "prisma_cloud", "ngfw"],
        "strength": "comprehensive_portfolio_integration"
      }
    },
    "endpoint_centric": {
      "crowdstrike": {
        "products": ["falcon", "zero_trust_assessment"],
        "strength": "endpoint_detection_response_leader"
      }
    },
    "platform": {
      "google_beyondcorp": {
        "products": ["beyondcorp_enterprise", "iap"],
        "strength": "original_zero_trust_implementation"
      },
      "cloudflare": {
        "products": ["access", "gateway", "warp"],
        "strength": "edge_network_performance"
      }
    },
    "techcorp_selection": {
      "identity": "azure_ad_conditional_access",
      "ztna": "zscaler_private_access",
      "endpoint": "crowdstrike_falcon",
      "rationale": "existing_microsoft_investment_best_of_breed_ztna"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 05 : Network Security Architecture - Segmentation & Modern Perimeter

**Concepts couverts** : 3.27.3.a (Network Segmentation), 3.27.3.b (DMZ Architecture), 3.27.3.c (Firewall Architecture), 3.27.3.d (East-West Security), 3.27.3.e (Secure Web Gateway), 3.27.3.f (Network Access Control), 3.27.3.g (SD-WAN Security), 3.27.3.h (SASE)

**Entrée JSON** :
```json
{
  "organization": {
    "name": "ManufactureCorp",
    "sites": ["headquarters", "factory_1", "factory_2", "warehouse", "branch_offices_50"],
    "cloud": ["aws_primary", "azure_dr"],
    "workforce": {"office": 2000, "remote": 500, "factory": 3000}
  },
  "current_network": {
    "topology": "hub_spoke_mpls",
    "security": "perimeter_only",
    "internet_breakout": "headquarters_only",
    "issues": ["latency_saas", "vpn_bottleneck", "flat_internal"]
  }
}
```

**Sortie attendue** :
```json
{
  "network_segmentation": {
    "definition": "divide_network_into_isolated_segments",
    "purposes": [
      "limit_blast_radius",
      "contain_breaches",
      "meet_compliance",
      "enforce_least_privilege"
    ],
    "segmentation_approaches": {
      "physical": {
        "method": "separate_hardware_switches_routers",
        "use_case": "air_gap_critical_systems_ot"
      },
      "vlan_based": {
        "method": "virtual_lans_layer_2_separation",
        "use_case": "department_function_separation"
      },
      "subnet_based": {
        "method": "ip_subnets_layer_3_separation",
        "use_case": "routing_based_policy_enforcement"
      },
      "micro_segmentation": {
        "method": "workload_level_software_defined",
        "use_case": "zero_trust_east_west"
      }
    },
    "manufacturecorp_design": {
      "zones": {
        "production_it": {
          "vlans": ["vlan_100_servers", "vlan_110_databases", "vlan_120_apps"],
          "trust_level": "high",
          "access": "authenticated_authorized_only"
        },
        "corporate_it": {
          "vlans": ["vlan_200_workstations", "vlan_210_voice", "vlan_220_printers"],
          "trust_level": "medium",
          "access": "employee_devices"
        },
        "ot_network": {
          "vlans": ["vlan_300_scada", "vlan_310_plc", "vlan_320_hmi"],
          "trust_level": "highest",
          "access": "strictly_controlled_airgap_from_it"
        },
        "guest_network": {
          "vlans": ["vlan_400_guest"],
          "trust_level": "untrusted",
          "access": "internet_only_isolated"
        },
        "dmz": {
          "vlans": ["vlan_500_web", "vlan_510_mail", "vlan_520_api"],
          "trust_level": "semi_trusted",
          "access": "public_facing_controlled"
        }
      },
      "inter_zone_rules": {
        "default": "deny_all",
        "explicit_allows": [
          "corporate_to_production_specific_ports",
          "dmz_to_production_reverse_proxy",
          "no_direct_ot_access_from_it"
        ]
      }
    }
  },
  "dmz_architecture": {
    "definition": "demilitarized_zone_buffer_between_trusted_untrusted",
    "design_patterns": {
      "single_firewall_three_leg": {
        "description": "one_firewall_three_interfaces",
        "interfaces": ["external", "dmz", "internal"],
        "pros": "simpler_cost_effective",
        "cons": "single_point_of_compromise"
      },
      "dual_firewall": {
        "description": "front_firewall_back_firewall",
        "layers": ["external_firewall_internet_dmz", "internal_firewall_dmz_lan"],
        "pros": "defense_in_depth_vendor_diversity",
        "cons": "complexity_cost"
      }
    },
    "manufacturecorp_dmz": {
      "design": "dual_firewall",
      "front_firewall": "palo_alto",
      "back_firewall": "cisco_ftd",
      "services_in_dmz": {
        "web_servers": {
          "function": "public_website_customer_portal",
          "protection": "waf_in_front"
        },
        "email_gateway": {
          "function": "inbound_outbound_email",
          "protection": "email_security_gateway"
        },
        "api_gateway": {
          "function": "public_api_access",
          "protection": "api_security_rate_limiting"
        },
        "reverse_proxy": {
          "function": "hide_internal_servers",
          "protection": "ssl_termination_inspection"
        }
      },
      "bastion_hosts": {
        "purpose": "secure_administrative_access",
        "access": "jump_box_mfa_session_recording"
      }
    }
  },
  "firewall_architecture": {
    "types": {
      "perimeter_firewall": {
        "location": "internet_edge",
        "function": "north_south_traffic_control"
      },
      "internal_firewall": {
        "location": "between_zones",
        "function": "inter_zone_traffic_control"
      },
      "distributed_firewall": {
        "location": "host_based_workload",
        "function": "micro_segmentation_east_west"
      }
    },
    "ngfw_capabilities": {
      "stateful_inspection": "track_connections",
      "application_awareness": "identify_apps_beyond_ports",
      "user_identity": "tie_rules_to_users",
      "ssl_inspection": "decrypt_inspect_re_encrypt",
      "ips": "inline_threat_prevention",
      "url_filtering": "category_based_web_control",
      "sandboxing": "unknown_file_analysis"
    },
    "manufacturecorp_firewall_design": {
      "perimeter": {
        "vendor": "palo_alto_pa_5450",
        "deployment": "ha_pair",
        "features": ["threat_prevention", "url_filter", "ssl_decrypt"]
      },
      "internal": {
        "vendor": "palo_alto_pa_3260",
        "zones": ["corp_to_prod", "prod_to_dmz"],
        "features": ["user_id", "app_id", "threat_prevention"]
      },
      "ot_boundary": {
        "vendor": "fortinet_rugged",
        "design": "industrial_firewall_data_diode",
        "features": ["protocol_validation", "anomaly_detection"]
      }
    },
    "rule_management": {
      "principle": "least_privilege_explicit_deny",
      "review": "quarterly_rule_review",
      "documentation": "business_justification_required"
    }
  },
  "east_west_security": {
    "problem": {
      "traditional": "once_inside_free_movement",
      "attacker_behavior": "lateral_movement_after_initial_compromise"
    },
    "solution": "inspect_control_internal_traffic",
    "implementation": {
      "internal_firewalls": {
        "approach": "zone_based_inter_zone_inspection",
        "granularity": "zone_level"
      },
      "micro_segmentation": {
        "approach": "workload_level_policies",
        "tools": ["illumio", "vmware_nsx", "guardicore"],
        "granularity": "process_level"
      },
      "service_mesh": {
        "approach": "application_layer_mtls_authz",
        "tools": ["istio", "linkerd"],
        "granularity": "service_level"
      }
    },
    "manufacturecorp_approach": {
      "zones": "internal_firewalls_between_major_zones",
      "production": "micro_segmentation_critical_workloads",
      "visibility": "network_detection_response_internal"
    }
  },
  "secure_web_gateway": {
    "definition": "proxy_protecting_web_traffic",
    "functions": {
      "url_filtering": "block_malicious_inappropriate_sites",
      "ssl_inspection": "decrypt_inspect_web_traffic",
      "malware_scanning": "scan_downloads_uploads",
      "dlp": "prevent_data_exfiltration_web",
      "cloud_app_control": "casb_functionality"
    },
    "deployment_models": {
      "on_premise": {
        "architecture": "explicit_or_transparent_proxy",
        "pros": "full_control",
        "cons": "backhaul_latency_for_remote"
      },
      "cloud": {
        "architecture": "cloud_proxy_direct_internet",
        "pros": "scalable_low_latency_anywhere",
        "cons": "dependency_on_vendor"
      }
    },
    "manufacturecorp_swg": {
      "vendor": "zscaler_internet_access",
      "deployment": "cloud_direct_from_all_locations",
      "features": ["ssl_inspect", "url_filter", "sandbox", "dlp", "casb"]
    }
  },
  "network_access_control": {
    "definition": "control_what_connects_to_network",
    "standards": {
      "802.1x": {
        "what": "port_based_network_access_control",
        "components": ["supplicant", "authenticator", "authentication_server"],
        "eap_methods": ["eap_tls", "peap", "eap_ttls"]
      }
    },
    "capabilities": {
      "pre_connect": "authenticate_before_network_access",
      "posture_assessment": "check_device_compliance",
      "guest_access": "separate_onboarding_limited_access",
      "dynamic_vlan": "assign_vlan_based_on_identity_posture"
    },
    "manufacturecorp_nac": {
      "vendor": "cisco_ise",
      "corporate_devices": "802.1x_eap_tls_certificates",
      "byod": "onboarding_portal_limited_vlan",
      "guest": "sponsor_portal_isolated_internet",
      "non_compliant": "quarantine_vlan_remediation"
    }
  },
  "sd_wan_security": {
    "definition": "software_defined_wan_with_security",
    "benefits": {
      "cost": "reduce_mpls_use_internet_broadband",
      "performance": "intelligent_path_selection",
      "agility": "rapid_deployment_changes"
    },
    "security_considerations": {
      "encryption": "ipsec_aes_256_all_tunnels",
      "segmentation": "overlay_zones_isolation",
      "inspection": "integrated_or_chained_ngfw",
      "zero_trust": "identity_aware_routing"
    },
    "manufacturecorp_sd_wan": {
      "vendor": "vmware_velocloud",
      "architecture": {
        "branches": "sd_wan_appliance_dual_internet",
        "factories": "sd_wan_plus_dedicated_line_hybrid",
        "headquarters": "sd_wan_hub_full_stack"
      },
      "security_integration": {
        "embedded": "stateful_firewall_on_appliance",
        "chained": "traffic_to_zscaler_swg",
        "cloud": "direct_to_aws_azure_secure"
      }
    }
  },
  "sase": {
    "definition": "Secure Access Service Edge - converged network + security",
    "gartner_definition": "cloud_delivered_converged_network_security_capabilities",
    "components": {
      "network": {
        "sd_wan": "intelligent_wan_connectivity",
        "cdn": "content_delivery_optimization",
        "wan_optimization": "traffic_efficiency"
      },
      "security": {
        "swg": "secure_web_gateway",
        "casb": "cloud_access_security_broker",
        "ztna": "zero_trust_network_access",
        "fwaas": "firewall_as_a_service",
        "dlp": "data_loss_prevention"
      }
    },
    "benefits": {
      "convergence": "single_vendor_single_pane",
      "cloud_native": "scalable_global_presence",
      "user_centric": "security_follows_user_anywhere",
      "reduced_latency": "direct_to_cloud_local_pop"
    },
    "manufacturecorp_sase_journey": {
      "current": "separate_sd_wan_separate_security",
      "target": "converged_sase_platform",
      "migration": {
        "phase_1": "zscaler_for_swg_ztna",
        "phase_2": "evaluate_sase_vendors_convergence",
        "phase_3": "migrate_to_single_sase_platform"
      },
      "vendor_evaluation": ["zscaler", "palo_alto_prisma", "netskope", "cisco_umbrella"]
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 06 : Network Security Architecture - Advanced Protections

**Concepts couverts** : 3.27.3.i (DDoS Architecture), 3.27.3.j (DNS Security), 3.27.3.k (Email Security Architecture), 3.27.3.l (Network Monitoring), 3.27.3.m (Encrypted Traffic Analysis), 3.27.3.n (Remote Access Architecture), 3.27.3.o (Cloud Network Security), 3.27.3.p (OT Network Architecture)

**Entrée JSON** :
```json
{
  "infrastructure": {
    "public_services": ["ecommerce_site", "api_platform", "customer_portal"],
    "email_users": 5500,
    "ot_systems": ["scada", "plc_networks", "hmi"],
    "cloud_presence": ["aws", "azure"]
  },
  "threats": {
    "ddos_attacks": "increasing",
    "phishing": "primary_attack_vector",
    "ot_targeting": "nation_state_concern"
  }
}
```

**Sortie attendue** :
```json
{
  "ddos_architecture": {
    "attack_types": {
      "volumetric": {
        "examples": ["udp_flood", "icmp_flood", "amplification"],
        "target": "saturate_bandwidth"
      },
      "protocol": {
        "examples": ["syn_flood", "fragmentation"],
        "target": "exhaust_server_resources"
      },
      "application": {
        "examples": ["http_flood", "slowloris", "api_abuse"],
        "target": "exhaust_application_resources"
      }
    },
    "mitigation_layers": {
      "upstream_scrubbing": {
        "providers": ["cloudflare", "akamai", "aws_shield_advanced"],
        "method": "divert_traffic_scrub_return_clean",
        "capacity": "multi_tbps"
      },
      "cdn_protection": {
        "method": "absorb_at_edge_cache_static",
        "benefit": "distribute_load_globally"
      },
      "on_premise": {
        "devices": "inline_ddos_mitigation_appliances",
        "use_case": "smaller_attacks_always_on"
      },
      "application_layer": {
        "waf": "rate_limiting_bot_detection",
        "challenge": "captcha_js_challenge"
      }
    },
    "manufacturecorp_design": {
      "primary": "cloudflare_spectrum_for_critical",
      "backup": "aws_shield_advanced_for_aws_hosted",
      "on_prem": "radware_defensepro",
      "playbook": "automatic_diversion_to_scrubbing"
    }
  },
  "dns_security": {
    "threats": {
      "dns_spoofing": "fake_dns_responses",
      "dns_hijacking": "redirect_to_malicious",
      "dns_tunneling": "data_exfiltration_via_dns",
      "dns_amplification": "ddos_via_open_resolvers"
    },
    "protective_measures": {
      "dnssec": {
        "what": "dns_security_extensions",
        "how": "cryptographic_signing_dns_records",
        "benefit": "verify_authenticity_integrity"
      },
      "dns_filtering": {
        "what": "block_known_malicious_domains",
        "providers": ["cisco_umbrella", "cloudflare_gateway", "infoblox"],
        "categories": ["malware", "phishing", "command_control"]
      },
      "doh_dot": {
        "doh": "dns_over_https",
        "dot": "dns_over_tls",
        "benefit": "encrypt_dns_prevent_snooping"
      },
      "dns_sinkhole": {
        "what": "redirect_malicious_to_controlled",
        "use": "contain_malware_internal"
      }
    },
    "internal_dns_security": {
      "split_dns": "internal_external_different_views",
      "monitoring": "log_analyze_dns_queries",
      "restriction": "only_corporate_dns_allowed"
    }
  },
  "email_security_architecture": {
    "threat_landscape": {
      "phishing": "credential_theft_malware_delivery",
      "bec": "business_email_compromise",
      "spam": "unwanted_malicious_content",
      "data_exfiltration": "sensitive_data_via_email"
    },
    "layered_defense": {
      "gateway": {
        "function": "first_line_inbound_outbound",
        "capabilities": ["spam_filter", "av_scan", "url_rewrite", "attachment_sandbox"],
        "vendors": ["proofpoint", "mimecast", "microsoft_defender"]
      },
      "authentication": {
        "spf": {
          "what": "sender_policy_framework",
          "how": "specify_authorized_sending_ips"
        },
        "dkim": {
          "what": "domainkeys_identified_mail",
          "how": "cryptographic_signature_emails"
        },
        "dmarc": {
          "what": "domain_authentication_reporting",
          "how": "policy_alignment_spf_dkim",
          "policy": "reject_quarantine_none"
        }
      },
      "user_protection": {
        "safe_links": "url_time_of_click_verification",
        "safe_attachments": "sandbox_before_delivery",
        "impersonation": "detect_lookalike_domains"
      },
      "dlp": {
        "outbound": "prevent_sensitive_data_leaving",
        "policies": ["pii", "financial", "intellectual_property"]
      }
    },
    "manufacturecorp_email": {
      "platform": "microsoft_365",
      "gateway": "microsoft_defender_for_office",
      "advanced": "proofpoint_targeted_attack_protection",
      "dmarc_policy": "p=reject"
    }
  },
  "network_monitoring": {
    "visibility_types": {
      "flow_data": {
        "what": "netflow_sflow_ipfix",
        "provides": "who_talked_to_whom_how_much",
        "use": "traffic_analysis_anomaly_detection"
      },
      "packet_capture": {
        "what": "full_packet_inspection",
        "provides": "complete_traffic_content",
        "use": "forensics_deep_analysis"
      },
      "log_data": {
        "what": "device_application_logs",
        "provides": "events_activities_decisions",
        "use": "correlation_alerting"
      }
    },
    "tools": {
      "ids_ips": {
        "function": "detect_prevent_known_attacks",
        "deployment": "inline_or_span",
        "vendors": ["snort", "suricata", "palo_alto"]
      },
      "ndr": {
        "function": "network_detection_response_ml_based",
        "capabilities": ["anomaly_detection", "threat_hunting", "investigation"],
        "vendors": ["darktrace", "vectra", "extrahop"]
      },
      "siem": {
        "function": "centralized_log_analysis_correlation",
        "vendors": ["splunk", "microsoft_sentinel", "elastic"]
      }
    },
    "strategic_placement": {
      "perimeter": "north_south_full_visibility",
      "internal": "east_west_critical_segments",
      "cloud": "vpc_flow_logs_mirror_traffic"
    }
  },
  "encrypted_traffic_analysis": {
    "challenge": "80_percent_traffic_encrypted_blind_spot",
    "approaches": {
      "ssl_tls_inspection": {
        "method": "decrypt_inspect_re_encrypt",
        "where": "firewall_proxy_with_ca_cert",
        "considerations": ["privacy", "performance", "compliance_exemptions"]
      },
      "metadata_analysis": {
        "method": "analyze_without_decryption",
        "data_points": ["sni", "certificate_info", "timing", "sizes"],
        "capabilities": "detect_malware_c2_tunneling"
      },
      "ja3_fingerprinting": {
        "method": "tls_client_fingerprint",
        "use": "identify_malware_botnets"
      },
      "certificate_validation": {
        "method": "verify_certificate_chain_reputation",
        "detects": "self_signed_expired_malicious_ca"
      }
    },
    "manufacturecorp_approach": {
      "external": "ssl_inspection_on_swg",
      "internal": "metadata_ndr_ja3",
      "exceptions": "healthcare_banking_privacy_sensitive"
    }
  },
  "remote_access_architecture": {
    "options": {
      "traditional_vpn": {
        "types": ["site_to_site", "client_to_site"],
        "protocols": ["ipsec", "ssl_vpn"],
        "limitations": ["full_network_access", "performance", "complexity"]
      },
      "ztna": {
        "approach": "application_level_identity_aware",
        "benefits": ["least_privilege", "invisible_network"],
        "vendors": ["zscaler_zpa", "cloudflare_access"]
      },
      "vdi_daas": {
        "approach": "virtual_desktop_data_stays_internal",
        "use_case": "high_security_contractors",
        "vendors": ["citrix", "vmware_horizon", "aws_workspaces"]
      }
    },
    "privileged_access": {
      "jump_servers": {
        "purpose": "controlled_access_point_critical_systems",
        "controls": ["mfa", "session_recording", "time_limited"]
      },
      "pam": {
        "purpose": "privileged_access_management",
        "capabilities": ["credential_vault", "session_management", "just_in_time"],
        "vendors": ["cyberark", "beyondtrust", "delinea"]
      }
    },
    "manufacturecorp_remote": {
      "general_workforce": "ztna_zscaler_zpa",
      "it_admin": "pam_cyberark_jump_servers",
      "contractors": "vdi_time_limited_access"
    }
  },
  "cloud_network_security": {
    "vpc_design": {
      "subnets": {
        "public": "internet_facing_load_balancers",
        "private_app": "application_tier_no_direct_internet",
        "private_data": "database_tier_most_restricted"
      },
      "isolation": {
        "approach": "separate_vpc_per_environment_workload",
        "connectivity": "transit_gateway_peering_controlled"
      }
    },
    "controls": {
      "security_groups": {
        "what": "instance_level_stateful_firewall",
        "best_practice": "least_privilege_specific_ports_sources"
      },
      "nacls": {
        "what": "subnet_level_stateless_firewall",
        "best_practice": "additional_layer_explicit_deny"
      },
      "flow_logs": {
        "what": "vpc_traffic_logging",
        "use": "security_analysis_compliance_troubleshooting"
      }
    },
    "egress_control": {
      "nat_gateway": "controlled_outbound_no_inbound",
      "proxy": "inspect_outbound_traffic",
      "firewall": "aws_network_firewall_or_appliance"
    },
    "connectivity": {
      "direct_connect_expressroute": "private_dedicated_to_onprem",
      "vpn": "encrypted_over_internet",
      "transit_gateway": "hub_for_vpc_connectivity"
    }
  },
  "ot_network_architecture": {
    "purdue_model": {
      "level_5": {"name": "enterprise", "systems": "erp_email_corporate"},
      "level_4": {"name": "site_business", "systems": "it_dmz_historians"},
      "level_3.5": {"name": "industrial_dmz", "systems": "patch_av_data_historian"},
      "level_3": {"name": "site_operations", "systems": "hmi_engineering"},
      "level_2": {"name": "area_control", "systems": "scada_dcs"},
      "level_1": {"name": "basic_control", "systems": "plc_rtu"},
      "level_0": {"name": "process", "systems": "sensors_actuators"}
    },
    "it_ot_segmentation": {
      "principle": "strict_separation_controlled_crossing",
      "industrial_dmz": {
        "purpose": "buffer_zone_data_exchange",
        "services": ["data_diode", "historian", "patch_server"]
      },
      "data_diode": {
        "what": "unidirectional_gateway",
        "how": "data_out_only_no_data_in",
        "use": "highest_security_ot_to_it"
      }
    },
    "ot_specific_security": {
      "protocol_validation": {
        "what": "inspect_industrial_protocols",
        "protocols": ["modbus", "dnp3", "opc_ua", "profinet"],
        "vendors": ["claroty", "nozomi", "dragos"]
      },
      "anomaly_detection": {
        "what": "baseline_normal_detect_deviation",
        "importance": "ot_signatures_limited"
      },
      "air_gap": {
        "when": "highest_security_safety_systems",
        "challenge": "updates_still_needed"
      }
    },
    "manufacturecorp_ot": {
      "design": "purdue_model_industrial_dmz",
      "it_ot_firewall": "fortinet_industrial",
      "data_transfer": "waterfall_data_diode",
      "monitoring": "claroty_ot_visibility"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 07 : Identity & Access Architecture - Core IAM

**Concepts couverts** : 3.27.4.a (IAM Architecture), 3.27.4.b (Authentication Architecture), 3.27.4.c (Authorization Models), 3.27.4.d (Directory Services), 3.27.4.e (Federation), 3.27.4.f (SSO Architecture), 3.27.4.g (Privileged Access Management), 3.27.4.h (Service Account Management)

**Entrée JSON** :
```json
{
  "organization": {
    "name": "HealthCare Systems Inc",
    "users": {"employees": 15000, "contractors": 2000, "partners": 500},
    "applications": {"internal": 150, "saas": 75, "patient_facing": 10},
    "compliance": ["HIPAA", "HITRUST"]
  },
  "current_iam": {
    "directories": ["on_prem_ad", "azure_ad"],
    "authentication": "password_mfa_some",
    "authorization": "group_based_inconsistent",
    "privileged_access": "shared_accounts"
  }
}
```

**Sortie attendue** :
```json
{
  "iam_architecture": {
    "definition": "identity_access_management_framework",
    "core_functions": {
      "identity_management": {
        "who": "define_manage_identities",
        "lifecycle": "joiner_mover_leaver",
        "governance": "attestation_recertification"
      },
      "authentication": {
        "what": "verify_identity_claims",
        "methods": ["password", "mfa", "biometric", "certificate"]
      },
      "authorization": {
        "what": "determine_allowed_actions",
        "models": ["rbac", "abac", "pbac"]
      },
      "accountability": {
        "what": "audit_trail_logging",
        "why": "compliance_forensics"
      }
    },
    "healthcare_iam_requirements": {
      "hipaa": ["minimum_necessary", "access_controls", "audit_logs"],
      "hitrust": ["strong_authentication", "privileged_access", "identity_governance"]
    },
    "architecture_layers": {
      "identity_source": "authoritative_hr_directory",
      "identity_provider": "azure_ad_primary_idp",
      "access_management": "conditional_access_policies",
      "governance": "saviynt_identity_governance"
    }
  },
  "authentication_architecture": {
    "mfa_strategy": {
      "mandate": "mfa_all_users_all_access",
      "methods_by_risk": {
        "high_assurance": ["fido2_security_key", "windows_hello"],
        "standard": ["authenticator_app_push", "otp"],
        "fallback": ["sms_otp_limited_use"]
      },
      "phishing_resistant": {
        "what": "mfa_that_cannot_be_phished",
        "how": ["fido2", "webauthn", "certificate"],
        "mandate": "privileged_users_sensitive_data"
      }
    },
    "passwordless": {
      "strategy": "reduce_eliminate_passwords",
      "methods": {
        "fido2": "security_key_hardware",
        "windows_hello": "biometric_pin_device_bound",
        "passkeys": "platform_authenticators"
      },
      "roadmap": {
        "phase_1": "passwordless_option_for_all",
        "phase_2": "passwordless_default_new_users",
        "phase_3": "password_elimination"
      }
    },
    "adaptive_authentication": {
      "factors": ["user_risk", "sign_in_risk", "device_compliance", "location"],
      "responses": {
        "low_risk": "allow_single_factor",
        "medium_risk": "require_mfa",
        "high_risk": "block_or_additional_verification"
      }
    }
  },
  "authorization_models": {
    "rbac": {
      "definition": "role_based_access_control",
      "concept": "permissions_assigned_to_roles_users_get_roles",
      "healthcare_example": {
        "roles": {
          "physician": ["view_patient_records", "order_medications", "sign_orders"],
          "nurse": ["view_patient_records", "document_vitals", "administer_medications"],
          "admin_staff": ["schedule_appointments", "update_demographics"],
          "billing": ["view_billing_info", "process_claims"]
        }
      },
      "pros": "simple_auditable_scalable",
      "cons": "role_explosion_not_context_aware"
    },
    "abac": {
      "definition": "attribute_based_access_control",
      "concept": "policies_based_on_attributes_user_resource_environment",
      "healthcare_example": {
        "policy": "allow_if_user.role=physician AND resource.patient.care_team.contains(user.id) AND time.within_business_hours",
        "attributes": ["user_role", "department", "patient_relationship", "data_sensitivity"]
      },
      "pros": "fine_grained_context_aware_flexible",
      "cons": "complex_to_manage_audit"
    },
    "pbac": {
      "definition": "policy_based_access_control",
      "concept": "centralized_policy_engine_evaluates_requests",
      "implementation": "opa_or_custom_policy_engine"
    },
    "healthcare_approach": {
      "base": "rbac_for_standard_access",
      "enhanced": "abac_for_patient_data_break_glass",
      "policy_engine": "azure_ad_conditional_access_plus_custom"
    }
  },
  "directory_services": {
    "architecture": {
      "hybrid": {
        "on_premises": "active_directory_domain_services",
        "cloud": "azure_active_directory",
        "sync": "azure_ad_connect"
      }
    },
    "authoritative_source": {
      "hr_system": "workday",
      "provisioning": "automated_from_hr_to_ad"
    },
    "schema_design": {
      "user_attributes": ["employeeID", "department", "jobTitle", "manager", "hipaa_training"],
      "groups": {
        "role_groups": "based_on_job_function",
        "application_groups": "per_app_access",
        "dynamic_groups": "attribute_based_membership"
      }
    },
    "lifecycle_automation": {
      "joiner": "auto_provision_based_on_role",
      "mover": "access_adjustment_on_role_change",
      "leaver": "immediate_disable_delayed_delete"
    }
  },
  "federation": {
    "purpose": "trust_relationship_between_identity_providers",
    "standards": {
      "saml_2_0": {
        "what": "security_assertion_markup_language",
        "flow": "idp_asserts_identity_sp_trusts",
        "use_case": "enterprise_sso_legacy_apps"
      },
      "oidc": {
        "what": "openid_connect_over_oauth_2",
        "flow": "id_token_user_info_claims",
        "use_case": "modern_apps_mobile_api"
      },
      "ws_federation": {
        "what": "web_services_federation",
        "use_case": "microsoft_legacy_integration"
      }
    },
    "healthcare_federation": {
      "internal": "azure_ad_as_idp",
      "partners": "b2b_federation_partner_idps",
      "patients": "b2c_social_verified_id"
    }
  },
  "sso_architecture": {
    "benefits": [
      "single_authentication_multiple_apps",
      "reduced_password_fatigue",
      "centralized_access_control",
      "improved_security_visibility"
    ],
    "implementation": {
      "corporate_apps": {
        "method": "saml_oidc_to_azure_ad",
        "coverage": "all_150_internal_apps"
      },
      "saas_apps": {
        "method": "azure_ad_app_gallery_scim",
        "coverage": "75_saas_applications"
      },
      "legacy_apps": {
        "method": "azure_ad_app_proxy_header_based",
        "coverage": "header_injection_kerberos_ntlm"
      }
    },
    "session_management": {
      "lifetime": "8_hours_business_day",
      "inactivity": "15_minutes_for_sensitive_apps",
      "reauthentication": "step_up_for_high_risk_actions"
    }
  },
  "privileged_access_management": {
    "problem": {
      "shared_accounts": "no_accountability",
      "static_credentials": "never_rotated_target_for_attackers",
      "excessive_access": "admin_everywhere"
    },
    "pam_capabilities": {
      "credential_vault": {
        "function": "secure_storage_privileged_credentials",
        "rotation": "automatic_after_use_or_schedule"
      },
      "session_management": {
        "function": "controlled_privileged_sessions",
        "features": ["recording", "live_monitoring", "command_filtering"]
      },
      "just_in_time": {
        "function": "temporary_elevated_access",
        "workflow": "request_approve_time_limited"
      },
      "just_enough_admin": {
        "function": "scoped_admin_not_full",
        "example": "reset_password_only_not_full_admin"
      }
    },
    "healthcare_pam": {
      "vendor": "cyberark_privileged_access_security",
      "tiers": {
        "tier_0": "domain_controllers_ad_admins",
        "tier_1": "servers_infrastructure",
        "tier_2": "workstations_helpdesk"
      },
      "break_glass": {
        "what": "emergency_access_procedure",
        "controls": ["monitored", "dual_approval", "time_limited", "incident_created"]
      }
    }
  },
  "service_account_management": {
    "challenges": {
      "proliferation": "hundreds_of_service_accounts",
      "over_privileged": "often_full_admin_rights",
      "static_credentials": "rarely_rotated",
      "lack_of_ownership": "no_one_responsible"
    },
    "best_practices": {
      "inventory": "comprehensive_list_all_service_accounts",
      "ownership": "assigned_owner_application_team",
      "least_privilege": "minimum_necessary_permissions",
      "managed_identities": "use_managed_identity_where_possible",
      "rotation": "automated_credential_rotation",
      "monitoring": "alert_on_anomalous_behavior"
    },
    "healthcare_implementation": {
      "cloud": {
        "azure": "managed_identities_for_azure_services",
        "aws": "iam_roles_for_ec2_lambda"
      },
      "on_premises": {
        "vault": "cyberark_for_service_credentials",
        "rotation": "automatic_nightly_for_critical"
      },
      "governance": {
        "review": "quarterly_service_account_review",
        "attestation": "owner_confirms_still_needed"
      }
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 08 : Identity Architecture - Modern Identity & Governance

**Concepts couverts** : 3.27.4.i (API Security Architecture), 3.27.4.j (Identity Governance), 3.27.4.k (Customer Identity CIAM), 3.27.4.l (Machine Identity), 3.27.4.m (Passwordless), 3.27.4.n (Decentralized Identity), 3.27.4.o (Identity Threat Detection), 3.27.4.p (Zero Standing Privileges)

**Entrée JSON** :
```json
{
  "context": "HealthCare Systems Inc - Advanced IAM",
  "api_ecosystem": {
    "internal_apis": 200,
    "partner_apis": 50,
    "patient_apis": 25
  },
  "identity_challenges": {
    "governance": "manual_access_reviews",
    "machine_identities": "unmanaged_api_keys",
    "patient_identity": "siloed_per_app"
  }
}
```

**Sortie attendue** :
```json
{
  "api_security_architecture": {
    "api_gateway": {
      "function": "centralized_api_management_security",
      "capabilities": {
        "authentication": "oauth2_jwt_api_key_validation",
        "authorization": "scope_based_policy_enforcement",
        "rate_limiting": "protect_against_abuse",
        "throttling": "fair_usage_quotas",
        "transformation": "request_response_manipulation",
        "logging": "comprehensive_audit_trail"
      },
      "vendors": ["kong", "apigee", "aws_api_gateway", "azure_apim"]
    },
    "oauth_oidc": {
      "flows": {
        "authorization_code": {
          "use_case": "web_apps_mobile_apps",
          "security": "pkce_required"
        },
        "client_credentials": {
          "use_case": "machine_to_machine",
          "security": "secrets_rotation_mTLS"
        },
        "device_code": {
          "use_case": "iot_devices_tvs",
          "security": "limited_device_capability"
        }
      },
      "token_management": {
        "access_token": "short_lived_15_min",
        "refresh_token": "longer_lived_rotation",
        "id_token": "identity_claims_for_client"
      }
    },
    "healthcare_api_security": {
      "internal": {
        "gateway": "kong_enterprise",
        "auth": "oauth2_jwt_from_azure_ad"
      },
      "partner_fhir": {
        "gateway": "apigee",
        "auth": "oauth2_smart_on_fhir",
        "compliance": "hipaa_compliant_logging"
      },
      "patient": {
        "gateway": "aws_api_gateway",
        "auth": "cognito_oauth2_patient_consent"
      }
    }
  },
  "identity_governance": {
    "definition": "manage_control_identity_access_lifecycle",
    "capabilities": {
      "access_request": {
        "self_service": "user_requests_access",
        "workflow": "approval_chain_based_on_sensitivity"
      },
      "access_certification": {
        "what": "periodic_review_of_access",
        "frequency": "quarterly_for_sensitive_annual_all",
        "process": "manager_app_owner_review_certify_revoke"
      },
      "segregation_of_duties": {
        "what": "prevent_toxic_combinations",
        "example": "cannot_have_both_create_payment_approve_payment"
      },
      "role_mining": {
        "what": "discover_optimize_roles",
        "method": "analyze_existing_access_patterns"
      },
      "orphan_account_detection": {
        "what": "find_accounts_without_owner",
        "action": "disable_or_assign_owner"
      }
    },
    "healthcare_governance": {
      "vendor": "saviynt_identity_cloud",
      "integration": "azure_ad_hr_system_apps",
      "policies": {
        "hipaa_minimum_necessary": "restrict_phi_access_job_function",
        "break_glass_tracking": "emergency_access_reviewed_24h",
        "contractor_expiration": "auto_disable_contract_end"
      },
      "certification_campaigns": {
        "phi_access": "quarterly_phi_access_review",
        "privileged": "monthly_admin_access_review",
        "all_access": "annual_full_certification"
      }
    }
  },
  "ciam": {
    "definition": "Customer Identity and Access Management",
    "differences_from_iam": {
      "scale": "millions_of_users_vs_thousands",
      "registration": "self_service_not_hr_provisioned",
      "authentication": "social_login_passwordless_options",
      "privacy": "consent_management_gdpr_ccpa",
      "experience": "ux_critical_for_conversion"
    },
    "capabilities": {
      "registration": "progressive_profiling_self_service",
      "authentication": {
        "options": ["email_password", "social_login", "passwordless", "mfa"],
        "adaptive": "risk_based_step_up"
      },
      "consent": {
        "management": "granular_consent_per_purpose",
        "withdrawal": "easy_consent_withdrawal"
      },
      "profile": {
        "management": "self_service_profile_management",
        "preferences": "communication_privacy_settings"
      }
    },
    "healthcare_patient_portal": {
      "vendor": "azure_ad_b2c",
      "features": {
        "registration": "identity_proofing_for_patients",
        "authentication": "passwordless_biometric_option",
        "consent": "hipaa_consent_management",
        "mfa": "required_for_phi_access"
      },
      "identity_proofing": {
        "level": "ial2_for_phi_access",
        "methods": ["document_verification", "knowledge_based", "trusted_referee"]
      }
    }
  },
  "machine_identity": {
    "types": {
      "service_accounts": "application_run_as_accounts",
      "api_keys": "simple_bearer_tokens",
      "certificates": "x509_for_mtls_code_signing",
      "tokens": "oauth_jwt_tokens",
      "ssh_keys": "server_access_automation"
    },
    "challenges": {
      "proliferation": "more_machines_than_humans",
      "lifecycle": "no_hr_system_for_machines",
      "rotation": "credentials_never_changed",
      "visibility": "unknown_scope_permissions"
    },
    "solutions": {
      "managed_identities": {
        "cloud": "azure_managed_identity_aws_iam_roles",
        "benefit": "no_credentials_to_manage"
      },
      "spiffe_spire": {
        "what": "secure_production_identity_framework",
        "how": "workload_identity_short_lived_svids",
        "use": "service_mesh_kubernetes"
      },
      "certificate_management": {
        "tools": ["venafi", "keyfactor", "hashicorp_vault"],
        "automation": "auto_renewal_rotation"
      }
    },
    "healthcare_machine_identity": {
      "cloud_workloads": "managed_identities_preferred",
      "on_prem_apps": "cyberark_for_secrets",
      "certificates": "venafi_for_certificate_lifecycle",
      "iot_medical_devices": "device_certificates_unique_per_device"
    }
  },
  "passwordless_deep_dive": {
    "technologies": {
      "fido2_webauthn": {
        "standard": "w3c_fido_alliance",
        "how": "public_key_cryptography_no_shared_secret",
        "authenticators": ["security_keys", "platform_biometrics"]
      },
      "passkeys": {
        "what": "synced_fido_credentials",
        "where": "icloud_keychain_google_password_manager",
        "benefit": "no_hardware_key_needed"
      },
      "windows_hello": {
        "how": "biometric_pin_device_bound",
        "integration": "azure_ad_native"
      },
      "certificate_based": {
        "how": "x509_smart_card_virtual_smart_card",
        "use_case": "high_security_government"
      }
    },
    "healthcare_passwordless": {
      "physicians": "fido2_security_keys_shared_workstations",
      "nurses": "windows_hello_on_assigned_devices",
      "executives": "passkeys_on_personal_devices",
      "shared_kiosks": "badge_tap_plus_pin"
    }
  },
  "decentralized_identity": {
    "concept": {
      "traditional": "idp_controls_your_identity",
      "decentralized": "user_controls_own_identity"
    },
    "components": {
      "did": {
        "what": "decentralized_identifier",
        "how": "unique_id_not_controlled_by_central_authority"
      },
      "verifiable_credentials": {
        "what": "cryptographically_signed_claims",
        "example": "license_degree_employment_verified"
      },
      "wallet": {
        "what": "app_stores_credentials",
        "user_control": "user_chooses_what_to_share"
      }
    },
    "use_cases": {
      "professional_credentials": "verify_medical_license_without_central_db",
      "patient_health_records": "patient_controlled_health_data",
      "prescription_verification": "verify_prescriber_without_call"
    },
    "healthcare_exploration": {
      "pilot": "physician_credential_verification",
      "technology": "microsoft_entra_verified_id"
    }
  },
  "identity_threat_detection": {
    "definition": "detect_identity_based_attacks_anomalies",
    "threats": {
      "credential_theft": "stolen_passwords_tokens",
      "credential_stuffing": "automated_login_attempts",
      "account_takeover": "attacker_controls_account",
      "privilege_escalation": "unauthorized_elevation"
    },
    "detection_capabilities": {
      "impossible_travel": "login_from_distant_locations",
      "anomalous_behavior": "unusual_access_patterns",
      "risky_sign_ins": "tor_vpn_new_device_location",
      "compromised_credentials": "found_in_breach_databases"
    },
    "response": {
      "automatic": ["block_sign_in", "require_mfa", "password_reset"],
      "manual": ["investigate", "revoke_sessions", "disable_account"]
    },
    "healthcare_itdr": {
      "tool": "microsoft_defender_for_identity",
      "integration": "siem_soar_automated_response",
      "scenarios": {
        "credential_harvest": "detect_lsass_mimikatz",
        "lateral_movement": "detect_pass_the_hash_ticket",
        "golden_ticket": "detect_forged_kerberos"
      }
    }
  },
  "zero_standing_privileges": {
    "concept": {
      "traditional": "permanent_admin_accounts",
      "zsp": "no_permanent_admin_all_jit"
    },
    "implementation": {
      "no_persistent_admin": "admin_accounts_disabled_by_default",
      "request_based": "user_requests_elevation",
      "approval_workflow": "manager_or_peer_approval",
      "time_limited": "access_expires_automatically",
      "audited": "all_elevated_access_logged_reviewed"
    },
    "technologies": {
      "azure_pim": "privileged_identity_management",
      "cyberark_jit": "just_in_time_elevation",
      "aws_iam_identity_center": "temporary_elevated_sessions"
    },
    "healthcare_zsp": {
      "implementation": "azure_pim_for_azure_roles",
      "workflow": {
        "request": "admin_requests_role_via_pim",
        "approval": "second_admin_approves",
        "duration": "max_8_hours",
        "audit": "all_actions_logged_reviewed"
      },
      "exceptions": {
        "break_glass": "emergency_always_available_dual_control",
        "monitoring": "enhanced_monitoring_during_elevation"
      }
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 09 : Data Security Architecture - Classification & Protection

**Concepts couverts** : 3.27.5.a (Data Classification), 3.27.5.b (Data Lifecycle), 3.27.5.c (Encryption Architecture), 3.27.5.d (Key Management), 3.27.5.e (Data Loss Prevention), 3.27.5.f (Database Security), 3.27.5.g (Cloud Data Security)

**Entrée JSON** :
```json
{
  "organization": {
    "name": "FinServ Corporation",
    "industry": "financial_services",
    "data_volume": "500_TB",
    "data_types": ["customer_pii", "financial_transactions", "trading_data", "employee_records"]
  },
  "compliance": ["PCI-DSS", "SOX", "GDPR", "GLBA"],
  "challenges": {
    "classification": "inconsistent_manual",
    "encryption": "partial_coverage",
    "cloud_data": "shadow_it_unknown_data"
  }
}
```

**Sortie attendue** :
```json
{
  "data_classification": {
    "framework": {
      "levels": {
        "public": {
          "description": "no_harm_if_disclosed",
          "examples": ["marketing_materials", "public_financials"],
          "handling": "no_special_controls"
        },
        "internal": {
          "description": "internal_use_only",
          "examples": ["internal_memos", "org_charts"],
          "handling": "access_control_no_external_sharing"
        },
        "confidential": {
          "description": "sensitive_business_data",
          "examples": ["financial_projections", "employee_salaries", "trade_secrets"],
          "handling": "encryption_access_logging_need_to_know"
        },
        "restricted": {
          "description": "highest_sensitivity_regulated",
          "examples": ["customer_pii", "card_data", "trading_algorithms"],
          "handling": "encryption_strict_access_dlp_monitoring"
        }
      }
    },
    "implementation": {
      "discovery": {
        "tools": ["microsoft_purview", "varonis", "bigid"],
        "method": "automated_scanning_pattern_matching_ml"
      },
      "labeling": {
        "manual": "user_applies_label_at_creation",
        "automatic": "content_inspection_auto_label",
        "inheritance": "container_label_applies_to_contents"
      },
      "persistence": {
        "method": "label_travels_with_data",
        "technology": "microsoft_information_protection"
      }
    },
    "finserv_classification": {
      "pci_card_data": "restricted_pci_scope",
      "customer_pii": "restricted_gdpr_scope",
      "trading_data": "confidential_sox_scope",
      "internal_comms": "internal_general"
    }
  },
  "data_lifecycle": {
    "stages": {
      "creation": {
        "security": ["classify_at_creation", "apply_protection", "define_ownership"],
        "controls": "information_classification_policy"
      },
      "storage": {
        "security": ["encryption_at_rest", "access_controls", "backup"],
        "controls": "storage_security_standards"
      },
      "use": {
        "security": ["access_control", "monitoring", "data_masking"],
        "controls": "acceptable_use_policy"
      },
      "sharing": {
        "security": ["authorized_recipients", "secure_transmission", "dlp"],
        "controls": "data_sharing_agreements"
      },
      "archival": {
        "security": ["encrypted_archive", "access_restrictions", "integrity"],
        "controls": "retention_policy"
      },
      "destruction": {
        "security": ["secure_deletion", "verification", "certificate"],
        "controls": "data_destruction_procedures"
      }
    },
    "retention": {
      "regulatory_requirements": {
        "sox": "7_years_financial_records",
        "pci_dss": "1_year_audit_logs",
        "gdpr": "no_longer_than_necessary"
      },
      "implementation": "automated_retention_policies_purview"
    }
  },
  "encryption_architecture": {
    "at_rest": {
      "storage": {
        "database": "tde_transparent_data_encryption",
        "file_storage": "aes_256_at_storage_layer",
        "backup": "encrypted_backup_separate_keys"
      },
      "application_level": {
        "field_level": "encrypt_specific_sensitive_fields",
        "column_level": "database_column_encryption",
        "use_case": "pii_card_numbers_ssn"
      }
    },
    "in_transit": {
      "network": {
        "standard": "tls_1.3_minimum",
        "internal": "mutual_tls_service_to_service",
        "api": "https_only_hsts"
      },
      "email": {
        "opportunistic": "tls_between_mail_servers",
        "forced": "s_mime_pgp_for_sensitive"
      }
    },
    "in_use": {
      "technologies": {
        "confidential_computing": "intel_sgx_amd_sev",
        "homomorphic": "compute_on_encrypted_limited",
        "tokenization": "substitute_sensitive_not_true_encryption"
      },
      "finserv_use": "azure_confidential_computing_for_trading"
    }
  },
  "key_management": {
    "architecture": {
      "hierarchy": {
        "master_key": "kek_protects_all_other_keys",
        "data_encryption_keys": "dek_encrypts_actual_data",
        "key_encryption_keys": "kek_encrypts_deks"
      },
      "hsm": {
        "what": "hardware_security_module",
        "function": "secure_key_storage_cryptographic_operations",
        "vendors": ["thales_luna", "aws_cloudhsm", "azure_dedicated_hsm"]
      },
      "kms": {
        "what": "key_management_service",
        "function": "centralized_key_lifecycle_management",
        "vendors": ["aws_kms", "azure_key_vault", "hashicorp_vault"]
      }
    },
    "lifecycle": {
      "generation": "secure_random_appropriate_length",
      "distribution": "secure_channel_envelope_encryption",
      "rotation": "regular_rotation_annual_or_event_driven",
      "revocation": "immediate_on_compromise_planned_end_of_life",
      "destruction": "secure_deletion_verification"
    },
    "finserv_kms": {
      "cloud": "aws_kms_with_custom_key_store_cloudhsm",
      "on_prem": "thales_luna_network_hsm",
      "byok": "bring_your_own_key_for_regulated_data"
    }
  },
  "data_loss_prevention": {
    "capabilities": {
      "discovery": "find_sensitive_data_everywhere",
      "monitoring": "watch_data_movement",
      "protection": "block_unauthorized_transfer",
      "reporting": "compliance_audit_evidence"
    },
    "deployment_points": {
      "network_dlp": {
        "where": "inline_or_mirror_at_perimeter",
        "monitors": "email_web_ftp_traffic"
      },
      "endpoint_dlp": {
        "where": "agent_on_workstations",
        "monitors": "usb_print_clipboard_upload"
      },
      "cloud_dlp": {
        "where": "api_integration_casb",
        "monitors": "cloud_storage_saas_apps"
      }
    },
    "policies": {
      "pci_card_data": {
        "detection": "regex_luhn_check",
        "action": "block_alert_if_over_threshold"
      },
      "pii": {
        "detection": "ssn_pattern_ml_based",
        "action": "encrypt_or_block_alert"
      },
      "intellectual_property": {
        "detection": "fingerprinting_keywords",
        "action": "prompt_user_log_alert"
      }
    },
    "finserv_dlp": {
      "vendor": "microsoft_purview_dlp",
      "integration": ["endpoint", "email", "teams", "sharepoint", "cloud_apps"],
      "policies": ["pci_card_data", "pii_gdpr", "financial_reports"]
    }
  },
  "database_security": {
    "layers": {
      "access_control": {
        "authentication": "strong_auth_service_accounts",
        "authorization": "least_privilege_roles",
        "row_level": "user_sees_only_their_data"
      },
      "encryption": {
        "tde": "transparent_data_encryption",
        "column": "encrypt_sensitive_columns",
        "always_encrypted": "client_side_encryption"
      },
      "monitoring": {
        "activity_monitoring": "log_all_queries_privileged_actions",
        "anomaly_detection": "baseline_alert_deviation",
        "tools": ["imperva", "ibm_guardium", "azure_sql_audit"]
      },
      "masking": {
        "static": "mask_in_non_prod_environments",
        "dynamic": "real_time_masking_based_on_user"
      }
    },
    "finserv_database_security": {
      "critical_databases": "core_banking_trading",
      "controls": ["always_encrypted_card_data", "tde_all", "dam_imperva", "dynamic_masking"]
    }
  },
  "cloud_data_security": {
    "challenges": {
      "visibility": "data_in_multiple_clouds",
      "control": "shared_responsibility_model",
      "shadow_it": "unauthorized_cloud_services"
    },
    "solutions": {
      "casb": {
        "what": "cloud_access_security_broker",
        "capabilities": ["visibility", "compliance", "threat_protection", "dlp"],
        "modes": ["api", "proxy", "log_analysis"],
        "vendors": ["microsoft_defender", "netskope", "zscaler"]
      },
      "dspm": {
        "what": "data_security_posture_management",
        "capabilities": ["discover_cloud_data", "classify", "assess_risk", "remediate"],
        "vendors": ["wiz", "laminar", "dig"]
      },
      "native_controls": {
        "aws": "macie_kms_config",
        "azure": "purview_key_vault_defender",
        "gcp": "dlp_api_kms_scc"
      }
    },
    "finserv_cloud_data": {
      "casb": "microsoft_defender_for_cloud_apps",
      "dspm": "wiz_for_multi_cloud",
      "strategy": "data_residency_eu_data_in_eu_region"
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 10 : Data Security Architecture - Advanced Protection

**Concepts couverts** : 3.27.5.h (Backup Architecture), 3.27.5.i (Data Masking), 3.27.5.j (Rights Management), 3.27.5.k (Secure Data Sharing), 3.27.5.l (Data Residency), 3.27.5.m (Data Discovery), 3.27.5.n (Secure Destruction)

**Entrée JSON** :
```json
{
  "requirements": {
    "disaster_recovery": "rpo_1h_rto_4h",
    "data_sharing": ["partners", "regulators", "analytics_vendors"],
    "global_operations": ["us", "eu", "apac"],
    "decommissioning": "legacy_systems_data_migration"
  }
}
```

**Sortie attendue** :
```json
{
  "backup_architecture": {
    "3_2_1_rule": {
      "3_copies": "production_local_offsite",
      "2_media_types": "disk_and_tape_or_cloud",
      "1_offsite": "geographically_separate"
    },
    "security_requirements": {
      "encryption": {
        "at_rest": "aes_256_all_backups",
        "in_transit": "tls_for_replication",
        "key_management": "separate_from_backup_data"
      },
      "immutability": {
        "what": "cannot_be_modified_deleted",
        "why": "ransomware_protection",
        "how": "worm_storage_retention_lock"
      },
      "air_gap": {
        "what": "physically_isolated_backup",
        "use_case": "critical_data_ransomware_protection",
        "implementation": "tape_vault_or_disconnected_storage"
      },
      "access_control": {
        "principle": "separate_from_production_admins",
        "implementation": "dedicated_backup_admin_role"
      }
    },
    "testing": {
      "frequency": "quarterly_restore_tests",
      "scope": "full_system_and_individual_files",
      "validation": "data_integrity_application_functionality"
    },
    "finserv_backup": {
      "production": "veeam_to_local_san",
      "replication": "aws_s3_cross_region",
      "immutable": "aws_s3_object_lock",
      "air_gap": "monthly_tape_to_iron_mountain"
    }
  },
  "data_masking": {
    "types": {
      "static_masking": {
        "what": "create_masked_copy_of_data",
        "use_case": "non_prod_environments_analytics",
        "methods": ["substitution", "shuffling", "encryption", "nulling"]
      },
      "dynamic_masking": {
        "what": "mask_at_query_time_based_on_user",
        "use_case": "production_role_based_visibility",
        "methods": ["sql_views", "database_native", "application_layer"]
      },
      "tokenization": {
        "what": "replace_with_token_reversible",
        "use_case": "pci_reduce_scope",
        "methods": ["vault_based", "format_preserving"]
      },
      "pseudonymization": {
        "what": "replace_identifiers_with_pseudonyms",
        "use_case": "gdpr_analytics_research",
        "reversibility": "with_key"
      }
    },
    "implementation": {
      "credit_card": "tokenization_format_preserving",
      "ssn": "static_masking_non_prod_dynamic_prod",
      "names_addresses": "substitution_with_realistic_fake"
    },
    "finserv_masking": {
      "tool": "delphix_data_virtualization",
      "non_prod": "fully_masked_pii_card_data",
      "analytics": "pseudonymized_aggregated",
      "support": "dynamic_masking_based_on_role"
    }
  },
  "rights_management": {
    "definition": "persistent_protection_travels_with_data",
    "capabilities": {
      "encryption": "data_encrypted_regardless_location",
      "access_control": "only_authorized_users_can_open",
      "usage_rights": "control_copy_print_forward_edit",
      "tracking": "know_who_accessed_when",
      "revocation": "revoke_access_after_sharing"
    },
    "technologies": {
      "microsoft_aip_mip": "azure_information_protection",
      "adobe_drm": "pdf_document_protection",
      "vera_virtru": "third_party_rights_management"
    },
    "use_cases": {
      "board_documents": "restricted_no_copy_no_print_audit",
      "contracts": "view_only_watermarked",
      "financial_reports": "internal_only_expires_after_filing"
    },
    "finserv_irm": {
      "tool": "microsoft_information_protection",
      "integration": ["office_365", "sharepoint", "email"],
      "policies": {
        "board_confidential": "executives_only_no_external",
        "client_pii": "need_to_know_logged"
      }
    }
  },
  "secure_data_sharing": {
    "with_partners": {
      "secure_file_transfer": {
        "method": "managed_file_transfer",
        "controls": ["encryption", "authentication", "audit_log"],
        "vendors": ["axway", "globalscape", "aws_transfer_family"]
      },
      "api_based": {
        "method": "secure_api_data_exchange",
        "controls": ["oauth", "rate_limiting", "dlp_inspection"]
      },
      "data_room": {
        "method": "virtual_data_room",
        "use_case": "due_diligence_ma",
        "controls": ["granular_access", "watermarking", "no_download"]
      }
    },
    "with_analytics_vendors": {
      "clean_rooms": {
        "what": "shared_compute_no_data_exposure",
        "how": "parties_bring_data_to_neutral_environment",
        "vendors": ["snowflake_clean_rooms", "aws_clean_rooms"]
      },
      "differential_privacy": {
        "what": "add_noise_to_protect_individuals",
        "use_case": "aggregate_analytics_without_pii"
      },
      "secure_enclaves": {
        "what": "compute_on_encrypted_data",
        "technology": "confidential_computing"
      }
    },
    "finserv_sharing": {
      "regulators": "secure_portal_encrypted_attestation",
      "partners": "api_with_tokenized_data",
      "analytics": "snowflake_clean_room"
    }
  },
  "data_residency": {
    "requirements": {
      "gdpr": "eu_personal_data_eu_adequacy_sccs",
      "china_pipl": "china_data_localization_cross_border_review",
      "russia": "russian_citizen_data_in_russia",
      "sector_specific": "financial_data_may_have_requirements"
    },
    "implementation": {
      "geo_fencing": {
        "what": "restrict_data_to_geographic_region",
        "how": "cloud_regions_storage_policies"
      },
      "data_classification": {
        "what": "identify_data_requiring_residency",
        "how": "tag_with_geographic_restriction"
      },
      "controls": {
        "prevent_copy": "dlp_block_cross_region",
        "audit": "log_data_location_access"
      }
    },
    "finserv_residency": {
      "eu_customer_data": "aws_eu_ireland_frankfurt",
      "us_customer_data": "aws_us_east_west",
      "cross_border": "standard_contractual_clauses",
      "monitoring": "dspm_data_location_tracking"
    }
  },
  "data_discovery": {
    "definition": "find_and_classify_all_sensitive_data",
    "challenges": {
      "unknown_data": "shadow_data_forgotten_copies",
      "scale": "petabytes_across_systems",
      "accuracy": "false_positives_negatives"
    },
    "capabilities": {
      "scanning": {
        "structured": "database_column_analysis",
        "unstructured": "file_content_analysis",
        "cloud": "saas_cloud_storage_scanning"
      },
      "classification": {
        "pattern_matching": "regex_for_known_formats",
        "ml_based": "context_aware_classification",
        "fingerprinting": "document_similarity"
      },
      "inventory": {
        "catalog": "central_data_asset_inventory",
        "lineage": "where_data_came_from_went_to"
      }
    },
    "finserv_discovery": {
      "tool": "microsoft_purview_bigid",
      "scope": ["databases", "file_shares", "cloud_storage", "saas"],
      "schedule": "continuous_scanning",
      "action": "auto_classify_alert_on_sensitive"
    }
  },
  "secure_destruction": {
    "requirements": {
      "regulatory": ["gdpr_right_to_erasure", "pci_cardholder_data"],
      "contractual": "data_retention_clauses",
      "business": "end_of_project_decommissioning"
    },
    "methods": {
      "crypto_shredding": {
        "what": "delete_encryption_key",
        "benefit": "fast_effective_for_encrypted_data",
        "requirement": "proper_key_management_in_place"
      },
      "secure_overwrite": {
        "what": "overwrite_data_multiple_times",
        "standards": ["nist_sp_800_88", "dod_5220.22_m"],
        "use": "hdd_ssd_prior_to_disposal"
      },
      "physical_destruction": {
        "what": "shred_degauss_incinerate",
        "use": "highest_security_media_disposal",
        "verification": "certificate_of_destruction"
      }
    },
    "verification": {
      "audit_trail": "document_what_was_destroyed_when_how",
      "certificate": "third_party_attestation",
      "spot_check": "verify_data_unrecoverable"
    },
    "finserv_destruction": {
      "electronic": "crypto_shredding_primary_overwrite_backup",
      "physical": "contracted_shredding_service_certificate",
      "process": "destruction_request_approval_execution_verification"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 11 : Application Security Architecture - SDLC & Design

**Concepts couverts** : 3.27.6.a (Secure SDLC), 3.27.6.b (Threat Modeling), 3.27.6.c (Secure Design Patterns), 3.27.6.d (API Security), 3.27.6.e (Web Application Architecture), 3.27.6.f (Microservices Security)

**Entrée JSON** :
```json
{
  "development": {
    "methodology": "agile_scrum",
    "teams": 15,
    "applications": {"web": 50, "api": 100, "mobile": 10},
    "architecture": "transitioning_to_microservices"
  },
  "security_maturity": {
    "sast": "partial",
    "dast": "manual_pentests",
    "threat_modeling": "ad_hoc"
  }
}
```

**Sortie attendue** :
```json
{
  "secure_sdlc": {
    "phases": {
      "requirements": {
        "activities": ["security_requirements", "abuse_cases", "compliance_mapping"],
        "deliverables": ["security_requirements_doc", "risk_rating"],
        "tools": ["requirements_tool_with_security_tags"]
      },
      "design": {
        "activities": ["threat_modeling", "security_architecture_review", "secure_design"],
        "deliverables": ["threat_model", "security_design_doc"],
        "gate": "security_design_review_approval"
      },
      "development": {
        "activities": ["secure_coding", "code_review", "sast"],
        "deliverables": ["secure_code", "sast_report"],
        "tools": ["ide_security_plugins", "sast_in_ci"]
      },
      "testing": {
        "activities": ["security_testing", "dast", "penetration_test"],
        "deliverables": ["security_test_results", "pentest_report"],
        "gate": "no_critical_high_vulnerabilities"
      },
      "deployment": {
        "activities": ["secure_config", "infrastructure_scan", "deployment_approval"],
        "deliverables": ["deployment_checklist", "config_scan_results"],
        "gate": "security_sign_off"
      },
      "operations": {
        "activities": ["monitoring", "vulnerability_management", "incident_response"],
        "deliverables": ["security_dashboards", "patching_reports"],
        "continuous": "ongoing_security_operations"
      }
    },
    "integration_with_agile": {
      "security_stories": "security_requirements_as_stories",
      "definition_of_done": "security_checks_included",
      "security_champion": "per_team_security_liaison",
      "sprint_security": "security_activities_each_sprint"
    }
  },
  "threat_modeling": {
    "methodologies": {
      "stride": {
        "what": "spoofing_tampering_repudiation_info_disclosure_dos_elevation",
        "approach": "per_component_threat_identification",
        "use": "most_common_structured_approach"
      },
      "pasta": {
        "what": "process_attack_simulation_threat_analysis",
        "approach": "risk_centric_business_aligned",
        "use": "risk_focused_organizations"
      },
      "attack_trees": {
        "what": "hierarchical_attack_paths",
        "approach": "goal_oriented_attack_modeling",
        "use": "specific_threat_deep_analysis"
      }
    },
    "process": {
      "scope": "identify_system_boundaries_assets",
      "decompose": "create_data_flow_diagram",
      "identify_threats": "apply_methodology_stride",
      "rate_threats": "likelihood_impact_scoring",
      "mitigate": "identify_controls_for_threats",
      "validate": "verify_mitigations_effective"
    },
    "data_flow_diagram": {
      "elements": {
        "external_entity": "outside_trust_boundary",
        "process": "transforms_data",
        "data_store": "persists_data",
        "data_flow": "movement_of_data",
        "trust_boundary": "where_trust_changes"
      }
    },
    "tools": ["microsoft_threat_modeling_tool", "threatmodeler", "iriusrisk", "owasp_threat_dragon"],
    "integration": {
      "when": "design_phase_architecture_changes",
      "who": "security_champion_with_dev_team",
      "time_box": "2_hours_per_feature"
    }
  },
  "secure_design_patterns": {
    "input_validation": {
      "pattern": "validate_all_input_at_trust_boundaries",
      "approach": "allowlist_preferred_over_denylist",
      "implementation": "centralized_validation_library"
    },
    "output_encoding": {
      "pattern": "encode_output_based_on_context",
      "contexts": ["html", "javascript", "url", "sql"],
      "prevents": "injection_attacks_xss"
    },
    "authentication": {
      "pattern": "centralized_authentication_service",
      "implementation": "oauth_oidc_from_idp",
      "anti_pattern": "custom_auth_per_app"
    },
    "authorization": {
      "pattern": "centralized_policy_enforcement",
      "implementation": "api_gateway_or_policy_engine",
      "principle": "default_deny_explicit_allow"
    },
    "secure_defaults": {
      "pattern": "secure_configuration_by_default",
      "examples": ["encryption_on", "auth_required", "logging_enabled"],
      "anti_pattern": "security_as_optional_feature"
    },
    "fail_secure": {
      "pattern": "fail_to_secure_state",
      "example": "deny_access_on_error",
      "anti_pattern": "fail_open_on_exception"
    },
    "least_privilege": {
      "pattern": "minimum_necessary_permissions",
      "implementation": "role_based_fine_grained"
    },
    "defense_in_depth": {
      "pattern": "multiple_layers_of_controls",
      "implementation": "waf_plus_input_validation_plus_prepared_statements"
    }
  },
  "api_security": {
    "owasp_api_top_10": {
      "api1_bola": "broken_object_level_authorization",
      "api2_broken_auth": "authentication_flaws",
      "api3_object_property": "excessive_data_exposure",
      "api4_resource_consumption": "unrestricted_resource_usage",
      "api5_bfla": "broken_function_level_authorization",
      "api6_mass_assignment": "unintended_property_modification",
      "api7_ssrf": "server_side_request_forgery",
      "api8_misconfiguration": "security_misconfiguration",
      "api9_inventory": "improper_asset_management",
      "api10_unsafe_consumption": "consuming_untrusted_apis"
    },
    "security_controls": {
      "authentication": {
        "internal": "oauth2_jwt_from_corporate_idp",
        "external": "api_keys_plus_oauth",
        "machine": "mtls_client_certificates"
      },
      "authorization": {
        "method": "scope_based_claims_based",
        "enforcement": "api_gateway_plus_app_level"
      },
      "rate_limiting": {
        "purpose": "prevent_abuse_dos",
        "implementation": "api_gateway_level"
      },
      "input_validation": {
        "schema": "openapi_spec_validation",
        "content": "payload_inspection"
      }
    },
    "api_gateway": {
      "function": "centralized_security_management",
      "capabilities": ["auth", "rate_limit", "logging", "transformation"],
      "vendor": "kong_or_apigee"
    }
  },
  "web_application_architecture": {
    "security_layers": {
      "waf": {
        "function": "web_application_firewall",
        "protects": ["owasp_top_10", "custom_rules", "bot_protection"],
        "deployment": "in_front_of_all_web_apps"
      },
      "secure_headers": {
        "csp": "content_security_policy_prevent_xss",
        "hsts": "force_https",
        "x_content_type": "prevent_mime_sniffing",
        "x_frame": "prevent_clickjacking"
      },
      "session_management": {
        "secure_cookies": "httponly_secure_samesite",
        "session_timeout": "15_min_inactivity",
        "regeneration": "new_session_after_auth"
      },
      "https": {
        "requirement": "all_traffic_encrypted",
        "implementation": "tls_1.3_minimum",
        "hsts_preload": "browser_enforced_https"
      }
    },
    "architecture_patterns": {
      "reverse_proxy": "hide_internal_servers",
      "cdn": "cache_static_ddos_protection",
      "load_balancer": "distribute_traffic_ssl_termination"
    }
  },
  "microservices_security": {
    "challenges": {
      "larger_attack_surface": "many_services_many_endpoints",
      "service_to_service": "internal_communication_security",
      "distributed_identity": "auth_across_services",
      "secret_management": "credentials_across_services"
    },
    "solutions": {
      "service_mesh": {
        "what": "infrastructure_layer_for_service_communication",
        "security_features": ["mtls", "authorization_policies", "observability"],
        "vendors": ["istio", "linkerd", "consul"]
      },
      "api_gateway": {
        "what": "entry_point_for_external_traffic",
        "security": "authentication_rate_limiting"
      },
      "secrets_management": {
        "what": "centralized_secrets_vault",
        "tools": ["hashicorp_vault", "aws_secrets_manager"],
        "injection": "sidecar_or_init_container"
      },
      "identity_propagation": {
        "what": "pass_user_context_through_services",
        "how": "jwt_token_in_header"
      }
    },
    "implementation": {
      "external_traffic": "api_gateway_authentication",
      "internal_traffic": "istio_mtls_authz_policies",
      "secrets": "vault_with_kubernetes_injection"
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 12 : Application Security Architecture - Modern Applications

**Concepts couverts** : 3.27.6.g (Serverless Security), 3.27.6.h (Mobile Application Security), 3.27.6.i (Legacy Application Security), 3.27.6.j (Third-Party Integration), 3.27.6.k (Runtime Protection), 3.27.6.l (Application Monitoring)

**Entrée JSON** :
```json
{
  "application_portfolio": {
    "serverless": "aws_lambda_functions_200",
    "mobile": "ios_android_banking_app",
    "legacy": "cobol_mainframe_core_banking",
    "integrations": "50_third_party_vendors"
  }
}
```

**Sortie attendue** :
```json
{
  "serverless_security": {
    "characteristics": {
      "ephemeral": "functions_short_lived",
      "event_driven": "triggered_by_events",
      "managed": "infrastructure_abstracted"
    },
    "security_challenges": {
      "shared_responsibility": "provider_manages_infrastructure_you_manage_code",
      "function_permissions": "iam_roles_for_functions",
      "event_injection": "malicious_event_data",
      "cold_start": "secrets_loading_timing"
    },
    "security_controls": {
      "least_privilege_iam": {
        "principle": "one_role_per_function_minimum_permissions",
        "anti_pattern": "star_permissions_shared_roles"
      },
      "event_validation": {
        "principle": "validate_all_event_data",
        "implementation": "schema_validation_input_sanitization"
      },
      "secrets_management": {
        "approach": "secrets_manager_not_env_vars",
        "caching": "cache_secrets_in_execution_context"
      },
      "dependencies": {
        "principle": "minimal_dependencies_scanned",
        "implementation": "sca_in_ci_cd_layer_analysis"
      },
      "monitoring": {
        "approach": "function_level_logging_tracing",
        "tools": ["cloudwatch", "x_ray", "datadog"]
      }
    },
    "tools": {
      "sast": "lambda_code_scanning",
      "runtime": ["aws_lambda_extensions", "aqua", "puresec"],
      "vulnerability": "snyk_lambda_scanning"
    }
  },
  "mobile_application_security": {
    "threats": {
      "reverse_engineering": "decompile_analyze_code",
      "tampering": "modify_app_behavior",
      "credential_theft": "extract_stored_credentials",
      "man_in_the_middle": "intercept_network_traffic",
      "malware": "malicious_apps_on_device"
    },
    "security_controls": {
      "code_protection": {
        "obfuscation": "make_reverse_engineering_harder",
        "anti_tamper": "detect_app_modification",
        "tools": ["proguard", "dexguard", "llvm_obfuscator"]
      },
      "secure_storage": {
        "ios": "keychain_for_sensitive_data",
        "android": "keystore_encrypted_shared_prefs",
        "never": "store_credentials_in_cleartext"
      },
      "network_security": {
        "certificate_pinning": "pin_server_certificate_in_app",
        "https_only": "no_http_traffic",
        "detection": "detect_ssl_interception"
      },
      "authentication": {
        "biometric": "fingerprint_face_id",
        "device_binding": "tie_auth_to_device",
        "session_management": "short_lived_tokens"
      },
      "runtime_protection": {
        "jailbreak_root_detection": "detect_compromised_device",
        "debugger_detection": "detect_debugging",
        "rasp": "runtime_application_self_protection"
      }
    },
    "owasp_mobile_top_10": {
      "m1": "improper_platform_usage",
      "m2": "insecure_data_storage",
      "m3": "insecure_communication",
      "m4": "insecure_authentication",
      "m5": "insufficient_cryptography"
    },
    "testing": {
      "sast": "mobile_code_scanning",
      "dast": "mobile_dynamic_testing",
      "pentest": "manual_mobile_pentest",
      "tools": ["mobsf", "frida", "objection"]
    }
  },
  "legacy_application_security": {
    "challenges": {
      "no_modern_auth": "password_only_no_sso",
      "vulnerable_components": "unsupported_frameworks",
      "no_encryption": "cleartext_protocols",
      "monolithic": "large_attack_surface"
    },
    "compensating_controls": {
      "network_isolation": {
        "approach": "segment_legacy_apps_restricted_access",
        "implementation": "dedicated_vlan_strict_firewall"
      },
      "waf_protection": {
        "approach": "waf_in_front_virtual_patching",
        "implementation": "rules_for_known_vulnerabilities"
      },
      "gateway_authentication": {
        "approach": "modern_auth_at_gateway_legacy_behind",
        "implementation": "sso_gateway_header_injection"
      },
      "monitoring": {
        "approach": "enhanced_monitoring_logging",
        "implementation": "siem_integration_anomaly_detection"
      },
      "access_control": {
        "approach": "strict_access_control_pam",
        "implementation": "privileged_access_only_audited"
      }
    },
    "modernization_path": {
      "short_term": "compensating_controls",
      "medium_term": "api_wrapper_strangler_pattern",
      "long_term": "rewrite_or_replace"
    },
    "cobol_mainframe": {
      "controls": {
        "racf": "mainframe_access_control",
        "encryption": "z_os_encryption",
        "monitoring": "smf_records_to_siem",
        "gateway": "api_gateway_for_external_access"
      }
    }
  },
  "third_party_integration": {
    "risks": {
      "data_exposure": "sharing_data_with_third_party",
      "api_security": "third_party_api_vulnerabilities",
      "supply_chain": "compromised_vendor",
      "compliance": "vendor_handling_regulated_data"
    },
    "security_controls": {
      "vendor_assessment": {
        "what": "evaluate_vendor_security",
        "how": ["questionnaire", "soc2_review", "pentest_results"],
        "ongoing": "annual_reassessment"
      },
      "api_security": {
        "outbound": "secure_api_calls_validation",
        "inbound": "validate_webhook_authenticity"
      },
      "data_minimization": {
        "principle": "share_only_necessary_data",
        "implementation": "data_mapping_per_integration"
      },
      "contracts": {
        "dpa": "data_processing_agreement",
        "sla": "security_requirements_in_sla",
        "audit_rights": "right_to_audit_vendor"
      },
      "monitoring": {
        "api_calls": "log_all_third_party_api_calls",
        "data_transfer": "dlp_on_outbound_data",
        "anomaly": "detect_unusual_patterns"
      }
    },
    "implementation": {
      "integration_gateway": "centralized_third_party_integration_point",
      "tokenization": "tokenize_before_sharing",
      "encryption": "encrypt_data_at_rest_in_transit"
    }
  },
  "runtime_protection": {
    "rasp": {
      "what": "Runtime Application Self-Protection",
      "how": "instrument_app_detect_block_attacks_runtime",
      "capabilities": {
        "injection_protection": "detect_block_sql_injection_runtime",
        "xss_protection": "detect_block_xss_runtime",
        "exploit_prevention": "detect_exploitation_attempts"
      },
      "deployment": "agent_in_application_runtime",
      "vendors": ["contrast", "hdiv", "signal_sciences"]
    },
    "waf_vs_rasp": {
      "waf": {
        "location": "network_perimeter",
        "visibility": "http_traffic_only",
        "context": "no_application_context"
      },
      "rasp": {
        "location": "inside_application",
        "visibility": "full_application_context",
        "context": "understands_app_behavior"
      },
      "recommendation": "use_both_defense_in_depth"
    },
    "virtual_patching": {
      "what": "block_exploit_without_code_change",
      "use_case": "vulnerability_discovered_patch_not_ready",
      "implementation": "waf_rule_or_rasp_rule"
    }
  },
  "application_monitoring": {
    "security_logging": {
      "what_to_log": {
        "authentication": "login_success_failure_mfa_events",
        "authorization": "access_granted_denied_privilege_changes",
        "data_access": "sensitive_data_access_modifications",
        "errors": "security_relevant_errors_exceptions",
        "admin": "administrative_actions_config_changes"
      },
      "format": {
        "structured": "json_format_parseable",
        "fields": ["timestamp", "user", "action", "resource", "outcome", "ip", "session"]
      },
      "protection": {
        "integrity": "tamper_evident_logging",
        "confidentiality": "mask_sensitive_data_in_logs",
        "availability": "centralized_secure_storage"
      }
    },
    "siem_integration": {
      "purpose": "centralized_analysis_correlation",
      "feeds": ["application_logs", "waf_logs", "api_gateway_logs"],
      "use_cases": ["attack_detection", "incident_investigation", "compliance"]
    },
    "anomaly_detection": {
      "behavioral": "baseline_normal_detect_deviation",
      "ml_based": "machine_learning_anomaly_detection",
      "alerts": {
        "impossible_travel": "user_logged_in_from_distant_locations",
        "unusual_access": "accessing_unusual_resources_times",
        "data_exfiltration": "unusual_data_download_patterns"
      }
    },
    "apm_security": {
      "distributed_tracing": "follow_request_across_services",
      "security_context": "add_security_events_to_traces",
      "correlation": "link_security_events_to_transactions",
      "tools": ["datadog", "dynatrace", "new_relic"]
    }
  }
}
```

**Barème** : 97/100

---

## RÉCAPITULATIF MODULE 3.27

**Module** : Security Architecture
**Concepts couverts** : 88/88 (100%)
**Exercices** : 12
**Note moyenne** : 97.5/100

### Distribution par sous-module :

| Sous-module | Concepts | Exercices | Couverture |
|-------------|----------|-----------|------------|
| 3.27.1 Security Architecture Fundamentals | 16 | Ex01-02 | 100% |
| 3.27.2 Zero Trust Deep Dive | 14 | Ex03-04 | 100% |
| 3.27.3 Network Security Architecture | 16 | Ex05-06 | 100% |
| 3.27.4 Identity & Access Architecture | 16 | Ex07-08 | 100% |
| 3.27.5 Data Security Architecture | 14 | Ex09-10 | 100% |
| 3.27.6 Application Security Architecture | 12 | Ex11-12 | 100% |

### Points forts :
- Frameworks d'architecture reconnus (SABSA, TOGAF, NIST CSF)
- Zero Trust complet de la théorie à l'implémentation
- Architecture réseau moderne (SASE, SD-WAN, microsegmentation)
- IAM enterprise avec CIAM et machine identity
- Data security avec classification et lifecycle complets
- AppSec couvrant moderne et legacy
