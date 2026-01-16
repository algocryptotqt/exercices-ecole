# PLAN MODULE 3.26 : DevSecOps

**Concepts totaux** : 80
**Exercices prévus** : 14
**Note moyenne cible** : >= 96/100

---

## TABLE DE COUVERTURE CONCEPTS → EXERCICES

| Sous-module | Concepts | Exercices couvrant |
|-------------|----------|-------------------|
| 3.26.1 Fondamentaux DevSecOps | a-n (14) | Ex01, Ex02 |
| 3.26.2 SAST | a-l (12) | Ex03, Ex04 |
| 3.26.3 DAST | a-l (12) | Ex05, Ex06 |
| 3.26.4 SCA | a-n (14) | Ex07, Ex08 |
| 3.26.5 Container/K8s/IaC Security | a-p (16) | Ex09, Ex10, Ex11 |
| 3.26.6 CI/CD Pipeline Security | a-l (12) | Ex12, Ex13, Ex14 |

---

## MATRICE DÉTAILLÉE

| Ex | Concepts couverts | Thème |
|----|-------------------|-------|
| 01 | 3.26.1: a,b,c,d,e,f,g | DevSecOps culture, shift-left/right, CI/CD |
| 02 | 3.26.1: h,i,j,k,l,m,n | Security stories, metrics, policy as code |
| 03 | 3.26.2: a,b,c,d,e,f | SAST tools, Semgrep, CodeQL, taint analysis |
| 04 | 3.26.2: g,h,i,j,k,l | SAST tuning, integration, limitations |
| 05 | 3.26.3: a,b,c,d,e,f | DAST tools, ZAP, Nuclei, API scanning |
| 06 | 3.26.3: g,h,i,j,k,l | DAST coverage, policies, remediation |
| 07 | 3.26.4: a,b,c,d,e,f,g | SCA tools, SBOM, vulnerability databases |
| 08 | 3.26.4: h,i,j,k,l,m,n | Dependencies, licenses, supply chain |
| 09 | 3.26.5: a,b,c,d,e,f | Container security, Kubernetes scanning |
| 10 | 3.26.5: g,h,i,j,k | Admission controllers, IaC, secrets |
| 11 | 3.26.5: l,m,n,o,p | Cloud posture, service mesh, supply chain |
| 12 | 3.26.6: a,b,c,d | Pipeline risks, hardening, GitHub Actions |
| 13 | 3.26.6: e,f,g,h | GitLab, Jenkins, signing, SLSA |
| 14 | 3.26.6: i,j,k,l | Branch protection, deployment, compliance |

---

## EXERCICE 01 : DevSecOps Culture & Pipeline Integration

**Concepts couverts** : 3.26.1.a (DevSecOps Definition), 3.26.1.b (Shift Left), 3.26.1.c (Shift Right), 3.26.1.d (CI/CD Pipeline), 3.26.1.e (Security Gates), 3.26.1.f (Security Champions), 3.26.1.g (Threat Modeling Agile)

**Contexte** : Une organisation veut transformer sa culture DevOps en DevSecOps en intégrant la sécurité tout au long du pipeline.

**Entrée JSON** :
```json
{
  "organization": {
    "current_state": "traditional_devops",
    "teams": {
      "dev": 50,
      "ops": 15,
      "security": 5
    },
    "pipeline": {
      "ci_tool": "jenkins",
      "cd_tool": "argocd",
      "vcs": "github",
      "artifact_registry": "artifactory"
    },
    "sdlc_phases": ["planning", "development", "testing", "staging", "production"],
    "current_security": {
      "when": "before_production",
      "method": "manual_pentest",
      "frequency": "quarterly"
    }
  },
  "transformation_goals": {
    "shift_left": true,
    "shift_right": true,
    "automation": "maximum",
    "developer_enablement": true
  },
  "new_project": {
    "name": "payment-service",
    "type": "microservice",
    "stack": "java_spring",
    "risk_level": "high",
    "compliance": ["PCI-DSS"]
  }
}
```

**Sortie attendue** :
```json
{
  "devsecops_transformation": {
    "definition_applied": {
      "core_principle": "security_integrated_not_bolted_on",
      "pillars": ["people", "process", "technology"],
      "culture_shift": "shared_security_responsibility"
    },
    "shift_left_implementation": {
      "phase_planning": {
        "activities": ["threat_modeling", "security_requirements", "abuse_cases"],
        "owner": "security_champion_with_dev_lead",
        "benefit": "catch_design_flaws_early"
      },
      "phase_development": {
        "activities": ["secure_coding_training", "ide_security_plugins", "pre_commit_hooks"],
        "tools": ["semgrep_ide", "gitleaks_pre_commit"],
        "benefit": "prevent_vulnerabilities_at_source"
      },
      "phase_build": {
        "activities": ["sast_scan", "sca_scan", "secret_detection"],
        "blocking": true,
        "benefit": "no_vulnerable_code_merged"
      },
      "cost_savings": "fixing_in_dev_100x_cheaper_than_production"
    },
    "shift_right_implementation": {
      "phase_staging": {
        "activities": ["dast_scan", "penetration_test_automated"],
        "environment": "production_mirror"
      },
      "phase_production": {
        "activities": ["runtime_protection", "waf", "rasp", "security_monitoring"],
        "tools": ["falco", "waf", "siem_integration"]
      },
      "continuous": {
        "vulnerability_scanning": "container_images_in_registry",
        "chaos_engineering": "security_game_days",
        "threat_detection": "real_time_alerting"
      },
      "benefit": "detect_runtime_attacks_zero_days"
    }
  },
  "pipeline_integration": {
    "ci_cd_security_stages": [
      {
        "stage": "pre_commit",
        "tools": ["gitleaks", "semgrep_local"],
        "blocking": false,
        "owner": "developer"
      },
      {
        "stage": "commit",
        "tools": ["branch_protection", "signed_commits"],
        "blocking": true,
        "owner": "vcs"
      },
      {
        "stage": "build",
        "tools": ["sast_full", "sca", "secret_scan", "sbom_generation"],
        "blocking": true,
        "owner": "ci_jenkins"
      },
      {
        "stage": "test",
        "tools": ["security_unit_tests", "dependency_check"],
        "blocking": true,
        "owner": "ci_jenkins"
      },
      {
        "stage": "staging_deploy",
        "tools": ["image_scan", "iac_scan", "dast"],
        "blocking": "critical_high",
        "owner": "ci_jenkins"
      },
      {
        "stage": "approval",
        "tools": ["security_gate_review", "compliance_check"],
        "blocking": true,
        "owner": "security_team"
      },
      {
        "stage": "production_deploy",
        "tools": ["signed_artifact_verify", "canary_deploy"],
        "blocking": true,
        "owner": "cd_argocd"
      },
      {
        "stage": "runtime",
        "tools": ["falco", "waf", "siem"],
        "blocking": false,
        "owner": "ops_security"
      }
    ]
  },
  "security_gates": {
    "design": {
      "gate_type": "advisory",
      "criteria": ["threat_model_reviewed", "security_requirements_defined"],
      "enforcement": "pr_checklist"
    },
    "build": {
      "gate_type": "blocking",
      "criteria": {
        "sast": "no_critical_high",
        "sca": "no_critical_known_exploited",
        "secrets": "zero_secrets"
      },
      "enforcement": "jenkins_pipeline_fail"
    },
    "staging": {
      "gate_type": "blocking_critical",
      "criteria": {
        "dast": "no_critical",
        "image_scan": "no_critical"
      },
      "enforcement": "promotion_blocked"
    },
    "production": {
      "gate_type": "blocking",
      "criteria": ["signed_artifact", "compliance_check_passed", "security_approval"],
      "enforcement": "argocd_sync_policy"
    }
  },
  "security_champions_program": {
    "structure": {
      "ratio": "1_champion_per_team",
      "total_needed": 8,
      "recruitment": "volunteer_plus_nomination"
    },
    "responsibilities": [
      "threat_modeling_facilitation",
      "code_review_security_focus",
      "security_tool_training",
      "vulnerability_triage_liaison",
      "security_culture_advocate"
    ],
    "training": {
      "initial": "40_hours_secure_coding_threat_modeling",
      "ongoing": "monthly_security_sessions",
      "certification": "encouraged_not_required"
    },
    "support": {
      "dedicated_time": "20_percent",
      "security_team_backing": "escalation_path",
      "tooling_access": "full_security_tooling"
    },
    "metrics": ["vulnerabilities_prevented", "training_delivered", "threat_models_completed"]
  },
  "threat_modeling_agile": {
    "approach": "lightweight_iterative",
    "when": {
      "new_feature": "threat_model_story",
      "architecture_change": "dedicated_session",
      "sprint_planning": "abuse_case_review"
    },
    "method": {
      "primary": "STRIDE_per_feature",
      "tools": ["threat_dragon", "draw_io", "whiteboard"],
      "time_boxed": "1_hour_max"
    },
    "artifacts": {
      "output": ["threat_list", "mitigations", "security_stories"],
      "storage": "wiki_linked_to_epic"
    },
    "payment_service_example": {
      "feature": "card_tokenization",
      "threats_identified": [
        {"threat": "token_theft", "stride": "information_disclosure", "mitigation": "encryption_at_rest"},
        {"threat": "replay_attack", "stride": "spoofing", "mitigation": "one_time_tokens"},
        {"threat": "bypass_validation", "stride": "tampering", "mitigation": "server_side_validation"}
      ],
      "security_stories_created": 3
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (7 concepts DevSecOps fondamentaux)
- Intelligence pédagogique : 24/25 (transformation complète)
- Originalité : 19/20 (approche culturelle + technique)
- Testabilité : 14/15 (structures vérifiables)
- Clarté : 15/15 (workflow clair)

---

## EXERCICE 02 : Security Metrics & Policy as Code

**Concepts couverts** : 3.26.1.h (Security User Stories), 3.26.1.i (Definition of Done), 3.26.1.j (Security Debt), 3.26.1.k (Metrics DevSecOps), 3.26.1.l (Guardrails vs Gates), 3.26.1.m (Policy as Code), 3.26.1.n (GitOps Security)

**Entrée JSON** :
```json
{
  "organization": {
    "devsecops_maturity": "intermediate",
    "teams": 10,
    "applications": 45,
    "vulnerabilities_backlog": 350
  },
  "current_metrics": {
    "mttr_vulnerabilities_days": 45,
    "vulnerability_escape_rate": "15%",
    "scan_coverage": "60%",
    "security_debt_unknown": true
  },
  "sprint_context": {
    "sprint_number": 42,
    "team": "payments",
    "features": [
      {"name": "express_checkout", "risk": "high"},
      {"name": "order_history", "risk": "low"}
    ]
  },
  "policy_requirements": {
    "container_policies": ["no_root", "approved_base_images", "no_secrets"],
    "deployment_policies": ["signed_images", "resource_limits", "network_policies"],
    "enforcement": "automated"
  }
}
```

**Sortie attendue** :
```json
{
  "security_user_stories": {
    "feature_express_checkout": {
      "functional_story": "As a customer, I want to save my payment method for faster checkout",
      "abuse_cases": [
        {
          "story": "As an attacker, I want to steal saved payment tokens to make fraudulent purchases",
          "acceptance_criteria_security": [
            "Tokens encrypted at rest with AES-256",
            "Token access requires re-authentication",
            "Token usage logged and monitored"
          ]
        },
        {
          "story": "As an attacker, I want to enumerate valid payment methods via timing attacks",
          "acceptance_criteria_security": [
            "Constant-time comparison for token validation",
            "Rate limiting on payment method API"
          ]
        }
      ],
      "security_stories_derived": [
        {
          "story": "Implement token encryption at rest",
          "points": 3,
          "acceptance_criteria": ["AES-256 encryption", "Key rotation support", "HSM integration"]
        },
        {
          "story": "Add re-authentication for token access",
          "points": 2,
          "acceptance_criteria": ["Step-up auth flow", "Session validation"]
        }
      ]
    },
    "integration_with_backlog": {
      "security_stories_percentage": "20%_of_sprint_capacity",
      "prioritization": "risk_based"
    }
  },
  "definition_of_done_security": {
    "code_level": [
      "SAST scan passed (no critical/high)",
      "SCA scan passed (no critical CVEs)",
      "No hardcoded secrets",
      "Security unit tests written",
      "Code review by security champion"
    ],
    "feature_level": [
      "Threat model updated",
      "Security acceptance criteria met",
      "DAST scan passed (staging)",
      "Security documentation updated"
    ],
    "release_level": [
      "Penetration test completed (if applicable)",
      "Security sign-off obtained",
      "Runbook includes security procedures"
    ],
    "enforcement": {
      "jira_workflow": "security_checklist_mandatory",
      "pr_template": "security_section_required",
      "pipeline": "automated_checks"
    }
  },
  "security_debt_management": {
    "current_state_analysis": {
      "total_vulnerabilities": 350,
      "critical": 15,
      "high": 85,
      "medium": 150,
      "low": 100,
      "debt_score": "high"
    },
    "categorization": {
      "by_age": {
        "over_90_days": {"count": 120, "action": "immediate_attention"},
        "30_90_days": {"count": 130, "action": "sprint_allocation"},
        "under_30_days": {"count": 100, "action": "normal_flow"}
      },
      "by_type": {
        "code_vulnerabilities": 150,
        "dependency_vulnerabilities": 180,
        "infrastructure_misconfigs": 20
      }
    },
    "sprint_allocation": {
      "rule": "20_percent_capacity_to_security_debt",
      "sprint_42_allocation": {
        "stories": [
          {"vuln_id": "VULN-123", "type": "sast", "age_days": 95, "points": 3},
          {"vuln_id": "VULN-456", "type": "sca_critical", "age_days": 45, "points": 5}
        ],
        "total_points": 8
      }
    },
    "tracking": {
      "dashboard": "security_debt_burndown",
      "trend": "target_reduce_20_percent_quarter",
      "reporting": "monthly_to_leadership"
    }
  },
  "devsecops_metrics": {
    "lead_metrics": {
      "scan_coverage": {
        "current": "60%",
        "target": "95%",
        "measurement": "apps_with_full_sast_sca_dast"
      },
      "security_training_completion": {
        "current": "45%",
        "target": "90%",
        "measurement": "developers_completed_secure_coding"
      },
      "threat_model_coverage": {
        "current": "30%",
        "target": "80%",
        "measurement": "features_with_threat_model"
      }
    },
    "lag_metrics": {
      "mttr_critical": {
        "current": "45_days",
        "target": "7_days",
        "measurement": "time_from_discovery_to_fix"
      },
      "vulnerability_escape_rate": {
        "current": "15%",
        "target": "5%",
        "measurement": "vulns_found_in_prod_vs_total"
      },
      "security_incidents": {
        "current": 5,
        "target": 0,
        "measurement": "security_incidents_quarter"
      }
    },
    "process_metrics": {
      "security_gate_pass_rate": {
        "current": "70%",
        "target": "90%",
        "meaning": "builds_passing_first_time"
      },
      "fix_rate": {
        "current": "60%",
        "target": "90%",
        "measurement": "vulns_fixed_within_sla"
      }
    },
    "dashboard_design": {
      "executive_view": ["escape_rate", "mttr", "debt_trend"],
      "team_view": ["scan_coverage", "gate_pass_rate", "sprint_debt_allocation"],
      "tool": "grafana_or_datadog"
    }
  },
  "guardrails_vs_gates": {
    "guardrails": {
      "definition": "guide_without_blocking",
      "examples": [
        {
          "guardrail": "ide_security_warnings",
          "behavior": "highlight_issues_developer_decides",
          "purpose": "education_awareness"
        },
        {
          "guardrail": "advisory_sast_on_pr",
          "behavior": "comment_on_pr_not_block",
          "purpose": "early_feedback"
        },
        {
          "guardrail": "security_linting",
          "behavior": "suggestions_not_errors",
          "purpose": "best_practices"
        }
      ],
      "when_to_use": "low_risk_educational_early_stages"
    },
    "gates": {
      "definition": "hard_stops_blocking",
      "examples": [
        {
          "gate": "critical_vulnerability_block",
          "behavior": "pipeline_fails_no_deploy",
          "purpose": "prevent_critical_risk"
        },
        {
          "gate": "secret_detection_block",
          "behavior": "commit_rejected",
          "purpose": "prevent_credential_exposure"
        },
        {
          "gate": "unsigned_image_block",
          "behavior": "deployment_rejected",
          "purpose": "supply_chain_integrity"
        }
      ],
      "when_to_use": "high_risk_compliance_critical"
    },
    "balance_strategy": {
      "principle": "guardrails_early_gates_late",
      "maturity_progression": "start_guardrails_add_gates_as_team_matures",
      "velocity_consideration": "too_many_gates_slows_delivery"
    }
  },
  "policy_as_code": {
    "framework": "open_policy_agent",
    "policies": {
      "container_security": {
        "policy_file": "container_policy.rego",
        "rules": [
          {
            "rule": "deny_root_user",
            "rego": "deny[msg] { input.spec.containers[_].securityContext.runAsUser == 0; msg := \"Containers must not run as root\" }"
          },
          {
            "rule": "require_approved_base_image",
            "rego": "deny[msg] { not startswith(input.spec.containers[_].image, \"approved-registry/\"); msg := \"Must use approved base images\" }"
          },
          {
            "rule": "no_secrets_in_env",
            "rego": "deny[msg] { contains(lower(input.spec.containers[_].env[_].name), \"password\"); msg := \"No secrets in environment variables\" }"
          }
        ]
      },
      "deployment_security": {
        "policy_file": "deployment_policy.rego",
        "rules": [
          {
            "rule": "require_resource_limits",
            "rego": "deny[msg] { not input.spec.containers[_].resources.limits; msg := \"Resource limits required\" }"
          },
          {
            "rule": "require_network_policy",
            "rego": "deny[msg] { not network_policy_exists; msg := \"NetworkPolicy required for namespace\" }"
          }
        ]
      }
    },
    "enforcement": {
      "admission_controller": "gatekeeper",
      "ci_check": "conftest_in_pipeline",
      "drift_detection": "opa_audit_mode"
    },
    "versioning": {
      "storage": "git_policies_repo",
      "review": "pr_required",
      "testing": "policy_unit_tests"
    }
  },
  "gitops_security": {
    "tool": "argocd",
    "security_configuration": {
      "rbac": {
        "teams": {
          "dev": ["view", "sync_staging"],
          "security": ["view", "override_gates"],
          "ops": ["full_access"]
        },
        "sso_integration": "okta"
      },
      "secrets_handling": {
        "method": "sealed_secrets",
        "encryption": "asymmetric_cluster_key",
        "storage": "encrypted_in_git"
      },
      "image_verification": {
        "cosign": true,
        "policy": "reject_unsigned"
      }
    },
    "audit_trail": {
      "git_history": "full_change_log",
      "argocd_audit": "all_syncs_logged",
      "compliance": "soc2_evidence"
    },
    "benefits": [
      "declarative_security_state",
      "version_controlled_config",
      "audit_trail_built_in",
      "rollback_capability"
    ]
  }
}
```

**Barème** : 98/100
- Pertinence conceptuelle : 25/25 (7 concepts métriques/policy)
- Intelligence pédagogique : 25/25 (framework complet)
- Originalité : 19/20 (OPA intégré)
- Testabilité : 14/15 (policies exécutables)
- Clarté : 15/15 (métriques claires)

---

## EXERCICE 03 : SAST Implementation & Tool Integration

**Concepts couverts** : 3.26.2.a (SAST Definition), 3.26.2.b (SAST Tools), 3.26.2.c (Semgrep), 3.26.2.d (CodeQL), 3.26.2.e (SonarQube), 3.26.2.f (Taint Analysis)

**Entrée JSON** :
```json
{
  "codebase": {
    "language": "python",
    "framework": "flask",
    "lines_of_code": 50000,
    "repositories": 5,
    "ci_system": "github_actions"
  },
  "sample_code": {
    "file": "app/api/users.py",
    "vulnerabilities_present": [
      "sql_injection",
      "command_injection",
      "path_traversal",
      "hardcoded_secret"
    ]
  },
  "requirements": {
    "integration": "ci_cd",
    "false_positive_tolerance": "low",
    "custom_rules": true
  }
}
```

**Sortie attendue** :
```json
{
  "sast_definition": {
    "what": "Static Application Security Testing",
    "how": "analyze_source_code_without_execution",
    "approach": "white_box_full_code_visibility",
    "timing": "development_build_phase",
    "coverage": "entire_codebase_paths_not_executed"
  },
  "tools_comparison": {
    "commercial": {
      "checkmarx": {"strength": "enterprise_coverage", "cost": "high", "accuracy": "high"},
      "fortify": {"strength": "language_depth", "cost": "high", "accuracy": "high"},
      "veracode": {"strength": "saas_convenience", "cost": "medium_high", "accuracy": "high"}
    },
    "open_source": {
      "semgrep": {"strength": "developer_friendly_custom_rules", "cost": "free", "accuracy": "medium_high"},
      "bandit": {"strength": "python_specific_fast", "cost": "free", "accuracy": "medium"},
      "codeql": {"strength": "deep_analysis_variant_finding", "cost": "free_github", "accuracy": "high"}
    },
    "recommendation": {
      "primary": "semgrep",
      "secondary": "codeql",
      "rationale": "cost_effective_customizable_accurate"
    }
  },
  "semgrep_implementation": {
    "configuration": {
      "config_file": ".semgrep.yml",
      "config": {
        "rules": [
          "p/python",
          "p/flask",
          "p/security-audit",
          "p/owasp-top-ten"
        ]
      }
    },
    "custom_rules": {
      "sql_injection_flask": {
        "rule": {
          "id": "flask-sql-injection",
          "pattern": "db.execute($QUERY)",
          "pattern-not": "db.execute($QUERY, $PARAMS)",
          "message": "Potential SQL injection: use parameterized queries",
          "severity": "ERROR",
          "languages": ["python"]
        }
      },
      "command_injection": {
        "rule": {
          "id": "command-injection",
          "pattern-either": [
            {"pattern": "os.system(...)"},
            {"pattern": "subprocess.call(..., shell=True, ...)"}
          ],
          "message": "Potential command injection",
          "severity": "ERROR"
        }
      }
    },
    "ci_integration": {
      "github_action": {
        "name": "Semgrep SAST",
        "on": ["push", "pull_request"],
        "jobs": {
          "semgrep": {
            "runs-on": "ubuntu-latest",
            "steps": [
              {"uses": "returntocorp/semgrep-action@v1"},
              {"with": {"config": ".semgrep.yml"}}
            ]
          }
        }
      }
    },
    "findings_on_sample": [
      {
        "rule": "flask-sql-injection",
        "file": "app/api/users.py",
        "line": 45,
        "code": "db.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
        "severity": "critical"
      }
    ]
  },
  "codeql_implementation": {
    "setup": {
      "database_creation": "codeql database create python-db --language=python",
      "query_packs": ["codeql/python-queries"]
    },
    "variant_analysis": {
      "use_case": "find_all_sql_injection_variants",
      "query": "import python\nimport semmle.python.security.dataflow.SqlInjectionQuery\n\nfrom SqlInjectionConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink\nwhere cfg.hasFlowPath(source, sink)\nselect sink, source, sink, \"SQL injection from $@\", source, \"user input\""
    },
    "github_integration": {
      "code_scanning": "enabled",
      "sarif_upload": "automatic",
      "alerts": "pr_checks"
    },
    "taint_tracking": {
      "sources": ["request.args", "request.form", "request.json"],
      "sinks": ["db.execute", "os.system", "open"],
      "sanitizers": ["escape", "quote", "validate"]
    }
  },
  "sonarqube_implementation": {
    "setup": {
      "scanner": "sonar-scanner",
      "project_config": {
        "sonar.projectKey": "payment-service",
        "sonar.sources": "app/",
        "sonar.python.coverage.reportPaths": "coverage.xml"
      }
    },
    "quality_gates": {
      "security_hotspots": "0_critical",
      "vulnerabilities": "0_blocker_critical",
      "security_rating": "A",
      "coverage": "80_percent_minimum"
    },
    "integration": {
      "ci": "run_on_every_pr",
      "quality_gate_check": "block_merge_if_failed",
      "developer_feedback": "inline_comments"
    }
  },
  "taint_analysis_explained": {
    "concept": {
      "source": "untrusted_input_entry_point",
      "sink": "dangerous_function_security_sensitive",
      "propagation": "data_flow_through_code",
      "sanitizer": "function_that_neutralizes_threat"
    },
    "example_flow": {
      "source": "request.args.get('id')",
      "propagation": ["user_id = request.args.get('id')", "query = f\"SELECT * FROM users WHERE id = {user_id}\""],
      "sink": "db.execute(query)",
      "vulnerability": "sql_injection",
      "fix": {
        "sanitizer": "db.execute(\"SELECT * FROM users WHERE id = ?\", [user_id])",
        "explanation": "parameterized_query_breaks_taint_flow"
      }
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 04 : SAST Tuning & Pipeline Optimization

**Concepts couverts** : 3.26.2.g (False Positives SAST), 3.26.2.h (Custom Rules), 3.26.2.i (IDE Integration), 3.26.2.j (CI Integration), 3.26.2.k (Baseline Management), 3.26.2.l (SAST Limitations)

**Entrée JSON** :
```json
{
  "current_sast_state": {
    "tool": "semgrep",
    "total_findings": 450,
    "confirmed_vulnerabilities": 85,
    "false_positive_rate": "81%",
    "developer_trust": "low"
  },
  "pipeline_issues": {
    "scan_time": "25_minutes",
    "blocking_builds": "60%",
    "developer_complaints": ["too_slow", "too_many_fp", "no_context"]
  },
  "legacy_codebase": {
    "existing_issues": 350,
    "new_code_rate": "5000_lines_month"
  }
}
```

**Sortie attendue** :
```json
{
  "false_positive_reduction": {
    "analysis": {
      "fp_categories": [
        {"type": "framework_specific", "count": 150, "example": "flask_template_not_xss"},
        {"type": "validation_not_recognized", "count": 100, "example": "custom_sanitizer"},
        {"type": "dead_code_paths", "count": 80, "example": "test_files"},
        {"type": "rule_too_generic", "count": 35, "example": "any_string_concat"}
      ]
    },
    "strategies": {
      "suppress_test_files": {
        "action": "exclude tests/ from scan",
        "impact": "reduce_80_findings"
      },
      "custom_sanitizers": {
        "action": "add sanitizer patterns to rules",
        "semgrep_config": {
          "pattern-not-inside": "validate_input(...)"
        },
        "impact": "reduce_100_findings"
      },
      "framework_specific_rules": {
        "action": "use flask-specific rulesets only",
        "impact": "reduce_50_findings"
      },
      "tune_severity": {
        "action": "focus on critical/high only initially",
        "impact": "reduce_noise_improve_trust"
      }
    },
    "suppression_workflow": {
      "inline": "# nosemgrep: rule-id (reason)",
      "config_file": ".semgrepignore",
      "review": "security_team_approves_suppressions"
    }
  },
  "custom_rules_development": {
    "organization_specific": [
      {
        "name": "internal-api-auth",
        "purpose": "ensure all internal APIs check authentication",
        "pattern": {
          "pattern": "@app.route(...)\ndef $FUNC(...):\n  ...",
          "pattern-not": "@app.route(...)\ndef $FUNC(...):\n  auth.require_login()\n  ..."
        }
      },
      {
        "name": "logging-sensitive-data",
        "purpose": "prevent logging of PII fields",
        "pattern": {
          "pattern-either": [
            {"pattern": "logger.info(..., $VAR, ...)"},
            {"pattern": "print(..., $VAR, ...)"}
          ],
          "metavariable-regex": {"metavariable": "$VAR", "regex": "(password|ssn|credit_card)"}
        }
      }
    ],
    "development_process": {
      "write": "security_team",
      "test": "unit_test_with_vulnerable_samples",
      "review": "pr_review",
      "deploy": "add_to_ci_config"
    }
  },
  "ide_integration": {
    "benefits": [
      "immediate_feedback",
      "developer_education",
      "fix_before_commit",
      "maximum_shift_left"
    ],
    "setup": {
      "vscode": {
        "extension": "Semgrep",
        "config": {
          "semgrep.trace.server": "verbose",
          "semgrep.scan": "onType"
        }
      },
      "intellij": {
        "plugin": "Semgrep",
        "settings": "same_rules_as_ci"
      }
    },
    "developer_experience": {
      "inline_highlights": true,
      "quick_fixes": "when_available",
      "documentation_links": true
    }
  },
  "ci_integration_optimization": {
    "current_problems": {
      "slow_scan": "25_minutes",
      "blocking_too_often": "60%_builds_fail"
    },
    "solutions": {
      "incremental_scanning": {
        "approach": "scan_only_changed_files",
        "implementation": "git diff --name-only | xargs semgrep",
        "time_reduction": "25min -> 3min"
      },
      "parallel_execution": {
        "approach": "split_by_directory",
        "jobs": 4,
        "time_reduction": "25min -> 7min_full"
      },
      "cache_dependencies": {
        "approach": "cache semgrep rules between runs",
        "implementation": "actions/cache"
      },
      "severity_tiers": {
        "pr_check": "critical_high_only_blocking",
        "scheduled": "all_severities_nightly"
      }
    },
    "optimized_pipeline": {
      "pr_workflow": {
        "trigger": "pull_request",
        "scan": "incremental_critical_high",
        "blocking": true,
        "time": "3_minutes"
      },
      "main_workflow": {
        "trigger": "push_to_main",
        "scan": "full_all_severities",
        "blocking": false,
        "time": "10_minutes"
      }
    }
  },
  "baseline_management": {
    "problem": "350_existing_issues_overwhelming",
    "solution": {
      "baseline_file": ".semgrep-baseline.json",
      "creation": "semgrep --config=auto --json > .semgrep-baseline.json",
      "usage": "semgrep --baseline-commit=HEAD~1"
    },
    "workflow": {
      "existing_issues": "tracked_separately_security_debt",
      "new_issues": "must_fix_before_merge",
      "gradual_reduction": "fix_10_legacy_issues_per_sprint"
    },
    "reporting": {
      "new_vulnerabilities": "pr_blocking",
      "total_debt": "dashboard_tracking",
      "trend": "should_decrease_over_time"
    }
  },
  "sast_limitations": {
    "cannot_detect": [
      {
        "limitation": "runtime_configuration",
        "example": "database connection string from environment",
        "mitigation": "config_scanning_separate"
      },
      {
        "limitation": "authentication_logic_flaws",
        "example": "weak password policy",
        "mitigation": "security_code_review"
      },
      {
        "limitation": "business_logic_vulnerabilities",
        "example": "price_manipulation",
        "mitigation": "threat_modeling_manual_review"
      },
      {
        "limitation": "third_party_code",
        "example": "vulnerable_library",
        "mitigation": "sca_tool"
      },
      {
        "limitation": "infrastructure_misconfig",
        "example": "open_s3_bucket",
        "mitigation": "iac_scanning"
      }
    ],
    "compensating_controls": {
      "complement_with": ["dast", "sca", "iac_scan", "manual_review", "pentesting"]
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 05 : DAST Implementation - Tools & API Scanning

**Concepts couverts** : 3.26.3.a (DAST Definition), 3.26.3.b (DAST Tools), 3.26.3.c (OWASP ZAP), 3.26.3.d (Nuclei), 3.26.3.e (Authenticated Scanning), 3.26.3.f (API Scanning)

**Contexte** : Une équipe DevSecOps doit intégrer le DAST dans leur pipeline pour tester une application e-commerce avec API REST et frontend.

**Entrée JSON** :
```json
{
  "application": {
    "name": "ecommerce-platform",
    "type": "web_api_combined",
    "urls": {
      "frontend": "https://staging.shop.example.com",
      "api": "https://api.staging.shop.example.com"
    },
    "authentication": {
      "type": "oauth2",
      "login_url": "/auth/login",
      "token_endpoint": "/oauth/token"
    },
    "api_spec": "openapi_3.0",
    "sensitive_endpoints": ["/users", "/orders", "/payments"]
  },
  "requirements": {
    "scan_frequency": "per_deployment",
    "environments": ["staging", "pre-prod"],
    "api_coverage": "complete",
    "budget": "open_source_preferred"
  }
}
```

**Sortie attendue** :
```json
{
  "dast_definition": {
    "what": "Dynamic Application Security Testing",
    "approach": "black_box_outside_in",
    "execution": "testing_running_application",
    "contrast_with_sast": {
      "sast": "analyzes_code_at_rest_white_box",
      "dast": "attacks_live_app_black_box"
    },
    "detects": [
      "runtime_vulnerabilities",
      "authentication_flaws",
      "session_management_issues",
      "server_misconfigurations",
      "injection_at_runtime"
    ],
    "timing": "staging_pre_production"
  },
  "tools_selection": {
    "commercial": {
      "burp_enterprise": {
        "strength": "comprehensive_enterprise_orchestration",
        "cost": "high",
        "best_for": "large_enterprise_complex_apps"
      },
      "invicti_netsparker": {
        "strength": "proof_based_scanning_low_fp",
        "cost": "medium_high",
        "best_for": "accuracy_focused_teams"
      },
      "qualys_was": {
        "strength": "cloud_native_vuln_management_integration",
        "cost": "medium",
        "best_for": "existing_qualys_customers"
      }
    },
    "open_source": {
      "owasp_zap": {
        "strength": "full_featured_free_api_automation",
        "cost": "free",
        "best_for": "ci_integration_api_testing"
      },
      "nuclei": {
        "strength": "template_based_fast_community",
        "cost": "free",
        "best_for": "vulnerability_validation_custom_checks"
      }
    },
    "recommendation": {
      "primary": "owasp_zap",
      "secondary": "nuclei",
      "rationale": "complementary_coverage_budget_friendly"
    }
  },
  "owasp_zap_implementation": {
    "setup": {
      "mode": "daemon_api",
      "command": "zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=<API_KEY>",
      "docker": "docker run -u zap -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon"
    },
    "scan_types": {
      "passive_scan": {
        "description": "observe_traffic_no_attacks",
        "use_case": "ci_fast_feedback",
        "findings": ["information_disclosure", "missing_headers", "cookies_issues"]
      },
      "active_scan": {
        "description": "attack_payloads_exploitation_attempt",
        "use_case": "staging_scheduled",
        "findings": ["sql_injection", "xss", "command_injection", "path_traversal"]
      },
      "ajax_spider": {
        "description": "javascript_rendering_spa_crawling",
        "use_case": "modern_frontend_applications"
      }
    },
    "api_automation": {
      "python_example": {
        "setup_context": "target = 'https://staging.shop.example.com'",
        "start_spider": "zap.spider.scan(target)",
        "wait_spider": "while int(zap.spider.status()) < 100: time.sleep(1)",
        "start_active": "zap.ascan.scan(target)",
        "get_alerts": "alerts = zap.core.alerts(baseurl=target)"
      }
    },
    "ci_integration": {
      "github_action": {
        "name": "ZAP DAST Scan",
        "steps": [
          {
            "name": "ZAP Baseline Scan",
            "uses": "zaproxy/action-baseline@v0.7.0",
            "with": {
              "target": "https://staging.shop.example.com",
              "rules_file_name": ".zap/rules.tsv",
              "cmd_options": "-I"
            }
          }
        ]
      }
    }
  },
  "nuclei_implementation": {
    "strengths": {
      "template_based": "yaml_templates_easy_customize",
      "speed": "concurrent_requests_fast_scanning",
      "community": "thousands_community_templates",
      "ci_friendly": "exit_codes_json_output"
    },
    "setup": {
      "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
      "update_templates": "nuclei -ut"
    },
    "template_categories": {
      "cves": "known_vulnerability_checks",
      "misconfigurations": "service_misconfig_detection",
      "exposures": "sensitive_data_exposure",
      "default_logins": "default_credential_checks"
    },
    "custom_template": {
      "name": "check-payment-api-auth",
      "template": {
        "id": "payment-api-unauthorized",
        "info": {
          "name": "Payment API Unauthorized Access",
          "severity": "critical"
        },
        "requests": [
          {
            "method": "GET",
            "path": ["/api/payments"],
            "matchers": [
              {"type": "status", "status": [200]},
              {"type": "word", "words": ["payment_id", "amount"]}
            ]
          }
        ]
      }
    },
    "ci_command": "nuclei -u https://api.staging.shop.example.com -t custom/ -severity critical,high -json -o results.json"
  },
  "authenticated_scanning": {
    "importance": "80_percent_more_coverage_vs_unauthenticated",
    "zap_authentication": {
      "form_based": {
        "login_url": "/auth/login",
        "username_field": "email",
        "password_field": "password",
        "logged_in_indicator": "\\QLogout\\E"
      },
      "oauth2_setup": {
        "approach": "script_based_authentication",
        "script": {
          "type": "authentication",
          "steps": [
            "get_authorization_code",
            "exchange_for_token",
            "set_authorization_header"
          ]
        }
      },
      "session_management": {
        "type": "cookie_based",
        "session_token": "session_id"
      }
    },
    "nuclei_authentication": {
      "header_based": "-H 'Authorization: Bearer <TOKEN>'",
      "cookie_based": "-H 'Cookie: session=<SESSION_ID>'"
    },
    "token_refresh": {
      "strategy": "refresh_before_expiry",
      "implementation": "pre_scan_token_fetch_script"
    }
  },
  "api_scanning": {
    "openapi_import": {
      "zap": {
        "command": "zap.openapi.importUrl(api_spec_url)",
        "benefit": "automatic_endpoint_discovery"
      },
      "nuclei": {
        "tool": "openapi-nuclei",
        "conversion": "generate_templates_from_openapi"
      }
    },
    "api_specific_tests": [
      {
        "test": "bola_idor",
        "description": "broken_object_level_authorization",
        "method": "parameter_tampering_id_values"
      },
      {
        "test": "bfla",
        "description": "broken_function_level_authorization",
        "method": "access_admin_endpoints_with_user_token"
      },
      {
        "test": "mass_assignment",
        "description": "unexpected_parameter_injection",
        "method": "add_role_admin_to_user_update"
      },
      {
        "test": "rate_limiting",
        "description": "brute_force_protection",
        "method": "rapid_requests_same_endpoint"
      }
    ],
    "graphql_support": {
      "introspection": "discover_schema_if_enabled",
      "mutations_fuzzing": "test_all_mutations",
      "tool": "graphql-cop_or_zap_graphql_addon"
    }
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25 (6 concepts DAST fondamentaux)
- Intelligence pédagogique : 24/25 (implémentation pratique)
- Originalité : 19/20 (ZAP + Nuclei combinés)
- Testabilité : 14/15 (configurations vérifiables)
- Clarté : 15/15 (workflow clair)

---

## EXERCICE 06 : DAST Operations - Coverage, Policies & Remediation

**Concepts couverts** : 3.26.3.g (Crawling & Coverage), 3.26.3.h (Scan Policies), 3.26.3.i (CI/CD Integration DAST), 3.26.3.j (False Positive Handling), 3.26.3.k (Remediation Workflow), 3.26.3.l (DAST Limitations)

**Entrée JSON** :
```json
{
  "scan_results": {
    "application": "ecommerce-platform",
    "total_findings": 85,
    "by_severity": {
      "critical": 3,
      "high": 12,
      "medium": 35,
      "low": 35
    },
    "coverage": {
      "urls_discovered": 150,
      "urls_scanned": 120,
      "gap_reason": "javascript_rendering"
    }
  },
  "team_context": {
    "release_frequency": "weekly",
    "security_team_size": 2,
    "developer_teams": 5,
    "current_remediation_time": "30_days_average"
  }
}
```

**Sortie attendue** :
```json
{
  "crawling_coverage_optimization": {
    "coverage_gap_analysis": {
      "current": "80%_urls_scanned",
      "gap_reasons": [
        {
          "reason": "javascript_spa_content",
          "impact": "dynamic_pages_missed",
          "solution": "ajax_spider_headless_browser"
        },
        {
          "reason": "form_submission_required",
          "impact": "post_authentication_pages",
          "solution": "form_handler_configuration"
        },
        {
          "reason": "deep_linking",
          "impact": "urls_beyond_depth_limit",
          "solution": "increase_max_depth_seed_urls"
        }
      ]
    },
    "optimization_strategies": {
      "ajax_spider": {
        "config": {
          "browser": "firefox_headless",
          "max_duration": "60_minutes",
          "max_crawl_depth": 10,
          "event_wait": 1000
        },
        "benefit": "javascript_rendered_content_discovered"
      },
      "seed_urls": {
        "approach": "provide_sitemap_or_url_list",
        "sources": ["sitemap.xml", "openapi_spec", "manual_critical_urls"],
        "impact": "ensure_critical_paths_scanned"
      },
      "context_configuration": {
        "include_patterns": ["https://staging.shop.example.com.*"],
        "exclude_patterns": [".*logout.*", ".*static.*", ".*assets.*"]
      }
    },
    "coverage_metrics": {
      "target": "95%_discovered_urls_scanned",
      "tracking": "coverage_report_per_scan",
      "trending": "week_over_week_comparison"
    }
  },
  "scan_policies": {
    "policy_types": {
      "ci_quick": {
        "purpose": "fast_feedback_per_pr",
        "scan_type": "passive_only",
        "duration": "5_minutes",
        "checks": ["headers", "cookies", "info_disclosure"],
        "blocking": false
      },
      "staging_standard": {
        "purpose": "per_deployment_validation",
        "scan_type": "passive_plus_safe_active",
        "duration": "30_minutes",
        "checks": ["owasp_top_10_safe"],
        "blocking": "critical_high"
      },
      "full_comprehensive": {
        "purpose": "weekly_scheduled_deep_scan",
        "scan_type": "full_active",
        "duration": "4_hours",
        "checks": ["all_checks_maximum_depth"],
        "blocking": false,
        "review": "security_team"
      }
    },
    "zap_policy_configuration": {
      "policy_file": "scan-policy.policy",
      "disable_dangerous": ["dos_tests", "buffer_overflow"],
      "threshold_adjustment": {
        "sql_injection": "low_threshold_high_strength",
        "xss": "medium_threshold_medium_strength"
      }
    },
    "environment_mapping": {
      "pr_check": "ci_quick",
      "staging_deploy": "staging_standard",
      "pre_prod": "full_comprehensive"
    }
  },
  "ci_cd_integration": {
    "pipeline_design": {
      "trigger": "post_deployment_staging",
      "pre_requisite": "application_healthy_check",
      "scan_execution": {
        "containerized": true,
        "image": "owasp/zap2docker-stable",
        "network": "staging_network_access"
      }
    },
    "dynamic_environment": {
      "approach": "ephemeral_staging_per_pr",
      "workflow": [
        "deploy_pr_environment",
        "wait_healthy",
        "run_dast_scan",
        "collect_results",
        "teardown_environment"
      ]
    },
    "github_actions_full": {
      "name": "DAST Pipeline",
      "jobs": {
        "deploy_staging": {
          "steps": ["checkout", "build", "deploy_to_staging", "health_check"]
        },
        "dast_scan": {
          "needs": "deploy_staging",
          "steps": [
            {
              "name": "ZAP Full Scan",
              "uses": "zaproxy/action-full-scan@v0.4.0",
              "with": {
                "target": "${{ env.STAGING_URL }}",
                "rules_file_name": ".zap/rules.tsv",
                "issue_title": "DAST Scan Report",
                "fail_action": "true"
              }
            }
          ]
        },
        "process_results": {
          "needs": "dast_scan",
          "steps": ["parse_sarif", "create_issues", "notify_team"]
        }
      }
    },
    "result_handling": {
      "sarif_upload": "github_code_scanning",
      "issue_creation": "critical_high_automatic",
      "dashboard_update": "security_metrics_grafana"
    }
  },
  "false_positive_handling": {
    "triage_workflow": {
      "step_1_automated": {
        "action": "rule_based_filtering",
        "criteria": ["known_fp_patterns", "baseline_comparison"]
      },
      "step_2_verification": {
        "action": "manual_verification_critical_high",
        "who": "security_engineer",
        "evidence": "reproduce_with_burp_curl"
      },
      "step_3_classification": {
        "options": ["true_positive", "false_positive", "acceptable_risk"]
      }
    },
    "fp_suppression": {
      "zap_rules_file": {
        "format": "tsv",
        "example": "10021\tIGNORE\t(X-Content-Type-Options Header Missing)",
        "location": ".zap/rules.tsv"
      },
      "per_url_suppression": {
        "pattern": "specific_url_rule_combination",
        "review_required": true
      }
    },
    "fp_tracking": {
      "database": "security_findings_db",
      "fields": ["finding_id", "classification", "justification", "reviewer"],
      "periodic_review": "quarterly_reassessment"
    },
    "metrics": {
      "fp_rate": "track_over_time",
      "target": "below_15_percent",
      "improvement": "tune_rules_add_context"
    }
  },
  "remediation_workflow": {
    "integration_jira": {
      "auto_create": "critical_high_findings",
      "template": {
        "summary": "[DAST] {finding_name} in {url}",
        "description": "Evidence: {evidence}\nReproduction: {curl_command}",
        "labels": ["security", "dast", "severity-{severity}"],
        "assignee": "component_owner_mapping"
      }
    },
    "sla_by_severity": {
      "critical": "24_hours",
      "high": "7_days",
      "medium": "30_days",
      "low": "90_days_or_backlog"
    },
    "developer_enablement": {
      "fix_guidance": "link_to_remediation_docs",
      "office_hours": "weekly_security_qa",
      "training": "owasp_top_10_course"
    },
    "verification": {
      "fix_deployed": "auto_rescan_specific_urls",
      "regression": "add_to_baseline_check"
    }
  },
  "dast_limitations": {
    "coverage_limitations": [
      {
        "limitation": "crawl_dependent",
        "explanation": "only_tests_discovered_endpoints",
        "mitigation": "api_spec_import_seed_urls"
      },
      {
        "limitation": "authentication_complexity",
        "explanation": "mfa_captcha_difficult_automate",
        "mitigation": "api_token_auth_bypass_ui"
      },
      {
        "limitation": "stateful_flows",
        "explanation": "multi_step_business_logic_hard",
        "mitigation": "recorded_sequences_or_api_tests"
      }
    ],
    "detection_limitations": [
      {
        "limitation": "no_source_code_context",
        "explanation": "cannot_trace_root_cause",
        "mitigation": "correlate_with_sast"
      },
      {
        "limitation": "business_logic_blind",
        "explanation": "cannot_detect_price_manipulation",
        "mitigation": "manual_testing_threat_modeling"
      },
      {
        "limitation": "time_consuming",
        "explanation": "full_scan_takes_hours",
        "mitigation": "tiered_policies_scheduled_scans"
      }
    ],
    "complementary_testing": {
      "sast": "code_level_vulnerabilities",
      "iast": "runtime_with_code_context",
      "manual_pentest": "business_logic_complex_auth"
    }
  }
}
```

**Barème** : 96/100

---

## EXERCICE 07 : SCA Fundamentals - Tools & SBOM

**Concepts couverts** : 3.26.4.a (SCA Definition), 3.26.4.b (SCA Tools), 3.26.4.c (Dependency-Check), 3.26.4.d (Snyk), 3.26.4.e (Trivy), 3.26.4.f (SBOM), 3.26.4.g (Vulnerability Databases)

**Entrée JSON** :
```json
{
  "project": {
    "name": "financial-api",
    "language": "java",
    "build_tool": "maven",
    "dependencies": {
      "direct": 45,
      "total_with_transitive": 320
    },
    "compliance": ["SOC2", "PCI-DSS"]
  },
  "current_state": {
    "sca_tool": "none",
    "known_vulnerabilities": "unknown",
    "sbom": "not_generated"
  }
}
```

**Sortie attendue** :
```json
{
  "sca_definition": {
    "what": "Software Composition Analysis",
    "purpose": [
      "identify_open_source_components",
      "detect_known_vulnerabilities",
      "track_licenses",
      "manage_supply_chain_risk"
    ],
    "approach": "analyze_dependencies_manifest_lockfiles",
    "importance": {
      "statistic": "80_percent_code_is_open_source",
      "risk": "one_vulnerable_dependency_compromises_all"
    }
  },
  "tools_comparison": {
    "commercial": {
      "snyk": {
        "strengths": ["developer_ux", "fix_prs", "container_iac", "broad_coverage"],
        "pricing": "free_tier_plus_paid",
        "best_for": "developer_first_organizations"
      },
      "black_duck": {
        "strengths": ["enterprise", "license_compliance", "audit_support"],
        "pricing": "enterprise",
        "best_for": "large_enterprises_ma"
      },
      "mend_whitesource": {
        "strengths": ["prioritization", "remediation_advice", "policies"],
        "pricing": "enterprise",
        "best_for": "policy_driven_organizations"
      }
    },
    "open_source": {
      "owasp_dependency_check": {
        "strengths": ["free", "nvd_matching", "ci_integration", "mature"],
        "limitations": ["slower", "higher_fp", "less_context"]
      },
      "trivy": {
        "strengths": ["fast", "multi_target", "container_native", "sbom"],
        "limitations": ["newer", "less_remediation_guidance"]
      }
    },
    "recommendation_financial_api": {
      "primary": "trivy",
      "secondary": "snyk_free_tier",
      "rationale": "speed_plus_accuracy_budget_conscious"
    }
  },
  "dependency_check_implementation": {
    "setup_maven": {
      "plugin": {
        "groupId": "org.owasp",
        "artifactId": "dependency-check-maven",
        "version": "8.4.0"
      },
      "configuration": {
        "failBuildOnCVSS": 7,
        "format": ["HTML", "JSON", "SARIF"],
        "nvdApiKey": "${NVD_API_KEY}"
      }
    },
    "execution": "mvn dependency-check:check",
    "ci_integration": {
      "github_action": {
        "step": {
          "name": "OWASP Dependency Check",
          "run": "mvn dependency-check:check -DfailBuildOnCVSS=7"
        }
      }
    },
    "output": {
      "report_location": "target/dependency-check-report.html",
      "sarif_for_github": "target/dependency-check-report.sarif"
    }
  },
  "snyk_implementation": {
    "setup": {
      "install": "npm install -g snyk",
      "auth": "snyk auth"
    },
    "commands": {
      "test": "snyk test --severity-threshold=high",
      "monitor": "snyk monitor",
      "fix": "snyk fix"
    },
    "ci_integration": {
      "github_action": {
        "uses": "snyk/actions/maven@master",
        "with": {
          "command": "test",
          "args": "--severity-threshold=high"
        },
        "env": {
          "SNYK_TOKEN": "${{ secrets.SNYK_TOKEN }}"
        }
      }
    },
    "fix_pr_feature": {
      "description": "automatic_pr_with_upgrade",
      "benefits": ["one_click_fix", "test_compatibility", "changelog"]
    }
  },
  "trivy_implementation": {
    "installation": "brew install trivy",
    "scan_modes": {
      "filesystem": "trivy fs --severity HIGH,CRITICAL .",
      "repository": "trivy repo https://github.com/org/financial-api",
      "sbom": "trivy fs --format spdx-json -o sbom.json ."
    },
    "configuration": {
      "trivy_yaml": {
        "severity": ["CRITICAL", "HIGH"],
        "vuln-type": ["os", "library"],
        "ignore-unfixed": true,
        "exit-code": 1
      }
    },
    "ci_integration": {
      "github_action": {
        "uses": "aquasecurity/trivy-action@master",
        "with": {
          "scan-type": "fs",
          "scan-ref": ".",
          "format": "sarif",
          "output": "trivy-results.sarif",
          "severity": "CRITICAL,HIGH"
        }
      }
    }
  },
  "sbom_generation": {
    "what": "Software Bill of Materials",
    "purpose": [
      "complete_dependency_inventory",
      "supply_chain_transparency",
      "compliance_requirement",
      "vulnerability_tracking"
    ],
    "formats": {
      "spdx": {
        "standard": "ISO_standard",
        "use_case": "compliance_legal"
      },
      "cyclonedx": {
        "standard": "OWASP_specification",
        "use_case": "security_focused_vuln_tracking"
      }
    },
    "generation_tools": {
      "trivy": "trivy fs --format cyclonedx -o sbom.json .",
      "syft": "syft packages dir:. -o cyclonedx-json > sbom.json",
      "cyclonedx_maven": "mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom"
    },
    "contents": {
      "components": ["name", "version", "supplier", "licenses", "purl"],
      "relationships": "dependency_tree",
      "metadata": ["tool_used", "timestamp", "authors"]
    },
    "compliance_drivers": {
      "executive_order_14028": "us_federal_requirement",
      "pci_dss_4": "software_inventory_required",
      "eu_cra": "upcoming_eu_requirement"
    },
    "storage_sharing": {
      "artifact_registry": "attach_to_release",
      "dependency_track": "centralized_sbom_management"
    }
  },
  "vulnerability_databases": {
    "primary_sources": {
      "nvd": {
        "name": "National Vulnerability Database",
        "coverage": "cve_comprehensive",
        "update": "hourly",
        "access": "free_api_key_recommended"
      },
      "github_advisory": {
        "name": "GitHub Advisory Database",
        "coverage": "open_source_packages",
        "update": "continuous",
        "access": "free"
      }
    },
    "vendor_specific": {
      "snyk_db": "curated_prioritized_proprietary",
      "osv": "open_source_vulnerabilities_aggregator"
    },
    "aggregation": {
      "strategy": "multi_source_correlation",
      "benefit": "comprehensive_coverage_reduced_gaps"
    },
    "matching": {
      "cpe": "common_platform_enumeration",
      "purl": "package_url_standard",
      "challenges": ["name_variations", "version_ranges"]
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 08 : SCA Advanced - Dependencies, Licenses & Supply Chain

**Concepts couverts** : 3.26.4.h (Transitive Dependencies), 3.26.4.i (License Compliance), 3.26.4.j (Remediation), 3.26.4.k (Dependency Pinning), 3.26.4.l (Private Registries), 3.26.4.m (Dependency Confusion), 3.26.4.n (CI Integration SCA)

**Entrée JSON** :
```json
{
  "scan_results": {
    "project": "financial-api",
    "vulnerabilities": {
      "critical": [
        {"package": "log4j-core", "version": "2.14.1", "cve": "CVE-2021-44228", "type": "transitive", "depth": 3}
      ],
      "high": [
        {"package": "spring-web", "version": "5.3.8", "cve": "CVE-2022-22965", "type": "direct"}
      ]
    },
    "license_issues": [
      {"package": "gpl-library", "license": "GPL-3.0", "conflict": "proprietary_product"}
    ]
  },
  "organizational_context": {
    "product_type": "commercial_saas",
    "registry": "internal_nexus",
    "package_namespaces": ["com.company.internal"]
  }
}
```

**Sortie attendue** :
```json
{
  "transitive_dependency_analysis": {
    "problem": {
      "log4j_example": {
        "vulnerability": "CVE-2021-44228_Log4Shell",
        "direct_dependency": "spring-boot-starter",
        "path": ["spring-boot-starter", "spring-boot-starter-logging", "log4j-core"],
        "depth": 3,
        "visibility": "hidden_without_sca_tool"
      }
    },
    "risks": [
      "hidden_vulnerabilities",
      "unexpected_updates",
      "version_conflicts",
      "large_attack_surface"
    ],
    "visualization": {
      "command": "mvn dependency:tree",
      "tools": ["snyk", "dependency-check", "trivy"]
    },
    "management_strategies": {
      "override": {
        "maven": {
          "dependencyManagement": {
            "groupId": "org.apache.logging.log4j",
            "artifactId": "log4j-core",
            "version": "2.17.1"
          }
        }
      },
      "exclude": {
        "maven": {
          "exclusions": {
            "groupId": "org.apache.logging.log4j",
            "artifactId": "log4j-core"
          }
        }
      }
    }
  },
  "license_compliance": {
    "license_categories": {
      "permissive": {
        "licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"],
        "commercial_use": "allowed",
        "obligations": "attribution"
      },
      "copyleft_weak": {
        "licenses": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"],
        "commercial_use": "allowed_with_conditions",
        "obligations": "share_modifications_to_library"
      },
      "copyleft_strong": {
        "licenses": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
        "commercial_use": "requires_source_disclosure",
        "obligations": "share_entire_derivative_work"
      }
    },
    "policy_for_commercial_saas": {
      "allowed": ["MIT", "Apache-2.0", "BSD", "ISC"],
      "review_required": ["LGPL", "MPL"],
      "blocked": ["GPL", "AGPL"],
      "enforcement": "ci_gate_block_on_violation"
    },
    "detection_resolution": {
      "gpl_library_issue": {
        "finding": "gpl-library uses GPL-3.0",
        "risk": "must_open_source_entire_product",
        "resolution_options": [
          "find_alternative_library_permissive",
          "isolate_in_separate_service",
          "obtain_commercial_license"
        ],
        "recommended": "replace_with_mit_alternative"
      }
    },
    "tooling": {
      "fossa": "comprehensive_license_compliance",
      "licensee": "github_license_detection",
      "trivy_license": "trivy fs --scanners license ."
    }
  },
  "remediation_strategies": {
    "upgrade_path_analysis": {
      "spring_web_cve": {
        "current": "5.3.8",
        "fixed_in": "5.3.18",
        "breaking_changes": "none_minor_version",
        "recommendation": "upgrade_safe"
      },
      "log4j_cve": {
        "current": "2.14.1",
        "fixed_in": "2.17.1",
        "breaking_changes": "minor_api_changes",
        "recommendation": "upgrade_with_testing"
      }
    },
    "remediation_options": {
      "upgrade": {
        "when": "fix_available_compatible",
        "action": "bump_version",
        "testing": "run_full_test_suite"
      },
      "workaround": {
        "when": "no_fix_or_breaking",
        "example": "log4j2.formatMsgNoLookups=true",
        "tracking": "security_debt_with_deadline"
      },
      "replace": {
        "when": "unmaintained_or_license_issue",
        "action": "find_alternative_library",
        "effort": "high_code_changes_required"
      }
    },
    "prioritization": {
      "factors": ["cvss_score", "exploitability", "exposure", "data_sensitivity"],
      "matrix": {
        "critical_exploited_internet": "immediate",
        "critical_not_exploited": "24_hours",
        "high_internal": "7_days"
      }
    }
  },
  "dependency_pinning": {
    "importance": [
      "reproducible_builds",
      "prevent_supply_chain_attacks",
      "controlled_updates"
    ],
    "implementation": {
      "maven": {
        "lockfile": "maven-dependency-lock-plugin",
        "exact_versions": "never_use_ranges"
      },
      "npm": {
        "lockfile": "package-lock.json",
        "command": "npm ci (not npm install)",
        "integrity": "sha512_checksums"
      },
      "python": {
        "lockfile": "Pipfile.lock or poetry.lock",
        "command": "pipenv sync or poetry install"
      }
    },
    "update_strategy": {
      "dependabot": "automated_pr_per_update",
      "renovate": "grouped_updates_scheduling",
      "manual": "monthly_security_review"
    }
  },
  "private_registry_security": {
    "nexus_configuration": {
      "proxy_repos": {
        "maven_central_proxy": "cache_public_packages",
        "npm_proxy": "cache_npm_packages"
      },
      "hosted_repos": {
        "internal_releases": "com.company.internal.*",
        "internal_snapshots": "internal_development"
      },
      "security_features": {
        "vulnerability_scanning": "nexus_iq_or_xray",
        "policy_enforcement": "block_vulnerable_downloads",
        "audit_logging": "all_downloads_tracked"
      }
    },
    "namespace_protection": {
      "reserved_namespaces": ["com.company.*", "@company/*"],
      "enforcement": "only_internal_publish_allowed"
    }
  },
  "dependency_confusion_prevention": {
    "attack_explained": {
      "technique": "publish_public_package_same_name_as_internal",
      "exploitation": "build_tool_prefers_public_higher_version",
      "impact": "malicious_code_execution_in_build"
    },
    "prevention_measures": {
      "namespace_reservation": {
        "npm": "register_@company_scope_publicly",
        "maven": "own_com.company_namespace",
        "pypi": "register_company_prefix"
      },
      "registry_configuration": {
        "npm": {
          "npmrc": "@company:registry=https://nexus.internal/npm/",
          "scope_mapping": "internal_scope_to_private_registry"
        },
        "maven": {
          "settings_xml": "mirror_all_to_nexus",
          "repository_order": "internal_first"
        }
      },
      "build_verification": {
        "checksums": "verify_package_integrity",
        "provenance": "verify_package_source"
      }
    }
  },
  "ci_integration_complete": {
    "pipeline_stages": {
      "pr_check": {
        "tool": "trivy",
        "command": "trivy fs --exit-code 1 --severity CRITICAL,HIGH .",
        "blocking": true,
        "purpose": "prevent_new_vulnerabilities"
      },
      "sbom_generation": {
        "tool": "syft",
        "command": "syft packages dir:. -o cyclonedx-json > sbom.json",
        "artifact": "attach_to_release"
      },
      "license_check": {
        "tool": "trivy",
        "command": "trivy fs --scanners license --severity UNKNOWN,HIGH .",
        "blocking": true
      },
      "dependency_track_upload": {
        "purpose": "centralized_vulnerability_management",
        "command": "upload_sbom_to_dependency_track"
      }
    },
    "thresholds": {
      "vulnerabilities": {
        "critical": 0,
        "high": 0,
        "medium": "warning_only"
      },
      "licenses": {
        "blocked": ["GPL-3.0", "AGPL-3.0"],
        "review": ["LGPL"]
      }
    },
    "reporting": {
      "sarif": "github_code_scanning",
      "dashboard": "dependency_track_grafana"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 09 : Container & Kubernetes Security Scanning

**Concepts couverts** : 3.26.5.a (Container Image Scanning), 3.26.5.b (Dockerfile Security), 3.26.5.c (Base Image Selection), 3.26.5.d (Runtime Security), 3.26.5.e (Kubernetes Security), 3.26.5.f (Kubernetes Scanning)

**Entrée JSON** :
```json
{
  "container_environment": {
    "registry": "gcr.io/company-prod",
    "kubernetes": "gke",
    "namespaces": ["production", "staging"],
    "images": [
      {"name": "api-service", "base": "ubuntu:20.04", "size": "850MB"},
      {"name": "worker", "base": "python:3.9", "size": "1.2GB"}
    ]
  },
  "current_security": {
    "image_scanning": "none",
    "dockerfile_review": "manual",
    "runtime_protection": "none"
  }
}
```

**Sortie attendue** :
```json
{
  "container_image_scanning": {
    "strategy": {
      "when": ["build_time", "registry_push", "runtime_continuous"],
      "what": ["os_packages", "application_libraries", "misconfigurations"]
    },
    "tools": {
      "trivy": {
        "command": "trivy image gcr.io/company-prod/api-service:latest",
        "features": ["vuln_scan", "config_scan", "secret_scan", "sbom"],
        "ci_integration": "native_github_gitlab"
      },
      "clair": {
        "approach": "registry_integrated",
        "features": ["layer_analysis", "notification_api"],
        "deployment": "with_quay_or_standalone"
      },
      "anchore": {
        "approach": "policy_based",
        "features": ["custom_policies", "compliance_checks", "sbom"],
        "deployment": "enterprise_or_grype_cli"
      }
    },
    "implementation": {
      "build_time": {
        "github_action": {
          "uses": "aquasecurity/trivy-action@master",
          "with": {
            "image-ref": "${{ env.IMAGE }}",
            "format": "sarif",
            "severity": "CRITICAL,HIGH",
            "exit-code": 1
          }
        }
      },
      "registry": {
        "gcr": "container_analysis_enabled",
        "ecr": "ecr_image_scanning",
        "harbor": "trivy_integrated"
      },
      "runtime": {
        "continuous_scan": "every_24h_registry_images",
        "alert": "new_cve_affects_running_image"
      }
    },
    "scan_results_api_service": {
      "os_vulnerabilities": {
        "critical": 5,
        "high": 23,
        "source": "ubuntu_20.04_packages"
      },
      "recommendation": "switch_to_distroless_or_alpine"
    }
  },
  "dockerfile_security": {
    "best_practices": {
      "non_root_user": {
        "bad": "# Running as root (default)",
        "good": "USER 1000:1000",
        "rationale": "limit_container_escape_impact"
      },
      "minimal_base": {
        "bad": "FROM ubuntu:20.04",
        "good": "FROM gcr.io/distroless/java:11",
        "rationale": "reduce_attack_surface"
      },
      "multi_stage_build": {
        "example": {
          "stage1": "FROM maven:3.8 AS build\nRUN mvn package",
          "stage2": "FROM gcr.io/distroless/java:11\nCOPY --from=build target/app.jar /"
        },
        "rationale": "no_build_tools_in_final_image"
      },
      "no_secrets": {
        "bad": "ENV DB_PASSWORD=secret123",
        "good": "# Use secrets manager at runtime",
        "rationale": "secrets_in_layers_persist"
      },
      "specific_versions": {
        "bad": "FROM python:latest",
        "good": "FROM python:3.11.4-slim@sha256:abc...",
        "rationale": "reproducible_secure_builds"
      }
    },
    "scanning_tools": {
      "hadolint": {
        "command": "hadolint Dockerfile",
        "ci_integration": "hadolint/hadolint-action",
        "rules": "dl3000_series_security"
      },
      "trivy_config": {
        "command": "trivy config .",
        "checks": ["dockerfile", "kubernetes", "terraform"]
      }
    },
    "remediated_dockerfile": {
      "api_service": [
        "FROM maven:3.9-eclipse-temurin-17 AS build",
        "WORKDIR /app",
        "COPY pom.xml .",
        "RUN mvn dependency:go-offline",
        "COPY src ./src",
        "RUN mvn package -DskipTests",
        "",
        "FROM gcr.io/distroless/java17-debian11",
        "WORKDIR /app",
        "COPY --from=build /app/target/api-service.jar .",
        "USER 1000:1000",
        "EXPOSE 8080",
        "ENTRYPOINT [\"java\", \"-jar\", \"api-service.jar\"]"
      ]
    }
  },
  "base_image_selection": {
    "options_comparison": {
      "distroless": {
        "size": "~20MB",
        "packages": "language_runtime_only",
        "shell": "none",
        "security": "minimal_attack_surface",
        "debugging": "difficult",
        "best_for": "production_final_images"
      },
      "alpine": {
        "size": "~5MB",
        "packages": "musl_busybox",
        "shell": "yes",
        "security": "small_fast_updates",
        "debugging": "possible",
        "caveat": "musl_compatibility_issues"
      },
      "slim_variants": {
        "size": "~50-100MB",
        "packages": "minimal_debian_ubuntu",
        "shell": "yes",
        "security": "reduced_vs_full",
        "best_for": "need_shell_glibc"
      }
    },
    "recommendation_matrix": {
      "java_production": "distroless/java",
      "python_production": "python:slim or distroless",
      "node_production": "node:alpine or distroless",
      "debug_needed": "slim_variant"
    },
    "update_strategy": {
      "frequency": "weekly_base_image_updates",
      "automation": "renovate_or_dependabot",
      "testing": "integration_tests_post_update"
    }
  },
  "runtime_security": {
    "falco": {
      "what": "runtime_threat_detection",
      "how": "syscall_monitoring_rules",
      "deployment": "daemonset_on_kubernetes",
      "rules_examples": [
        {
          "name": "shell_spawned_in_container",
          "condition": "container and proc.name in (bash, sh)",
          "output": "Shell spawned (container=%container.name command=%proc.cmdline)"
        },
        {
          "name": "sensitive_file_read",
          "condition": "open_read and fd.name startswith /etc/shadow",
          "output": "Sensitive file read (file=%fd.name proc=%proc.name)"
        }
      ],
      "alerting": "slack_pagerduty_siem"
    },
    "runtime_policies": {
      "read_only_rootfs": {
        "kubernetes": "securityContext.readOnlyRootFilesystem: true",
        "benefit": "prevent_persistent_malware"
      },
      "drop_capabilities": {
        "kubernetes": "securityContext.capabilities.drop: [ALL]",
        "benefit": "limit_kernel_interactions"
      },
      "seccomp": {
        "kubernetes": "securityContext.seccompProfile.type: RuntimeDefault",
        "benefit": "restrict_syscalls"
      }
    },
    "drift_detection": {
      "concept": "alert_on_changes_vs_image",
      "detects": ["new_processes", "new_files", "config_changes"],
      "tools": ["falco", "sysdig", "aqua"]
    }
  },
  "kubernetes_security": {
    "rbac": {
      "principle": "least_privilege",
      "implementation": {
        "service_accounts": "unique_per_workload",
        "roles": "namespace_scoped_preferred",
        "cluster_roles": "minimal_cluster_wide"
      },
      "audit": "rbac-police or krane"
    },
    "network_policies": {
      "default_deny": {
        "policy": {
          "kind": "NetworkPolicy",
          "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"]
          }
        },
        "effect": "block_all_then_allowlist"
      },
      "allow_specific": {
        "example": "allow_api_to_database_only"
      }
    },
    "pod_security_standards": {
      "levels": {
        "privileged": "unrestricted_not_for_production",
        "baseline": "minimal_restrictions",
        "restricted": "hardened_best_practices"
      },
      "enforcement": "pod_security_admission_controller",
      "recommendation": "restricted_for_production"
    },
    "secrets_management": {
      "problem": "kubernetes_secrets_base64_not_encrypted",
      "solutions": {
        "external_secrets_operator": "sync_from_vault_aws_secrets",
        "sealed_secrets": "encrypted_in_git",
        "csi_secrets_store": "mount_from_vault"
      }
    }
  },
  "kubernetes_scanning": {
    "kube_bench": {
      "what": "cis_kubernetes_benchmark",
      "command": "kube-bench run --targets node,master",
      "checks": ["api_server", "etcd", "scheduler", "kubelet"],
      "ci_integration": "scheduled_job"
    },
    "kube_hunter": {
      "what": "penetration_testing_kubernetes",
      "modes": ["remote", "internal", "network"],
      "finds": ["exposed_dashboards", "privileged_pods", "token_leaks"]
    },
    "kubeaudit": {
      "what": "manifest_security_audit",
      "checks": ["privileged", "rootfs", "capabilities", "limits"],
      "command": "kubeaudit all -f deployment.yaml"
    },
    "ci_pipeline": {
      "pre_deploy": "kubeaudit manifests",
      "post_deploy": "kube-bench scheduled",
      "continuous": "falco runtime"
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 10 : IaC Security & Admission Control

**Concepts couverts** : 3.26.5.g (Admission Controllers), 3.26.5.h (IaC Security), 3.26.5.i (IaC Scanning Tools), 3.26.5.j (Policy as Code OPA), 3.26.5.k (Secret Detection)

**Entrée JSON** :
```json
{
  "infrastructure": {
    "iac_tool": "terraform",
    "cloud": "aws",
    "modules": 25,
    "resources": 150
  },
  "kubernetes": {
    "cluster": "eks",
    "admission_control": "none",
    "namespaces": 10
  },
  "git_repositories": 15,
  "secret_management": "manual"
}
```

**Sortie attendue** :
```json
{
  "admission_controllers": {
    "concept": {
      "what": "intercept_kubernetes_api_requests",
      "when": "before_persistence",
      "types": {
        "mutating": "modify_requests",
        "validating": "accept_or_reject"
      }
    },
    "opa_gatekeeper": {
      "what": "policy_enforcement_kubernetes",
      "architecture": {
        "constraint_templates": "define_policy_schema",
        "constraints": "apply_policy_to_resources"
      },
      "installation": "helm install gatekeeper gatekeeper/gatekeeper",
      "example_policies": {
        "require_labels": {
          "template": {
            "apiVersion": "templates.gatekeeper.sh/v1",
            "kind": "ConstraintTemplate",
            "metadata": {"name": "k8srequiredlabels"},
            "spec": {
              "crd": {
                "spec": {
                  "names": {"kind": "K8sRequiredLabels"},
                  "validation": {"properties": {"labels": {"type": "array"}}}
                }
              },
              "targets": [{
                "target": "admission.k8s.gatekeeper.sh",
                "rego": "violation[{\"msg\": msg}] { provided := input.review.object.metadata.labels; required := input.parameters.labels[_]; not provided[required]; msg := sprintf(\"Missing label: %v\", [required]) }"
              }]
            }
          },
          "constraint": {
            "apiVersion": "constraints.gatekeeper.sh/v1beta1",
            "kind": "K8sRequiredLabels",
            "spec": {
              "match": {"kinds": [{"apiGroups": [""], "kinds": ["Pod"]}]},
              "parameters": {"labels": ["app", "owner"]}
            }
          }
        },
        "block_privileged": {
          "rego": "violation[{\"msg\": msg}] { c := input.review.object.spec.containers[_]; c.securityContext.privileged; msg := \"Privileged containers not allowed\" }"
        }
      }
    },
    "kyverno": {
      "what": "kubernetes_native_policy_engine",
      "advantage": "yaml_based_no_rego",
      "example": {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {"name": "disallow-latest-tag"},
        "spec": {
          "validationFailureAction": "enforce",
          "rules": [{
            "name": "require-image-tag",
            "match": {"resources": {"kinds": ["Pod"]}},
            "validate": {
              "message": "Image tag 'latest' not allowed",
              "pattern": {"spec": {"containers": [{"image": "!*:latest"}]}}
            }
          }]
        }
      }
    },
    "image_verification": {
      "cosign_integration": {
        "gatekeeper": "custom_policy_verify_signature",
        "kyverno": "verifyImages_rule_native"
      },
      "policy": "reject_unsigned_images"
    }
  },
  "iac_security": {
    "risks": [
      "misconfigured_resources",
      "exposed_services",
      "overly_permissive_iam",
      "unencrypted_storage",
      "default_credentials"
    ],
    "terraform_specific": {
      "state_security": {
        "risk": "state_contains_secrets_cleartext",
        "mitigation": "encrypted_remote_backend_s3_gcs"
      },
      "provider_credentials": {
        "risk": "credentials_in_tf_files",
        "mitigation": "environment_variables_iam_roles"
      }
    },
    "shift_left_approach": {
      "ide": "realtime_scanning",
      "pre_commit": "block_insecure_commits",
      "ci": "fail_pipeline_on_issues",
      "plan": "analyze_plan_output"
    }
  },
  "iac_scanning_tools": {
    "checkov": {
      "supported": ["terraform", "cloudformation", "kubernetes", "dockerfile"],
      "command": "checkov -d . --framework terraform",
      "features": {
        "custom_policies": "yaml_or_python",
        "sarif_output": "github_integration",
        "fix_suggestions": "some_auto_remediation"
      },
      "ci_integration": {
        "github_action": {
          "uses": "bridgecrewio/checkov-action@master",
          "with": {
            "directory": ".",
            "framework": "terraform",
            "soft_fail": false
          }
        }
      }
    },
    "tfsec": {
      "focus": "terraform_specific_deep",
      "command": "tfsec .",
      "features": ["custom_checks", "ci_friendly", "ide_plugins"],
      "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    },
    "kics": {
      "supported": ["terraform", "cloudformation", "ansible", "kubernetes", "docker"],
      "command": "kics scan -p . -o results/",
      "features": ["owasp_top_10_iac", "query_library", "rego_custom"]
    },
    "comparison": {
      "breadth": "checkov_kics",
      "terraform_depth": "tfsec",
      "kubernetes_focus": "checkov_kubeaudit"
    }
  },
  "policy_as_code_opa": {
    "rego_language": {
      "what": "declarative_policy_language",
      "structure": {
        "package": "namespace",
        "rules": "boolean_conditions",
        "functions": "reusable_logic"
      }
    },
    "terraform_integration": {
      "conftest": {
        "what": "test_structured_data_with_opa",
        "command": "conftest test tfplan.json",
        "example_policy": {
          "file": "policy/terraform.rego",
          "content": "package main\n\ndeny[msg] {\n  resource := input.resource_changes[_]\n  resource.type == \"aws_s3_bucket\"\n  not resource.change.after.server_side_encryption_configuration\n  msg := \"S3 bucket must have encryption\"\n}"
        }
      },
      "workflow": {
        "steps": [
          "terraform plan -out=tfplan",
          "terraform show -json tfplan > tfplan.json",
          "conftest test tfplan.json"
        ]
      }
    },
    "ci_enforcement": {
      "pr_check": "conftest_validate_plan",
      "blocking": "critical_policies_only",
      "advisory": "medium_low_comment_only"
    }
  },
  "secret_detection": {
    "tools": {
      "gitleaks": {
        "what": "git_history_secret_scanner",
        "command": "gitleaks detect --source . --verbose",
        "pre_commit": {
          "hook": {
            "repo": "https://github.com/gitleaks/gitleaks",
            "hooks": [{"id": "gitleaks"}]
          }
        }
      },
      "trufflehog": {
        "what": "entropy_pattern_detector",
        "command": "trufflehog git file://. --only-verified",
        "features": ["verification", "git_history", "filesystem"]
      },
      "detect_secrets": {
        "what": "yelp_secret_scanner",
        "command": "detect-secrets scan . --all-files"
      }
    },
    "patterns_detected": [
      "api_keys",
      "aws_credentials",
      "private_keys",
      "database_urls",
      "jwt_tokens",
      "oauth_secrets"
    ],
    "prevention_strategy": {
      "pre_commit": {
        "tool": "gitleaks",
        "action": "block_commit_with_secret"
      },
      "ci": {
        "tool": "trufflehog",
        "action": "fail_pr_scan_history"
      },
      "remediation": {
        "rotate": "immediately_revoke_exposed_secret",
        "history": "consider_git_filter_repo"
      }
    },
    "allowlisting": {
      "file": ".gitleaksignore",
      "content": "# False positive example\ntests/fixtures/fake_api_key.txt",
      "review": "security_team_approval_required"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 11 : Cloud Security Posture & Supply Chain

**Concepts couverts** : 3.26.5.l (Secrets Management), 3.26.5.m (Cloud Security Posture), 3.26.5.n (Service Mesh Security), 3.26.5.o (GitOps Security), 3.26.5.p (Supply Chain Security)

**Entrée JSON** :
```json
{
  "cloud_environment": {
    "provider": "aws",
    "accounts": 5,
    "services": ["ec2", "s3", "rds", "eks", "lambda"],
    "compliance": ["SOC2", "HIPAA"]
  },
  "kubernetes": {
    "cluster": "eks",
    "service_mesh": "considering",
    "gitops": "argocd"
  },
  "supply_chain_concerns": {
    "image_signing": "none",
    "provenance": "unknown"
  }
}
```

**Sortie attendue** :
```json
{
  "secrets_management": {
    "problems_with_alternatives": {
      "environment_variables": "visible_in_logs_ps_output",
      "config_files": "in_git_history_containers",
      "kubernetes_secrets": "base64_not_encryption"
    },
    "solutions": {
      "hashicorp_vault": {
        "features": ["dynamic_secrets", "leasing", "revocation", "audit"],
        "integration": {
          "kubernetes": {
            "method": "vault_agent_injector",
            "workflow": "sidecar_injects_secrets_to_pod"
          },
          "ci_cd": {
            "method": "jwt_auth",
            "workflow": "pipeline_authenticates_fetches_secrets"
          }
        },
        "secret_rotation": {
          "database": "dynamic_credentials_per_pod",
          "api_keys": "leased_auto_revoke"
        }
      },
      "aws_secrets_manager": {
        "features": ["rotation", "cross_region", "iam_integration"],
        "kubernetes_integration": "external_secrets_operator",
        "rotation_lambda": "automatic_rds_rotation"
      },
      "kubernetes_native": {
        "external_secrets_operator": {
          "what": "sync_external_secrets_to_k8s",
          "supported": ["vault", "aws", "gcp", "azure"],
          "example": {
            "apiVersion": "external-secrets.io/v1beta1",
            "kind": "ExternalSecret",
            "spec": {
              "refreshInterval": "1h",
              "secretStoreRef": {"name": "vault-backend", "kind": "SecretStore"},
              "target": {"name": "db-credentials"},
              "data": [{"secretKey": "password", "remoteRef": {"key": "database/creds/api", "property": "password"}}]
            }
          }
        },
        "sealed_secrets": {
          "what": "encrypt_secrets_safe_in_git",
          "workflow": "kubeseal_encrypts_only_cluster_decrypts"
        }
      }
    }
  },
  "cloud_security_posture": {
    "cspm_concept": {
      "what": "Cloud Security Posture Management",
      "purpose": [
        "continuous_misconfiguration_detection",
        "compliance_monitoring",
        "risk_assessment",
        "remediation_guidance"
      ]
    },
    "tools": {
      "commercial": {
        "prisma_cloud": "palo_alto_comprehensive",
        "wiz": "agentless_graph_based",
        "orca": "sidescanning_no_agents",
        "lacework": "anomaly_detection_focus"
      },
      "open_source": {
        "prowler": {
          "what": "aws_azure_gcp_security_assessment",
          "command": "prowler aws --compliance soc2",
          "checks": "300_plus_security_checks"
        },
        "steampipe": {
          "what": "sql_for_cloud_resources",
          "compliance": "mod_aws_compliance"
        },
        "cloudquery": {
          "what": "cloud_asset_inventory_sql",
          "policies": "custom_sql_queries"
        }
      }
    },
    "implementation": {
      "continuous_scanning": {
        "frequency": "hourly",
        "scope": "all_accounts",
        "tool": "prowler_scheduled"
      },
      "compliance_mapping": {
        "soc2": "prowler_soc2_checks",
        "hipaa": "prowler_hipaa_checks"
      },
      "alerting": {
        "critical": "immediate_pagerduty",
        "high": "slack_security_channel",
        "medium_low": "weekly_report"
      },
      "remediation": {
        "auto_fix": "lambda_remediation_critical",
        "manual": "ticket_creation_sla"
      }
    },
    "key_checks": {
      "s3": ["public_access_blocked", "encryption_enabled", "versioning"],
      "iam": ["mfa_enabled", "no_root_access_keys", "least_privilege"],
      "ec2": ["imdsv2_required", "ebs_encryption", "security_groups"],
      "rds": ["encryption", "no_public", "backup_retention"]
    }
  },
  "service_mesh_security": {
    "options": {
      "istio": {
        "security_features": ["mtls", "authorization", "jwt_validation"],
        "overhead": "medium_sidecar_per_pod"
      },
      "linkerd": {
        "security_features": ["mtls_automatic", "authorization"],
        "overhead": "low_lightweight"
      }
    },
    "mtls": {
      "what": "mutual_tls_service_to_service",
      "benefit": [
        "encrypted_traffic",
        "identity_verification",
        "zero_trust_network"
      ],
      "istio_config": {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "PeerAuthentication",
        "spec": {"mtls": {"mode": "STRICT"}}
      }
    },
    "authorization_policies": {
      "concept": "fine_grained_service_access_control",
      "istio_example": {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "spec": {
          "selector": {"matchLabels": {"app": "payment-service"}},
          "rules": [{
            "from": [{"source": {"principals": ["cluster.local/ns/default/sa/api-gateway"]}}],
            "to": [{"operation": {"methods": ["POST"], "paths": ["/process"]}}]
          }]
        }
      }
    },
    "observability_security": {
      "traffic_monitoring": "detect_anomalous_patterns",
      "access_logs": "audit_service_communication",
      "distributed_tracing": "security_incident_investigation"
    }
  },
  "gitops_security": {
    "argocd_security": {
      "rbac": {
        "sso_integration": "okta_or_dex",
        "role_mapping": {
          "developers": "app_sync_specific_projects",
          "security": "view_all_override_gates",
          "platform": "admin_all_clusters"
        }
      },
      "secrets": {
        "problem": "secrets_in_git_repo",
        "solutions": {
          "sealed_secrets": "encrypt_in_repo",
          "argocd_vault_plugin": "fetch_at_sync",
          "external_secrets": "sync_to_cluster"
        }
      },
      "repository_security": {
        "gpg_signature_verification": "verify_commits",
        "webhook_secret": "authenticate_triggers"
      }
    },
    "security_benefits": [
      "declarative_desired_state",
      "audit_trail_in_git",
      "rollback_to_any_commit",
      "drift_detection"
    ],
    "security_risks_mitigation": {
      "repo_compromise": "branch_protection_signed_commits",
      "argocd_compromise": "rbac_network_policies_audit"
    }
  },
  "supply_chain_security": {
    "slsa_framework": {
      "what": "Supply-chain Levels for Software Artifacts",
      "levels": {
        "level_1": {
          "requirements": ["documented_build_process"],
          "effort": "low"
        },
        "level_2": {
          "requirements": ["version_controlled_build", "hosted_build_service"],
          "effort": "medium"
        },
        "level_3": {
          "requirements": ["auditable_builds", "isolated_builds"],
          "effort": "high"
        },
        "level_4": {
          "requirements": ["hermetic_reproducible_builds", "two_person_review"],
          "effort": "very_high"
        }
      },
      "recommendation": "target_level_3"
    },
    "image_signing": {
      "cosign": {
        "what": "sigstore_image_signing",
        "sign": "cosign sign --key cosign.key $IMAGE",
        "verify": "cosign verify --key cosign.pub $IMAGE",
        "keyless": "cosign sign $IMAGE (oidc_identity)"
      },
      "ci_integration": {
        "step": {
          "name": "Sign Image",
          "run": "cosign sign --yes $IMAGE",
          "env": {"COSIGN_EXPERIMENTAL": "1"}
        }
      },
      "enforcement": {
        "admission_controller": "kyverno_or_gatekeeper",
        "policy": "reject_unsigned_images"
      }
    },
    "provenance": {
      "what": "build_metadata_attestation",
      "in_toto": {
        "concept": "in-toto_attestations",
        "content": ["builder", "source_repo", "build_instructions", "materials"]
      },
      "slsa_provenance": {
        "generation": "github_actions_slsa_generator",
        "verification": "slsa-verifier verify-artifact"
      }
    },
    "complete_pipeline": {
      "source": "signed_commits_branch_protection",
      "build": "isolated_ephemeral_logged",
      "artifact": "signed_sbom_provenance",
      "deploy": "signature_verification_admission",
      "runtime": "continuous_scanning_monitoring"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 12 : CI/CD Security - Risks & Pipeline Hardening

**Concepts couverts** : 3.26.6.a (CI/CD Security Risks), 3.26.6.b (Pipeline Hardening), 3.26.6.c (Secret Management CI), 3.26.6.d (GitHub Actions Security)

**Entrée JSON** :
```json
{
  "ci_cd_platform": "github_actions",
  "pipelines": 45,
  "current_security": {
    "secrets_storage": "github_secrets",
    "third_party_actions": "unrestricted",
    "permissions": "default_write_all"
  },
  "incidents": [
    {"type": "secret_leak_in_logs", "date": "2025-06"},
    {"type": "dependency_confusion", "date": "2025-08"}
  ]
}
```

**Sortie attendue** :
```json
{
  "ci_cd_security_risks": {
    "risk_categories": {
      "secret_exposure": {
        "vectors": [
          "logs_output",
          "environment_variable_dump",
          "artifact_inclusion",
          "error_messages"
        ],
        "impact": "credential_theft_lateral_movement",
        "likelihood": "high"
      },
      "code_injection": {
        "vectors": [
          "untrusted_input_in_workflow",
          "third_party_action_compromise",
          "dependency_confusion"
        ],
        "impact": "arbitrary_code_execution_supply_chain",
        "likelihood": "medium"
      },
      "artifact_tampering": {
        "vectors": [
          "unsigned_artifacts",
          "mutable_tags",
          "registry_compromise"
        ],
        "impact": "malicious_deployment",
        "likelihood": "medium"
      },
      "privilege_escalation": {
        "vectors": [
          "overly_permissive_tokens",
          "self_hosted_runner_access",
          "cross_workflow_token_theft"
        ],
        "impact": "repository_takeover",
        "likelihood": "low_medium"
      }
    },
    "recent_incidents_analysis": {
      "secret_leak_june": {
        "root_cause": "debug_mode_enabled_printed_env",
        "fix": "remove_debug_add_secret_masking"
      },
      "dependency_confusion_august": {
        "root_cause": "no_namespace_protection",
        "fix": "registry_configuration_scope_mapping"
      }
    }
  },
  "pipeline_hardening": {
    "runner_security": {
      "ephemeral_runners": {
        "what": "fresh_vm_per_job",
        "benefit": "no_persistent_compromise",
        "github": "default_for_hosted"
      },
      "self_hosted_risks": {
        "risks": ["persistent_access", "network_exposure", "credential_theft"],
        "mitigations": {
          "ephemeral": "github.com/actions-runner-controller",
          "isolation": "dedicated_network_no_prod_access",
          "monitoring": "audit_logs_behavior_analysis"
        }
      }
    },
    "network_isolation": {
      "principle": "runners_should_not_access_production",
      "implementation": {
        "vpc_configuration": "separate_ci_vpc",
        "outbound_restrictions": "allow_only_necessary_registries"
      }
    },
    "least_privilege": {
      "token_permissions": "minimal_required_per_job",
      "repository_access": "single_repo_not_org_wide",
      "secret_access": "environment_scoped"
    },
    "audit_logging": {
      "what_to_log": ["workflow_runs", "secret_access", "deployments"],
      "retention": "90_days_minimum",
      "alerting": "suspicious_patterns"
    },
    "workflow_approval": {
      "first_time_contributors": "require_approval",
      "fork_prs": "require_approval",
      "protected_branches": "environment_approvals"
    }
  },
  "secret_management_ci": {
    "github_secrets_best_practices": {
      "hierarchy": {
        "organization": "shared_across_repos",
        "repository": "repo_specific",
        "environment": "deployment_stage_specific"
      },
      "naming": "PREFIX_SECRETNAME (AWS_PROD_ACCESS_KEY)",
      "rotation": "quarterly_or_on_incident"
    },
    "vault_integration": {
      "approach": "jwt_authentication",
      "workflow": {
        "step": {
          "name": "Vault Secrets",
          "uses": "hashicorp/vault-action@v2",
          "with": {
            "url": "https://vault.company.com",
            "method": "jwt",
            "role": "github-actions",
            "secrets": "secret/data/ci/aws access_key | AWS_ACCESS_KEY_ID"
          }
        }
      },
      "benefits": ["centralized", "audited", "dynamic", "rotated"]
    },
    "secret_masking": {
      "automatic": "github_masks_secrets_in_logs",
      "manual": "echo '::add-mask::$SENSITIVE_VALUE'",
      "caution": "base64_encoding_reveals_secrets"
    },
    "secret_scanning": {
      "github_feature": "push_protection",
      "behavior": "block_commit_with_detected_secrets",
      "scope": "200_plus_patterns"
    }
  },
  "github_actions_security": {
    "permissions_configuration": {
      "default_problem": "GITHUB_TOKEN has write-all by default",
      "solution": {
        "repo_settings": "read_permissions_default",
        "workflow_level": {
          "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "write"
          }
        },
        "job_level": {
          "permissions": {
            "contents": "read"
          }
        }
      },
      "principle": "explicit_minimal_permissions"
    },
    "third_party_actions": {
      "risks": [
        "action_compromise",
        "data_exfiltration",
        "credential_theft"
      ],
      "vetting_process": {
        "check": ["source_code", "permissions_requested", "maintainer_reputation"],
        "prefer": "verified_creators_official"
      },
      "pinning": {
        "bad": "uses: actions/checkout@v4",
        "good": "uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608",
        "rationale": "sha_immutable_tags_mutable"
      },
      "allowlist": {
        "org_setting": "allow_only_specified_actions",
        "recommended": ["actions/*", "github/*", "hashicorp/*"]
      }
    },
    "oidc_authentication": {
      "what": "keyless_cloud_authentication",
      "how": "github_provides_jwt_cloud_validates",
      "aws_example": {
        "permissions": {"id-token": "write"},
        "step": {
          "uses": "aws-actions/configure-aws-credentials@v4",
          "with": {
            "role-to-assume": "arn:aws:iam::123456789:role/github-actions",
            "aws-region": "us-east-1"
          }
        }
      },
      "benefits": ["no_long_lived_credentials", "auditable", "scoped"]
    },
    "workflow_injection_prevention": {
      "vulnerable_patterns": {
        "issue_title": "${{ github.event.issue.title }}",
        "pr_body": "${{ github.event.pull_request.body }}"
      },
      "safe_patterns": {
        "environment_variable": {
          "env": {"TITLE": "${{ github.event.issue.title }}"},
          "run": "echo \"$TITLE\""
        },
        "actions_github_script": "use javascript context"
      }
    },
    "secured_workflow_example": {
      "name": "Secure CI Pipeline",
      "on": {
        "pull_request": {"branches": ["main"]},
        "push": {"branches": ["main"]}
      },
      "permissions": {
        "contents": "read",
        "packages": "write",
        "id-token": "write"
      },
      "jobs": {
        "build": {
          "runs-on": "ubuntu-latest",
          "environment": "production",
          "steps": [
            {"uses": "actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608"},
            {"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "${{ vars.AWS_ROLE }}", "aws-region": "us-east-1"}}
          ]
        }
      }
    }
  }
}
```

**Barème** : 98/100

---

## EXERCICE 13 : CI/CD Platforms Security & Artifact Integrity

**Concepts couverts** : 3.26.6.e (GitLab CI Security), 3.26.6.f (Jenkins Security), 3.26.6.g (Artifact Signing), 3.26.6.h (SLSA Framework)

**Entrée JSON** :
```json
{
  "ci_platforms": {
    "gitlab": {"pipelines": 20, "runners": "shared"},
    "jenkins": {"jobs": 15, "version": "2.401"}
  },
  "artifact_security": {
    "signing": "none",
    "registry": "docker_hub",
    "provenance": "unknown"
  }
}
```

**Sortie attendue** :
```json
{
  "gitlab_ci_security": {
    "protected_variables": {
      "what": "secrets_only_for_protected_branches",
      "configuration": {
        "settings_path": "Settings > CI/CD > Variables",
        "options": {
          "protected": "only_protected_branches_tags",
          "masked": "hidden_in_logs",
          "expanded": "variable_reference_enabled"
        }
      },
      "best_practice": "all_secrets_protected_and_masked"
    },
    "protected_branches": {
      "settings": {
        "allowed_to_merge": "maintainers_only",
        "allowed_to_push": "no_one",
        "require_approval": "1_plus_reviewers",
        "code_owner_approval": true
      }
    },
    "runner_security": {
      "shared_runners": {
        "risk": "multi_tenant_potential_leak",
        "mitigation": "use_project_runners_for_sensitive"
      },
      "project_runners": {
        "isolation": "dedicated_per_project",
        "configuration": "limit_to_protected_branches"
      },
      "runner_registration": {
        "token_security": "rotate_after_use",
        "authentication": "runner_authentication_tokens"
      }
    },
    "built_in_security": {
      "sast": {
        "template": "include: - template: Security/SAST.gitlab-ci.yml",
        "benefit": "pre_configured_analysis"
      },
      "dast": {
        "template": "include: - template: Security/DAST.gitlab-ci.yml",
        "requirement": "deployed_environment"
      },
      "dependency_scanning": {
        "template": "include: - template: Security/Dependency-Scanning.gitlab-ci.yml"
      },
      "container_scanning": {
        "template": "include: - template: Security/Container-Scanning.gitlab-ci.yml"
      }
    },
    "security_dashboard": {
      "features": [
        "vulnerability_tracking",
        "merge_request_blocking",
        "security_approval_rules"
      ],
      "requirement": "ultimate_tier"
    },
    "secure_pipeline_example": {
      "stages": ["build", "test", "security", "deploy"],
      "variables": {
        "SECURE_ANALYZERS_PREFIX": "$CI_TEMPLATE_REGISTRY_HOST/security-products"
      },
      "include": [
        {"template": "Security/SAST.gitlab-ci.yml"},
        {"template": "Security/Dependency-Scanning.gitlab-ci.yml"}
      ],
      "build": {
        "script": ["docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA ."],
        "rules": [{"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}]
      }
    }
  },
  "jenkins_security": {
    "credentials_management": {
      "credentials_plugin": {
        "what": "centralized_secret_storage",
        "types": ["username_password", "secret_text", "ssh_key", "certificate"],
        "scope": ["global", "folder", "job"]
      },
      "best_practices": {
        "folder_scoped": "limit_access_per_team",
        "credential_binding": {
          "pipeline": "withCredentials([string(credentialsId: 'api-key', variable: 'API_KEY')]) { sh 'deploy.sh' }"
        },
        "external_vault": {
          "plugin": "hashicorp-vault-plugin",
          "integration": "vault_secret_source"
        }
      }
    },
    "agent_security": {
      "controller_isolation": {
        "principle": "no_builds_on_controller",
        "setting": "number_of_executors: 0"
      },
      "agent_authentication": {
        "jnlp": "agent_to_controller_security",
        "ssh": "key_based_authentication"
      },
      "ephemeral_agents": {
        "kubernetes": "kubernetes_plugin_pod_per_build",
        "docker": "docker_plugin_container_per_build"
      }
    },
    "rbac": {
      "matrix_authorization": {
        "plugin": "matrix-auth",
        "principle": "least_privilege_per_user_role"
      },
      "folder_permissions": {
        "approach": "teams_own_folders",
        "inheritance": "limit_global_permissions"
      },
      "script_security": {
        "sandbox": "groovy_sandbox_enabled",
        "approvals": "admin_approves_unsafe_scripts"
      }
    },
    "pipeline_security": {
      "jenkinsfile_in_scm": "pipeline_as_code_auditable",
      "shared_libraries": {
        "trusted": "admin_controlled_library_repo",
        "untrusted": "sandboxed_limited_features"
      },
      "replay_protection": {
        "disable": "prevent_replay_with_modifications"
      }
    },
    "hardening_checklist": [
      "disable_cli_over_remoting",
      "enable_csrf_protection",
      "restrict_api_access",
      "regular_plugin_updates",
      "audit_logging_enabled",
      "backup_jenkins_home"
    ]
  },
  "artifact_signing": {
    "importance": [
      "verify_artifact_origin",
      "detect_tampering",
      "supply_chain_integrity",
      "compliance_requirement"
    ],
    "sigstore": {
      "what": "free_signing_infrastructure",
      "components": {
        "cosign": "container_image_signing",
        "rekor": "transparency_log",
        "fulcio": "certificate_authority"
      },
      "keyless_signing": {
        "concept": "sign_with_oidc_identity",
        "benefit": "no_key_management",
        "how": "fulcio_issues_short_lived_cert_from_oidc"
      }
    },
    "cosign_workflow": {
      "keyed_signing": {
        "generate": "cosign generate-key-pair",
        "sign": "cosign sign --key cosign.key $IMAGE",
        "verify": "cosign verify --key cosign.pub $IMAGE"
      },
      "keyless_signing": {
        "sign": "cosign sign $IMAGE",
        "verify": "cosign verify $IMAGE --certificate-identity=https://github.com/org/repo --certificate-oidc-issuer=https://token.actions.githubusercontent.com"
      }
    },
    "in_toto": {
      "what": "software_supply_chain_framework",
      "concepts": {
        "layout": "defines_expected_steps_in_supply_chain",
        "link": "metadata_for_each_step",
        "attestation": "signed_statement_about_artifact"
      },
      "integration": "slsa_provenance_format"
    },
    "ci_implementation": {
      "github_action": {
        "build_job": {
          "outputs": {"digest": "${{ steps.build.outputs.digest }}"}
        },
        "sign_job": {
          "needs": "build",
          "steps": [
            {"uses": "sigstore/cosign-installer@v3"},
            {"run": "cosign sign --yes $IMAGE@${{ needs.build.outputs.digest }}"}
          ]
        }
      }
    }
  },
  "slsa_framework": {
    "overview": {
      "what": "Supply-chain Levels for Software Artifacts",
      "goal": "improve_integrity_of_software_supply_chain",
      "approach": "progressive_levels_of_assurance"
    },
    "levels_detailed": {
      "level_0": {
        "name": "no_guarantees",
        "description": "no_slsa_compliance"
      },
      "level_1": {
        "name": "documentation",
        "requirements": {
          "build": "scripted_build",
          "provenance": "exists_but_not_authenticated"
        },
        "effort": "minimal"
      },
      "level_2": {
        "name": "build_service",
        "requirements": {
          "build": "build_service_generates_provenance",
          "provenance": "authenticated_non_forgeable"
        },
        "effort": "low_to_medium"
      },
      "level_3": {
        "name": "auditable",
        "requirements": {
          "build": "hardened_build_platform",
          "provenance": "non_falsifiable_by_builder",
          "source": "verified_history"
        },
        "effort": "medium_to_high"
      },
      "level_4": {
        "name": "dependencies",
        "requirements": {
          "build": "hermetic_reproducible",
          "provenance": "includes_dependency_graph",
          "review": "two_person_review_all_changes"
        },
        "effort": "high"
      }
    },
    "provenance_generation": {
      "github_slsa_generator": {
        "uses": "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0",
        "with": {
          "base64-subjects": "${{ needs.build.outputs.digests }}",
          "upload-assets": true
        }
      },
      "output": {
        "format": "in-toto_attestation",
        "content": {
          "builder": {"id": "github_actions"},
          "buildType": "workflow",
          "invocation": {"configSource": {"ref": "refs/heads/main"}},
          "materials": [{"uri": "git+https://github.com/org/repo"}]
        }
      }
    },
    "verification": {
      "command": "slsa-verifier verify-artifact artifact.tar.gz --provenance-path provenance.jsonl --source-uri github.com/org/repo",
      "checks": [
        "signature_valid",
        "builder_trusted",
        "source_matches",
        "build_level_met"
      ]
    },
    "adoption_path": {
      "current_state": "level_0",
      "phase_1": {
        "target": "level_1",
        "actions": ["document_build_process", "generate_basic_provenance"]
      },
      "phase_2": {
        "target": "level_2",
        "actions": ["use_github_actions", "integrate_slsa_generator"]
      },
      "phase_3": {
        "target": "level_3",
        "actions": ["harden_workflows", "verify_source_integrity"]
      }
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 14 : CI/CD Governance & Deployment Security

**Concepts couverts** : 3.26.6.i (Branch Protection), 3.26.6.j (Deployment Security), 3.26.6.k (Audit & Compliance), 3.26.6.l (Self-Hosted vs Cloud)

**Entrée JSON** :
```json
{
  "organization": {
    "repositories": 100,
    "deployment_environments": ["dev", "staging", "prod"],
    "compliance": ["SOC2", "ISO27001"],
    "current_runners": "cloud_hosted"
  },
  "governance_requirements": {
    "code_review": "mandatory",
    "deployment_approval": "required_for_prod",
    "audit_trail": "comprehensive"
  }
}
```

**Sortie attendue** :
```json
{
  "branch_protection": {
    "github_settings": {
      "main_branch": {
        "require_pull_request": {
          "enabled": true,
          "required_approving_reviews": 2,
          "dismiss_stale_reviews": true,
          "require_code_owner_review": true,
          "restrict_who_can_dismiss": true
        },
        "require_status_checks": {
          "strict": true,
          "required_checks": ["build", "test", "security-scan"]
        },
        "require_conversation_resolution": true,
        "require_signed_commits": true,
        "require_linear_history": true,
        "restrictions": {
          "push": "release_managers_only",
          "force_push": "disabled",
          "deletion": "disabled"
        },
        "allow_admin_bypass": false
      }
    },
    "enforcement_strategy": {
      "org_level_rules": {
        "what": "rulesets_applied_org_wide",
        "benefit": "consistent_security_all_repos"
      },
      "codeowners": {
        "file": ".github/CODEOWNERS",
        "content": "* @security-team\n/infrastructure/ @platform-team @security-team\n/src/auth/ @security-team",
        "effect": "auto_assign_reviewers_mandatory"
      }
    },
    "commit_signing": {
      "requirement": "vigilant_mode",
      "setup": {
        "developer": "git config commit.gpgsign true",
        "verification": "github_shows_verified_badge"
      },
      "benefit": "prove_commit_author_identity"
    }
  },
  "deployment_security": {
    "environment_protection": {
      "github_environments": {
        "dev": {
          "protection_rules": "none",
          "deployment": "automatic"
        },
        "staging": {
          "protection_rules": {
            "required_reviewers": ["qa-team"],
            "wait_timer": 0
          },
          "deployment": "on_approval"
        },
        "prod": {
          "protection_rules": {
            "required_reviewers": ["release-managers", "security-team"],
            "wait_timer": "30_minutes",
            "prevent_self_review": true
          },
          "deployment_branches": ["main"],
          "secrets": "prod_specific_secrets"
        }
      }
    },
    "deployment_patterns": {
      "canary": {
        "approach": "deploy_to_percentage_of_traffic",
        "monitoring": "compare_error_rates",
        "rollback": "automatic_on_threshold"
      },
      "blue_green": {
        "approach": "parallel_environments_switch_traffic",
        "benefit": "instant_rollback",
        "requirement": "double_infrastructure"
      },
      "progressive": {
        "approach": "feature_flags_gradual_rollout",
        "benefit": "fine_grained_control"
      }
    },
    "rollback_strategy": {
      "automatic": {
        "triggers": ["error_rate_spike", "health_check_failure", "latency_increase"],
        "action": "revert_to_previous_version"
      },
      "manual": {
        "process": "incident_declared_rollback_approved",
        "argocd": "sync_to_previous_commit"
      }
    },
    "change_management": {
      "change_ticket": {
        "requirement": "link_deployment_to_ticket",
        "approval": "change_advisory_board_for_major"
      },
      "deployment_window": {
        "production": "business_hours_weekdays",
        "exceptions": "emergency_with_approval"
      }
    }
  },
  "audit_compliance": {
    "audit_logging": {
      "what_to_capture": {
        "source_control": ["commits", "branch_changes", "permission_changes"],
        "ci_cd": ["pipeline_runs", "deployments", "secret_access"],
        "infrastructure": ["resource_changes", "access_logs"]
      },
      "github_audit_log": {
        "enterprise": "full_audit_log_api",
        "retention": "indefinite_enterprise",
        "export": "siem_integration"
      },
      "pipeline_artifacts": {
        "build_logs": "retained_90_days",
        "sbom": "attached_to_release",
        "provenance": "slsa_attestation"
      }
    },
    "compliance_evidence": {
      "soc2": {
        "cc6_1": {
          "control": "logical_access_controls",
          "evidence": ["branch_protection_config", "rbac_settings", "audit_logs"]
        },
        "cc7_1": {
          "control": "system_monitoring",
          "evidence": ["security_scan_results", "alert_configurations"]
        },
        "cc8_1": {
          "control": "change_management",
          "evidence": ["pr_approvals", "deployment_logs", "change_tickets"]
        }
      },
      "iso27001": {
        "a12_1": {
          "control": "operational_procedures",
          "evidence": ["pipeline_definitions", "runbooks"]
        },
        "a14_2": {
          "control": "security_in_development",
          "evidence": ["sast_dast_results", "security_reviews"]
        }
      }
    },
    "reporting": {
      "dashboards": {
        "security_posture": "vulnerabilities_by_severity_trend",
        "deployment_metrics": "frequency_failure_rate_mttr",
        "compliance_status": "control_coverage"
      },
      "periodic_reports": {
        "weekly": "security_findings_summary",
        "monthly": "compliance_status_metrics",
        "quarterly": "security_review_audit_prep"
      }
    }
  },
  "self_hosted_vs_cloud": {
    "comparison": {
      "cloud_hosted": {
        "github_actions": {
          "security_model": "ephemeral_multi_tenant",
          "network": "internet_egress_no_vpc",
          "cost": "per_minute_billing",
          "maintenance": "zero"
        },
        "pros": [
          "no_infrastructure_management",
          "auto_scaling",
          "always_latest_patches"
        ],
        "cons": [
          "limited_customization",
          "no_vpc_access_without_workarounds",
          "rate_limits"
        ],
        "best_for": "most_workloads"
      },
      "self_hosted": {
        "security_model": "full_control_responsibility",
        "network": "vpc_access_internal_resources",
        "cost": "infrastructure_plus_maintenance",
        "maintenance": "patches_updates_monitoring"
      },
      "pros": [
        "vpc_private_access",
        "custom_hardware_gpu",
        "no_rate_limits",
        "data_residency_control"
      ],
      "cons": [
        "security_responsibility",
        "persistent_access_risk",
        "maintenance_burden"
      ],
      "best_for": "specific_requirements_security_mature_orgs"
    },
    "self_hosted_security_requirements": {
      "ephemeral_runners": {
        "solution": "actions_runner_controller_kubernetes",
        "benefit": "fresh_pod_per_job"
      },
      "network_isolation": {
        "approach": "dedicated_vpc_no_prod_access",
        "egress_control": "firewall_allowlist"
      },
      "credential_management": {
        "approach": "vault_integration_short_lived",
        "avoid": "long_lived_creds_on_runner"
      },
      "monitoring": {
        "runner_logs": "centralized_siem",
        "anomaly_detection": "unusual_network_access"
      },
      "patching": {
        "os": "automated_regular",
        "runner_software": "auto_update_enabled"
      }
    },
    "hybrid_approach": {
      "strategy": "cloud_default_self_hosted_specific",
      "cloud_for": ["builds", "tests", "public_deployments"],
      "self_hosted_for": ["vpc_access_required", "specialized_hardware", "high_volume"],
      "security_baseline": "same_policies_both_types"
    },
    "decision_matrix": {
      "use_cloud_if": [
        "standard_workloads",
        "no_vpc_access_needed",
        "want_zero_maintenance",
        "security_maturity_developing"
      ],
      "use_self_hosted_if": [
        "need_vpc_private_access",
        "compliance_data_residency",
        "specialized_hardware_needed",
        "security_team_can_maintain"
      ]
    }
  }
}
```

**Barème** : 96/100

---

## RÉCAPITULATIF MODULE 3.26

**Module** : DevSecOps
**Concepts couverts** : 80/80 (100%)
**Exercices** : 14
**Note moyenne** : 97.1/100

### Distribution par sous-module :

| Sous-module | Concepts | Exercices | Couverture |
|-------------|----------|-----------|------------|
| 3.26.1 Fondamentaux | 14 | Ex01-02 | 100% |
| 3.26.2 SAST | 12 | Ex03-04 | 100% |
| 3.26.3 DAST | 12 | Ex05-06 | 100% |
| 3.26.4 SCA | 14 | Ex07-08 | 100% |
| 3.26.5 Container/K8s/IaC | 16 | Ex09-11 | 100% |
| 3.26.6 CI/CD Pipeline Security | 12 | Ex12-14 | 100% |

### Points forts :
- Couverture complète du pipeline DevSecOps
- Outils pratiques avec configurations réelles
- Intégration CI/CD pour chaque domaine
- Équilibre sécurité/vélocité développeur
- Compliance SOC2/ISO27001 intégrée

