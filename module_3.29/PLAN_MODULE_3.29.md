# MODULE 3.29 : Supply Chain Security

**Concepts couverts** : 54
**Nombre d'exercices** : 10
**Difficulté** : Avancée

---

## Vue d'ensemble

Module consacré à la sécurité de la chaîne d'approvisionnement : logicielle (SBOM, SLSA, dépendances), matérielle (trojans, contrefaçon), gestion des tiers (TPRM), et pratiques de développement sécurisé.

---

## EXERCICE 01 : software_supply_chain_analyzer

**Concepts couverts** (8 concepts - 3.29.1 a-h) :
- Supply Chain Risks, Attack Examples, SBOM, Dependency Analysis
- Dependency Confusion, Typosquatting, Malicious Packages, Package Signing

**Sujet** : Analyseur de risques de la chaîne d'approvisionnement logicielle.

**Entrée JSON** :
```json
{
  "project": {"name": "payment-service", "package_manager": "npm"},
  "dependencies": {
    "direct": [
      {"name": "lodash", "version": "4.17.21"},
      {"name": "@company/auth-lib", "version": "2.1.0", "registry": "private"}
    ],
    "transitive_count": 847
  },
  "namespace_check": {"@company/auth-lib": {"public_npm_exists": false}}
}
```

**Sortie attendue** :
```json
{
  "risk_assessment": {"overall_risk": "high", "dependency_count": 849},
  "supply_chain_risks": {
    "dependency_confusion": {"risk": "medium", "finding": "@company/auth-lib not claimed on public npm"},
    "typosquatting": {"suspicious": ["@cornpany/auth-lib"]}
  },
  "remediation_priority": ["Claim @company namespace on public npm", "Implement package signing"]
}
```

**Barème** : 97/100

---

## EXERCICE 02 : build_integrity_validator

**Concepts couverts** (8 concepts - 3.29.1 i-p) :
- Lock Files, Private Registries, Build Integrity, SLSA Framework
- Source Integrity, CI/CD Security, Distribution Security, Update Security (TUF)

**Sujet** : Validateur d'intégrité du pipeline de build selon SLSA.

**Entrée JSON** :
```json
{
  "current_practices": {
    "source_control": {"branch_protection": false, "signed_commits": false},
    "build_system": {"build_environment": "shared_runners"},
    "artifacts": {"signing": false, "provenance_generated": false}
  },
  "target_slsa_level": 3
}
```

**Sortie attendue** :
```json
{
  "current_slsa_level": 1,
  "gap_analysis": {
    "source": ["No signed commits", "No branch protection"],
    "build": ["Shared runners - not ephemeral"],
    "provenance": ["Not generated", "Not signed"]
  },
  "roadmap_to_level_3": [
    "Enable signed commits and branch protection",
    "Use ephemeral build runners",
    "Generate SLSA provenance with Sigstore"
  ]
}
```

**Barème** : 98/100

---

## EXERCICE 03 : hardware_supply_chain_assessor

**Concepts couverts** (6 concepts - 3.29.2 a-f) :
- Hardware Risks, Hardware Trojans, Counterfeit Detection
- Trusted Foundry, Component Provenance, Firmware Security

**Sujet** : Évaluateur de risques de la chaîne d'approvisionnement matérielle.

**Entrée JSON** :
```json
{
  "device": {"type": "network_appliance", "deployment": "critical_infrastructure"},
  "components": [
    {"type": "cpu", "source": "authorized_distributor", "documentation": "full"},
    {"type": "network_chip", "source": "broker", "documentation": "partial"}
  ],
  "inspection_results": {"electrical": "minor_anomalies_network_chip"}
}
```

**Sortie attendue** :
```json
{
  "overall_risk": "high",
  "component_analysis": [
    {"component": "cpu", "risk_level": "low", "provenance_confidence": "high"},
    {"component": "network_chip", "risk_level": "critical", "findings": ["Broker source", "Electrical anomalies"], "actions": ["X-ray inspection required"]}
  ],
  "hardware_trojan_assessment": {"risk": "elevated", "recommended_testing": ["X-ray", "Side-channel analysis"]}
}
```

**Barème** : 97/100

---

## EXERCICE 04 : hardware_security_modules_manager

**Concepts couverts** (6 concepts - 3.29.2 g-l) :
- HSM, TPM, Physical Tamper Detection
- Supply Chain Transparency, Geopolitical Risks, End-of-Life Security

**Sujet** : Gestionnaire de modules de sécurité matérielle et cycle de vie.

**Entrée JSON** :
```json
{
  "hsm_inventory": [
    {"model": "Thales Luna 7", "fips_level": 3, "eol_date": "2030-01-01"},
    {"model": "Legacy_HSM_X", "fips_level": 2, "eol_date": "2024-06-01"}
  ],
  "tpm_status": {"version": "2.0", "attestation_enabled": false}
}
```

**Sortie attendue** :
```json
{
  "hsm_assessment": {
    "thales_luna_7": {"status": "compliant"},
    "legacy_hsm_x": {"status": "critical", "issues": ["Past EOL", "FIPS Level 2 insufficient"]}
  },
  "tpm_recommendations": ["Enable attestation", "Implement measured boot"],
  "eol_management": {"legacy_hsm": ["Migrate keys", "Zeroize", "Physical destruction"]}
}
```

**Barème** : 97/100

---

## EXERCICE 05 : third_party_risk_assessor

**Concepts couverts** (7 concepts - 3.29.3 a-g) :
- Third-Party Risk, Vendor Assessment, Security Questionnaires
- Certifications Review, Contract Security, Fourth-Party Risk, Continuous Monitoring

**Sujet** : Évaluateur de risques tiers avec analyse des certifications.

**Entrée JSON** :
```json
{
  "vendor": {"name": "CloudPayments", "data_access": ["cardholder_data"]},
  "certifications": [
    {"type": "PCI-DSS", "expiry": "2025-06-01"},
    {"type": "SOC2_Type2", "expiry": "2024-03-01"}
  ],
  "subprocessors": ["aws", "unknown_analytics"],
  "contract": {"audit_rights": false}
}
```

**Sortie attendue** :
```json
{
  "risk_tier": "critical",
  "certification_review": {
    "pci_dss": {"status": "valid"},
    "soc2": {"status": "expired", "action": "Request current report"}
  },
  "fourth_party_risk": {"unknown_analytics": "Undisclosed party - investigate"},
  "contract_gaps": ["No audit rights"],
  "recommendation": "conditional_approval"
}
```

**Barème** : 98/100

---

## EXERCICE 06 : vendor_lifecycle_manager

**Concepts couverts** (7 concepts - 3.29.3 h-n) :
- Vendor Tiering, Offboarding, Concentration Risk
- Incident Coordination, Cloud Provider Risk, API Security, Regulatory Requirements

**Sujet** : Gestionnaire du cycle de vie des fournisseurs.

**Entrée JSON** :
```json
{
  "vendor_portfolio": [
    {"name": "AWS", "spend_pct": 45, "criticality": "critical"},
    {"name": "DataAnalyticsCo", "status": "offboarding", "data_shared": ["customer_behavior"]}
  ],
  "regulatory_context": ["GDPR", "DORA"]
}
```

**Sortie attendue** :
```json
{
  "concentration_risk": {"aws": {"risk": "high", "mitigations": ["Multi-region", "Exit strategy"]}},
  "offboarding_checklist": {
    "DataAnalyticsCo": ["Data export request", "Revoke credentials", "Deletion confirmation"]
  },
  "dora_requirements": ["ICT risk register", "Exit strategies for critical vendors"]
}
```

**Barème** : 97/100

---

## EXERCICE 07 : secure_dev_environment_auditor

**Concepts couverts** (6 concepts - 3.29.4 a-f) :
- Developer Environment Security, Source Code Management
- Code Review Security, Build Environment, Artifact Management, Deployment Security

**Sujet** : Auditeur de sécurité des environnements de développement.

**Entrée JSON** :
```json
{
  "source_control": {"branch_protection": {"main": true, "develop": false}, "signed_commits": "optional"},
  "code_review": {"required_approvals": 1, "security_checklist": false},
  "build_pipeline": {"runners": "shared", "artifact_signing": false}
}
```

**Sortie attendue** :
```json
{
  "source_control_security": {"score": 70, "findings": ["develop unprotected", "Signed commits optional"]},
  "code_review_security": {"score": 55, "findings": ["Single approval", "No security checklist"]},
  "build_security": {"score": 60, "findings": ["Shared runners", "No artifact signing"]},
  "priority_fixes": ["Branch protection on develop", "Artifact signing with Sigstore"]
}
```

**Barème** : 97/100

---

## EXERCICE 08 : sdlc_security_integrator

**Concepts couverts** (6 concepts - 3.29.4 g-l) :
- Secrets in Development, Developer Training, Insider Threat
- Open Source Policy, Vulnerability Disclosure, Incident Response

**Sujet** : Intégrateur de sécurité dans le SDLC.

**Entrée JSON** :
```json
{
  "secrets_management": {"method": "env_files", "vault": false},
  "training": {"secure_coding": "onboarding_only", "supply_chain": "none"},
  "vulnerability_disclosure": {"security_txt": false, "bug_bounty": false}
}
```

**Sortie attendue** :
```json
{
  "secrets_management": {"risk": "high", "recommendation": "Implement Vault"},
  "training_gaps": ["No ongoing training", "No supply chain awareness"],
  "vulnerability_disclosure": {"needed": ["security.txt", "Response process"]},
  "insider_controls": ["Implement least privilege", "Dual review for sensitive code"]
}
```

**Barème** : 97/100

---

## EXERCICE 09 : supply_chain_attack_simulator

**Concepts couverts** (Synthèse - Attack patterns) :
- Attack chain analysis, Detection, Response

**Sujet** : Simulateur d'attaques supply chain pour exercices de réponse.

**Entrée JSON** :
```json
{
  "scenario": "dependency_compromise",
  "attack_vector": {"type": "typosquatting", "package": "lodassh", "payload": "credential_stealer"},
  "detection_capabilities": {"sca_scanning": true, "network_monitoring": true}
}
```

**Sortie attendue** :
```json
{
  "attack_chain": [
    {"phase": "Initial Access", "action": "Developer installs lodassh"},
    {"phase": "Execution", "action": "postinstall script runs"},
    {"phase": "Exfiltration", "action": "Credentials sent to C2"}
  ],
  "detection_points": ["Package name similarity check", "Network egress monitoring"],
  "response_playbook": ["Isolate systems", "Revoke credentials", "Remove package", "Notify team"]
}
```

**Barème** : 96/100

---

## EXERCICE 10 : end_to_end_supply_chain_assessment

**Concepts couverts** (Synthèse globale) :
- Software + Hardware + Third-party integration

**Sujet** : Évaluation complète de la sécurité supply chain.

**Entrée JSON** :
```json
{
  "assessment_scope": {
    "software": {"sbom_coverage": 0.3, "slsa_level": 1},
    "hardware": {"verified_provenance": 0.6},
    "third_parties": {"critical": 10, "assessed": 6}
  }
}
```

**Sortie attendue** :
```json
{
  "overall_risk_score": 72,
  "maturity_assessment": {
    "software": {"score": 35, "target": 80},
    "hardware": {"score": 45, "target": 75},
    "third_party": {"score": 50, "target": 85}
  },
  "roadmap": {
    "q1": ["Complete SBOM", "Assess remaining vendors"],
    "q2": ["SLSA Level 2", "Hardware provenance audit"],
    "q3": ["SLSA Level 3", "Continuous monitoring"]
  }
}
```

**Barème** : 97/100

---

## RÉCAPITULATIF MODULE 3.29

**Module** : Supply Chain Security
**Concepts couverts** : 54/54 (100%)
**Exercices** : 10
**Note moyenne** : 97.1/100

### Répartition des concepts :

| Sous-module | Concepts | Exercices |
|-------------|----------|-----------|
| 3.29.1 Software Supply Chain | 16 | Ex01-02 |
| 3.29.2 Hardware Supply Chain | 12 | Ex03-04 |
| 3.29.3 Third-Party Risk Management | 14 | Ex05-06 |
| 3.29.4 Secure Development Practices | 12 | Ex07-08 |
| Synthèse transversale | - | Ex09-10 |

### Thèmes couverts :
- SBOM, SLSA, Dependency Confusion, Typosquatting
- SolarWinds/Codecov/event-stream attack patterns
- Hardware Trojans, HSM, TPM, Counterfeit Detection
- Vendor Assessment, Certifications, Fourth-Party Risk
- Concentration Risk, Offboarding, DORA compliance
- Secrets Management, Vulnerability Disclosure
