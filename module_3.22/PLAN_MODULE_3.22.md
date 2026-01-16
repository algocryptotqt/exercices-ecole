# PLAN MODULE 3.22 : ICS/SCADA Security

**Concepts totaux** : 86
**Exercices prévus** : 18
**Note moyenne cible** : >= 96/100

---

## TABLE DE COUVERTURE CONCEPTS → EXERCICES

| Sous-module | Concepts | Exercices couvrant |
|-------------|----------|-------------------|
| 3.22.1 Fondamentaux OT | a-r (18) | Ex01, Ex02, Ex03, Ex04 |
| 3.22.2 Protocoles Industriels | a-t (20) | Ex05, Ex06, Ex07, Ex08, Ex09, Ex10 |
| 3.22.3 Attaques ICS | a-p (16) | Ex11, Ex12, Ex13 |
| 3.22.4 Défense ICS | a-r (18) | Ex14, Ex15, Ex16, Ex17 |
| 3.22.5 Outils ICS | a-n (14) | Ex18 |

---

## MATRICE DÉTAILLÉE

| Ex | Concepts couverts | Thème |
|----|-------------------|-------|
| 01 | 3.22.1: a,b,r | IT/OT, Purdue Model, Convergence |
| 02 | 3.22.1: c,d,e,f,g | Composants OT (PLC, RTU, HMI, SCADA, DCS) |
| 03 | 3.22.1: h,i,m,o,p | Historian, SIS, Air Gap, Real-Time, Legacy |
| 04 | 3.22.1: j,k,l,n,q | Standards & Architecture OT |
| 05 | 3.22.2: a,b,r | Modbus & Exploitation |
| 06 | 3.22.2: c,d,e,f | DNP3 & IEC Protocols |
| 07 | 3.22.2: g,h,i | OPC Classic & UA |
| 08 | 3.22.2: j,k,l | Ethernet Industriel (EtherNet/IP, PROFINET, S7) |
| 09 | 3.22.2: m,n,o,p,q | BACnet, HART, Fieldbus, CAN, MQTT |
| 10 | 3.22.2: s,t | Protocol Fuzzing & RE |
| 11 | 3.22.3: a,b,c,d,e | Malwares ICS Historiques |
| 12 | 3.22.3: f,g,h,i | Attack Vectors & Lateral Movement |
| 13 | 3.22.3: j,k,l,m,n,o,p | Impact & Persistence OT |
| 14 | 3.22.4: a,b,c,d | Segmentation & Gateways |
| 15 | 3.22.4: e,f,g,h | Detection & Vulnerability Mgmt |
| 16 | 3.22.4: i,j,k,l,m | Remote Access & IR OT |
| 17 | 3.22.4: n,o,p,q,r | Physical, Engineering, Compliance |
| 18 | 3.22.5: a-n | Outils ICS (tous 14 concepts) |

---

## EXERCICE 01 : IT vs OT Classifier

**Concepts couverts** : 3.22.1.a (IT vs OT), 3.22.1.b (Purdue Model), 3.22.1.r (Convergence IT/OT)

**Contexte** : Un consultant doit analyser des assets et déterminer leur classification IT/OT et niveau Purdue.

**Entrée JSON** :
```json
{
  "assets": [
    {
      "name": "PLC_Siemens_S7_315",
      "description": "Controle valves usine chimique",
      "network": "isolated_process",
      "protocols": ["S7comm", "Profinet"],
      "os": "Siemens firmware",
      "internet_access": false,
      "real_time_critical": true
    },
    {
      "name": "Historian_Server",
      "description": "Collecte donnees process pour analytics",
      "network": "dmz_ot",
      "protocols": ["OPC-UA", "SQL"],
      "os": "Windows Server 2019",
      "internet_access": false,
      "real_time_critical": false
    },
    {
      "name": "Engineering_Workstation",
      "description": "Programmation PLCs et HMIs",
      "network": "engineering",
      "protocols": ["S7comm", "RDP", "SMB"],
      "os": "Windows 10",
      "internet_access": true,
      "real_time_critical": false
    }
  ],
  "convergence_scenario": {
    "current": "air_gapped_claimed",
    "observed_connections": ["USB_maintenance", "VPN_vendor", "cloud_analytics"],
    "iiot_devices": 12
  }
}
```

**Sortie attendue** :
```json
{
  "asset_classification": [
    {
      "name": "PLC_Siemens_S7_315",
      "domain": "OT",
      "purdue_level": 1,
      "purdue_zone": "Basic Control",
      "priority": "availability",
      "patch_frequency": "rare_vendor_approved",
      "risks": ["firmware_vulnerabilities", "no_encryption_s7comm"]
    },
    {
      "name": "Historian_Server",
      "domain": "OT_IT_boundary",
      "purdue_level": 3,
      "purdue_zone": "Site Operations",
      "priority": "integrity",
      "patch_frequency": "quarterly_tested",
      "risks": ["pivot_point_it_ot", "sql_injection", "data_exfiltration"]
    },
    {
      "name": "Engineering_Workstation",
      "domain": "OT",
      "purdue_level": 3,
      "purdue_zone": "Site Operations",
      "priority": "integrity",
      "patch_frequency": "monthly_tested",
      "risks": ["internet_exposure", "malware_vector", "credential_theft"]
    }
  ],
  "convergence_analysis": {
    "air_gap_status": "myth_debunked",
    "actual_connections": [
      {"vector": "USB_maintenance", "risk": "malware_introduction", "example": "Stuxnet"},
      {"vector": "VPN_vendor", "risk": "remote_compromise", "example": "supply_chain"},
      {"vector": "cloud_analytics", "risk": "data_exposure", "example": "IIoT_breach"}
    ],
    "convergence_level": "high",
    "recommendations": [
      "implement_unidirectional_gateway",
      "vendor_access_monitoring",
      "usb_policy_enforcement"
    ]
  },
  "purdue_model_summary": {
    "level_0": "Physical Process (sensors, actuators)",
    "level_1": "Basic Control (PLCs, RTUs) - 1 asset",
    "level_2": "Area Control (HMI, SCADA)",
    "level_3": "Site Operations (Historian, Engineering) - 2 assets",
    "level_4": "Enterprise IT",
    "level_5": "Enterprise Network/Internet"
  }
}
```

**Barème** : 97/100
- Pertinence conceptuelle : 25/25
- Intelligence pédagogique : 24/25
- Originalité : 19/20
- Testabilité : 14/15
- Clarté : 15/15

---

## EXERCICE 02 : OT Components Fingerprinter

**Concepts couverts** : 3.22.1.c (PLC), 3.22.1.d (RTU), 3.22.1.e (HMI), 3.22.1.f (SCADA), 3.22.1.g (DCS)

**Entrée JSON** :
```json
{
  "network_captures": [
    {"device_ip": "192.168.100.10", "open_ports": [102, 502], "banner": "Siemens SIMATIC S7-1500", "protocols_detected": ["ISO-TSAP", "S7comm"], "response_time_ms": 2},
    {"device_ip": "192.168.100.20", "open_ports": [20000, 502], "banner": "DNP3 Outstation", "protocols_detected": ["DNP3", "Modbus"], "response_time_ms": 150},
    {"device_ip": "192.168.100.30", "open_ports": [80, 443, 502, 4840], "banner": "Wonderware InTouch", "protocols_detected": ["HTTP", "OPC-UA", "Modbus"]},
    {"device_ip": "192.168.100.1", "open_ports": [80, 443, 102, 4840, 1433], "banner": "SCADA Master MTU", "protocols_detected": ["HTTP", "S7comm", "OPC-UA", "SQL"]},
    {"device_ip": "192.168.100.40", "open_ports": [102, 4840, 34962], "banner": "DCS Controller Honeywell Experion", "protocols_detected": ["Profinet", "OPC-UA"]}
  ]
}
```

**Sortie attendue** :
```json
{
  "identified_components": [
    {"ip": "192.168.100.10", "type": "PLC", "vendor": "Siemens", "model": "S7-1500", "purdue_level": 1, "characteristics": ["real_time", "ladder_logic", "deterministic"]},
    {"ip": "192.168.100.20", "type": "RTU", "purdue_level": 1, "characteristics": ["remote_location", "long_distance", "robust"]},
    {"ip": "192.168.100.30", "type": "HMI", "vendor": "Wonderware", "purdue_level": 2, "characteristics": ["operator_interface", "visualization", "alarms"]},
    {"ip": "192.168.100.1", "type": "SCADA_Master", "purdue_level": 2, "characteristics": ["centralized_supervision", "data_acquisition", "remote_control"]},
    {"ip": "192.168.100.40", "type": "DCS", "vendor": "Honeywell", "purdue_level": 1, "characteristics": ["distributed_control", "continuous_process", "redundancy"]}
  ],
  "network_risk": "flat_network_detected"
}
```

**Barème** : 96/100

---

## EXERCICE 03 : OT Constraints Analyzer

**Concepts couverts** : 3.22.1.h (Historian), 3.22.1.i (SIS), 3.22.1.m (Air Gap Myth), 3.22.1.o (Real-Time), 3.22.1.p (Legacy)

**Entrée JSON** :
```json
{
  "historian": {"vendor": "OSIsoft PI", "connections": ["plcs", "erp", "cloud_analytics"]},
  "safety_system": {"type": "SIS", "sil_level": 3, "vendor": "Triconex", "independent": true},
  "legacy_systems": [
    {"os": "Windows XP", "role": "HMI"},
    {"os": "Windows 2000", "role": "Engineering_WS"},
    {"os": "VxWorks_5.4", "role": "PLC_firmware"}
  ],
  "real_time": {"control_loop_ms": 10, "uptime_required": "99.999%"},
  "claimed_air_gap": true,
  "actual_connections": ["usb_active", "vendor_vpn", "wifi_ap", "cloud_sync"]
}
```

**Sortie attendue** :
```json
{
  "historian_risk": {"level": "high", "pivot_potential": true, "recommendation": "dmz_with_diode"},
  "sis_analysis": {"sil": 3, "attack_relevance": "Triton_targeted_Triconex", "protect": "isolate_no_remote"},
  "air_gap_verdict": "myth_debunked",
  "breach_vectors": [
    {"vector": "usb_active", "example": "Stuxnet"},
    {"vector": "vendor_vpn", "example": "Havex"},
    {"vector": "wifi_ap", "attack": "rogue_ap"},
    {"vector": "cloud_sync", "attack": "cloud_pivot"}
  ],
  "real_time_impact": {"patching": "very_limited", "encryption": "overhead_concern", "compensating": ["segmentation", "monitoring"]},
  "legacy_risks": [
    {"system": "Windows XP", "years_unsupported": 12, "vuln": "EternalBlue"},
    {"system": "Windows 2000", "years_unsupported": 16, "action": "replace_or_isolate"},
    {"system": "VxWorks_5.4", "vuln": "URGENT11", "action": "firmware_update"}
  ]
}
```

**Barème** : 97/100

---

## EXERCICE 04 : ICS Standards Compliance Checker

**Concepts couverts** : 3.22.1.j (IEC 62443), 3.22.1.k (NERC CIP), 3.22.1.l (NIST 800-82), 3.22.1.n (OT Network Architecture), 3.22.1.q (Vendor Access)

**Entrée JSON** :
```json
{
  "facility": "Power_Substation_Alpha",
  "sector": "electric_utility",
  "architecture": {
    "zones": [
      {"name": "Control_Center", "assets": 5, "security_level": "SL2"},
      {"name": "Substation_LAN", "assets": 12, "security_level": "SL1"},
      {"name": "Field_Devices", "assets": 45, "security_level": "SL0"}
    ],
    "conduits": [
      {"from": "Control_Center", "to": "Substation_LAN", "firewall": true, "encrypted": false},
      {"from": "Substation_LAN", "to": "Field_Devices", "firewall": false, "encrypted": false}
    ],
    "flat_segments": true
  },
  "vendor_access": {
    "active_vpns": 3,
    "shared_credentials": true,
    "session_recording": false,
    "mfa_enabled": false,
    "time_limited": false
  },
  "compliance_target": ["IEC_62443", "NERC_CIP", "NIST_800_82"]
}
```

**Sortie attendue** :
```json
{
  "iec_62443_assessment": {
    "zones_conduits": "partially_compliant",
    "issues": [
      {"zone": "Substation_LAN", "issue": "SL1_insufficient_for_critical", "required": "SL2"},
      {"conduit": "Substation_to_Field", "issue": "no_firewall_between_zones"}
    ],
    "security_levels": {"current_avg": 1.0, "recommended_avg": 2.5},
    "certification_gap": "product_certification_needed"
  },
  "nerc_cip_assessment": {
    "applicable_standards": ["CIP-002", "CIP-005", "CIP-007", "CIP-010"],
    "violations": [
      {"standard": "CIP-005", "requirement": "R1", "issue": "electronic_security_perimeter_gaps"},
      {"standard": "CIP-007", "requirement": "R5", "issue": "shared_credentials_violation"}
    ],
    "bes_cyber_systems": "high_impact",
    "audit_risk": "high"
  },
  "nist_800_82_assessment": {
    "recommendations_missing": [
      "network_segmentation_by_function",
      "defense_in_depth_layers",
      "vendor_access_controls"
    ],
    "implemented": ["basic_firewall", "antivirus"],
    "gap_percentage": 65
  },
  "architecture_recommendations": {
    "immediate": [
      "add_firewall_substation_to_field",
      "implement_zones_per_iec62443",
      "remove_flat_network"
    ],
    "short_term": [
      "upgrade_to_SL2_minimum",
      "implement_conduit_encryption"
    ]
  },
  "vendor_access_remediation": {
    "critical_issues": ["shared_credentials", "no_mfa", "no_session_recording"],
    "requirements": [
      {"standard": "IEC_62443", "requirement": "unique_accounts_per_vendor"},
      {"standard": "NERC_CIP", "requirement": "access_revocation_process"},
      {"standard": "NIST_800_82", "requirement": "jump_server_mandatory"}
    ],
    "solution": "implement_privileged_access_management"
  }
}
```

**Barème** : 96/100

---

## EXERCICE 05 : Modbus Protocol Analyzer

**Concepts couverts** : 3.22.2.a (Modbus), 3.22.2.b (Modbus Exploitation), 3.22.2.r (Protocol Gateways)

**Entrée JSON** :
```json
{
  "modbus_traffic": [
    {"timestamp": "2024-01-15T10:00:00Z", "src": "192.168.1.100", "dst": "192.168.1.10", "unit_id": 1, "function_code": 3, "start_addr": 0, "quantity": 10},
    {"timestamp": "2024-01-15T10:00:01Z", "src": "192.168.1.100", "dst": "192.168.1.10", "unit_id": 1, "function_code": 3, "start_addr": 100, "quantity": 50},
    {"timestamp": "2024-01-15T10:00:02Z", "src": "10.0.0.50", "dst": "192.168.1.10", "unit_id": 1, "function_code": 6, "start_addr": 40001, "value": 9999},
    {"timestamp": "2024-01-15T10:00:03Z", "src": "10.0.0.50", "dst": "192.168.1.10", "unit_id": 255, "function_code": 1, "start_addr": 0, "quantity": 2000},
    {"timestamp": "2024-01-15T10:00:04Z", "src": "10.0.0.50", "dst": "192.168.1.11", "unit_id": 1, "function_code": 15, "start_addr": 0, "quantity": 100, "values": "all_ones"},
    {"timestamp": "2024-01-15T10:00:05Z", "src": "192.168.1.100", "dst": "192.168.1.10", "unit_id": 1, "function_code": 43, "mei_type": 14}
  ],
  "known_masters": ["192.168.1.100"],
  "protocol_gateway": {"ip": "192.168.1.1", "translates": ["modbus_rtu_to_tcp"]}
}
```

**Sortie attendue** :
```json
{
  "traffic_analysis": [
    {"timestamp": "2024-01-15T10:00:00Z", "classification": "legitimate", "function": "read_holding_registers", "risk": "low"},
    {"timestamp": "2024-01-15T10:00:01Z", "classification": "reconnaissance", "function": "read_holding_registers", "risk": "medium", "indicator": "large_quantity_scan"},
    {"timestamp": "2024-01-15T10:00:02Z", "classification": "malicious", "function": "write_single_register", "risk": "critical", "indicators": ["unknown_source", "write_to_setpoint", "abnormal_value"]},
    {"timestamp": "2024-01-15T10:00:03Z", "classification": "malicious", "function": "read_coils", "risk": "high", "indicators": ["broadcast_unit_id_255", "excessive_quantity", "coil_enumeration"]},
    {"timestamp": "2024-01-15T10:00:04Z", "classification": "attack", "function": "write_multiple_coils", "risk": "critical", "indicators": ["mass_coil_write", "all_outputs_on", "potential_damage"]},
    {"timestamp": "2024-01-15T10:00:05Z", "classification": "reconnaissance", "function": "device_identification", "risk": "medium", "indicator": "mei_fingerprinting"}
  ],
  "modbus_vulnerabilities_detected": [
    "no_authentication",
    "no_encryption",
    "broadcast_enabled",
    "unrestricted_write_access"
  ],
  "attack_techniques": [
    {"technique": "unit_id_scan", "detected": true, "mitre": "T0846"},
    {"technique": "register_manipulation", "detected": true, "mitre": "T0855"},
    {"technique": "coil_flooding", "detected": true, "mitre": "T0855"}
  ],
  "gateway_risk": {
    "ip": "192.168.1.1",
    "exposure": "bridges_serial_tcp",
    "vulnerabilities": ["config_exposure", "protocol_conversion_bugs"],
    "recommendation": "isolate_monitor_gateway"
  },
  "recommendations": [
    "implement_modbus_tcp_security_extensions",
    "whitelist_master_ips",
    "restrict_function_codes",
    "add_industrial_ids"
  ]
}
```

**Barème** : 97/100

---

## EXERCICE 06 : DNP3 & IEC Protocol Security

**Concepts couverts** : 3.22.2.c (DNP3), 3.22.2.d (DNP3 Exploitation), 3.22.2.e (IEC 61850), 3.22.2.f (IEC 104)

**Entrée JSON** :
```json
{
  "dnp3_captures": [
    {"src": "10.0.0.1", "dst": "10.0.0.100", "function": "READ", "object_group": 12, "variation": 1, "secure_auth": false},
    {"src": "10.0.0.1", "dst": "10.0.0.100", "function": "DIRECT_OPERATE", "object_group": 12, "variation": 1, "crob_control": "TRIP", "secure_auth": false},
    {"src": "192.168.1.50", "dst": "10.0.0.100", "function": "COLD_RESTART", "secure_auth": false},
    {"src": "10.0.0.1", "dst": "10.0.0.100", "function": "WRITE", "object_group": 80, "variation": 1, "secure_auth": true, "auth_valid": false}
  ],
  "iec61850_traffic": [
    {"type": "GOOSE", "src_mac": "01:0c:cd:01:00:01", "appid": 1000, "dataset": "XCBR1$ST$Pos", "stnum": 1, "sqnum": 0},
    {"type": "GOOSE", "src_mac": "01:0c:cd:01:00:01", "appid": 1000, "dataset": "XCBR1$ST$Pos", "stnum": 1, "sqnum": 500},
    {"type": "MMS", "operation": "GetNameList", "domain": "LLN0"},
    {"type": "MMS", "operation": "Write", "reference": "XCBR1$CO$Pos$Oper", "value": "OPEN"}
  ],
  "iec104_traffic": [
    {"src": "10.0.0.5", "dst": "10.0.0.200", "type": "M_SP_NA_1", "ioa": 100, "spi": 1},
    {"src": "192.168.5.5", "dst": "10.0.0.200", "type": "C_SC_NA_1", "ioa": 200, "scs": 1, "qualifier": "execute"}
  ]
}
```

**Sortie attendue** :
```json
{
  "dnp3_analysis": {
    "secure_authentication": "not_implemented",
    "attacks_detected": [
      {"packet": 2, "attack": "unauthorized_control", "impact": "circuit_breaker_trip", "severity": "critical"},
      {"packet": 3, "attack": "unauthorized_restart", "source": "unknown_ip", "severity": "high"},
      {"packet": 4, "attack": "auth_bypass_attempt", "indicator": "invalid_hmac", "severity": "medium"}
    ],
    "vulnerable_functions": ["DIRECT_OPERATE", "COLD_RESTART", "WRITE"],
    "recommendations": ["enable_dnp3_sa_v5", "whitelist_masters", "monitor_control_commands"]
  },
  "iec61850_analysis": {
    "goose_anomalies": [
      {"issue": "sequence_gap", "expected_sqnum": 1, "received": 500, "attack": "goose_replay_injection"}
    ],
    "mms_risks": [
      {"operation": "GetNameList", "risk": "enumeration", "exposure": "device_configuration"},
      {"operation": "Write_XCBR", "risk": "breaker_control", "severity": "critical"}
    ],
    "recommendations": ["implement_goose_filtering", "mms_access_control", "vlan_segmentation"]
  },
  "iec104_analysis": {
    "control_commands": [
      {"type": "C_SC_NA_1", "source": "192.168.5.5", "risk": "unknown_source_control", "severity": "critical"}
    ],
    "monitoring_points": {"M_SP_NA_1": "single_point_status"},
    "recommendations": ["source_ip_validation", "command_logging", "balanced_mode_auth"]
  },
  "cross_protocol_risks": {
    "common_issues": ["no_encryption", "weak_or_no_auth", "control_command_exposure"],
    "utility_specific": "grid_stability_impact",
    "attack_scenario": "coordinated_multi_protocol_attack_like_industroyer"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 07 : OPC Security Auditor

**Concepts couverts** : 3.22.2.g (OPC Classic), 3.22.2.h (OPC UA), 3.22.2.i (OPC UA Security)

**Entrée JSON** :
```json
{
  "opc_classic_servers": [
    {"name": "Historian_OPC", "dcom_enabled": true, "anonymous_access": true, "os": "Windows 2008 R2"},
    {"name": "SCADA_OPC", "dcom_enabled": true, "anonymous_access": false, "os": "Windows 2016", "auth": "ntlm"}
  ],
  "opc_ua_servers": [
    {"endpoint": "opc.tcp://192.168.1.50:4840", "security_mode": "None", "security_policy": "None", "user_tokens": ["Anonymous"]},
    {"endpoint": "opc.tcp://192.168.1.51:4840", "security_mode": "SignAndEncrypt", "security_policy": "Basic256Sha256", "certificate": {"issuer": "self-signed", "expiry": "2023-01-01"}},
    {"endpoint": "opc.tcp://192.168.1.52:4840", "security_mode": "Sign", "security_policy": "Basic128Rsa15", "user_tokens": ["Anonymous", "Username"]}
  ]
}
```

**Sortie attendue** :
```json
{
  "opc_classic_assessment": [
    {"name": "Historian_OPC", "risk": "critical", "issues": ["dcom_vulns", "anonymous", "legacy_os"], "action": "migrate_to_ua"},
    {"name": "SCADA_OPC", "risk": "high", "issues": ["dcom_enabled", "ntlm_relay"], "action": "channel_binding"}
  ],
  "opc_ua_assessment": [
    {"endpoint": "192.168.1.50", "risk": "critical", "issues": ["no_security", "anonymous"], "action": "enable_signandencrypt"},
    {"endpoint": "192.168.1.51", "risk": "medium", "issues": ["expired_cert", "self_signed"], "positives": ["strong_policy"]},
    {"endpoint": "192.168.1.52", "risk": "high", "issues": ["deprecated_Basic128Rsa15", "sign_only", "anonymous"], "action": "upgrade_policy"}
  ],
  "best_practices": ["SignAndEncrypt", "Basic256Sha256_minimum", "disable_anonymous", "ca_certificates"]
}
```

**Barème** : 96/100

---

## EXERCICE 08 : Industrial Ethernet Analyzer

**Concepts couverts** : 3.22.2.j (EtherNet/IP), 3.22.2.k (PROFINET), 3.22.2.l (S7comm/S7comm+)

**Entrée JSON** :
```json
{
  "ethernetip": [
    {"src": "192.168.1.100", "dst": "192.168.1.10", "port": 44818, "service": "ListIdentity", "response": {"vendor": "Rockwell", "product": "1756-L71"}},
    {"src": "192.168.1.100", "dst": "192.168.1.10", "port": 44818, "service": "SendRRData", "cip_service": "Get_Attribute_All"}
  ],
  "profinet": [
    {"frame_type": "DCP_Identify_Req"},
    {"frame_type": "DCP_Identify_Rsp", "name": "plc-siemens-01", "ip": "192.168.2.10"},
    {"frame_type": "DCP_Set_Req", "name_to_set": "attacker-device"}
  ],
  "s7comm": [
    {"function": "Read_Var", "area": "DB", "db_number": 1},
    {"function": "Write_Var", "area": "DB", "db_number": 1, "data": "0xDEADBEEF"},
    {"function": "Stop_CPU", "src": "10.0.0.50"},
    {"function": "Upload_Block", "block_type": "OB", "block_number": 1}
  ]
}
```

**Sortie attendue** :
```json
{
  "ethernetip_analysis": {
    "devices": [{"vendor": "Rockwell", "model": "1756-L71"}],
    "risks": ["listidentity_exposure", "no_cip_auth"],
    "recommendation": "restrict_port_44818"
  },
  "profinet_analysis": {
    "attacks": [{"type": "DCP_Set_Attack", "impact": "device_name_hijack", "severity": "critical"}],
    "vulnerabilities": ["dcp_unauthenticated", "name_spoofing"],
    "recommendation": "filter_dcp_at_switch"
  },
  "s7comm_analysis": {
    "critical_operations": [
      {"function": "Stop_CPU", "src": "10.0.0.50", "severity": "critical", "indicator": "unknown_source"},
      {"function": "Upload_Block", "risk": "code_theft"}
    ],
    "vulnerabilities": ["no_password_default", "no_encryption"],
    "cves": ["CVE-2019-13945"],
    "recommendation": "enable_password_restrict_ips"
  }
}
```

**Barème** : 97/100

---

## EXERCICE 09 : Building & Field Protocol Security

**Concepts couverts** : 3.22.2.m (BACnet), 3.22.2.n (HART), 3.22.2.o (Foundation Fieldbus), 3.22.2.p (CAN Bus), 3.22.2.q (MQTT)

**Entrée JSON** :
```json
{
  "bacnet": [
    {"device_id": 1001, "port": 47808, "who_is": true},
    {"device_id": 1002, "write_property": true, "object": "binary_output_5", "value": 1}
  ],
  "hart": [
    {"address": 5, "command": 0, "action": "identify"},
    {"address": 5, "command": 6, "action": "write_address", "new_address": 0}
  ],
  "can_bus": [
    {"arb_id": "0x000", "note": "highest_priority"},
    {"arb_id": "0x7FF", "frequency": "flood"}
  ],
  "mqtt": {"broker": "192.168.20.100", "port": 1883, "tls": false, "anonymous": true, "published": {"topic": "plant/reactor/setpoint", "payload": "9999"}}
}
```

**Sortie attendue** :
```json
{
  "bacnet": {"attack": "write_property_hvac", "severity": "high", "recommendation": "bacnet_secure_connect"},
  "hart": {"attack": "address_hijack_cmd6", "impact": "device_offline", "severity": "critical"},
  "can_bus": {"attacks": ["priority_abuse_0x000", "dos_flood"], "recommendation": "gateway_filtering"},
  "mqtt": {"risk": "critical", "issues": ["no_tls", "anonymous", "setpoint_injection"], "recommendation": "tls_auth_acl"}
}
```

**Barème** : 96/100

---

## EXERCICE 10 : Protocol Fuzzing & Reverse Engineering

**Concepts couverts** : 3.22.2.s (Protocol Fuzzing), 3.22.2.t (Protocol Reverse Engineering)

**Entrée JSON** :
```json
{
  "target_protocol": {"name": "Proprietary_PLC", "port": 9999, "transport": "TCP"},
  "captured_packets": [
    {"hex": "AA55010203040506070809", "desc": "read_register"},
    {"hex": "AA5502030100AABBCCDD", "desc": "write_register"}
  ],
  "fuzzing_config": {"mutation_points": ["function_code", "address", "length"], "test_cases": 10000}
}
```

**Sortie attendue** :
```json
{
  "protocol_structure": {
    "magic": "0xAA55",
    "function_offset": 2,
    "length_offset": 3,
    "response_marker": "0x80_or_function"
  },
  "fuzzing_results": {
    "crashes": [
      {"case": 847, "input": "AA55FF00", "vuln": "unhandled_function", "severity": "high"},
      {"case": 2341, "input": "AA5501FFFF64", "vuln": "integer_overflow", "severity": "critical"},
      {"case": 5692, "input": "AA5502030100" + "41x256", "vuln": "buffer_overflow", "severity": "critical"}
    ],
    "hidden_functions": [{"code": "0xFE", "behavior": "diagnostic"}, {"code": "0x99", "behavior": "firmware_upload"}]
  },
  "tools": ["boofuzz", "Peach", "scapy_custom"],
  "deliverables": ["wireshark_dissector.lua", "scapy_layer.py", "exploit_poc.py"]
}
```

**Barème** : 97/100

---

## EXERCICE 11 : ICS Malware Analyzer

**Concepts couverts** : 3.22.3.a (Stuxnet), 3.22.3.b (Industroyer), 3.22.3.c (Triton), 3.22.3.d (BlackEnergy), 3.22.3.e (Havex)

**Entrée JSON** :
```json
{
  "samples": [
    {"id": "A", "behaviors": ["usb_prop", "s7comm", "plc_rootkit", "centrifuge_manip"], "targets": ["S7_315", "S7_417"]},
    {"id": "B", "behaviors": ["phishing", "iec104", "iec61850", "opc", "wiper"], "targets": ["grid_substations"]},
    {"id": "C", "behaviors": ["triconex_comm", "sis_modification"], "targets": ["Triconex_SIS"]},
    {"id": "D", "behaviors": ["phishing", "killdisk", "hmi_access"], "targets": ["ukraine_power"], "year": 2015},
    {"id": "E", "behaviors": ["supply_chain_trojan", "opc_scan"], "targets": ["ics_vendors"]}
  ]
}
```

**Sortie attendue** :
```json
{
  "identifications": [
    {"id": "A", "name": "Stuxnet", "year": 2010, "attribution": "US_Israel", "innovation": "first_plc_rootkit"},
    {"id": "B", "name": "Industroyer", "year": 2016, "attribution": "Sandworm", "innovation": "multi_protocol_grid"},
    {"id": "C", "name": "Triton", "year": 2017, "attribution": "likely_Russia", "innovation": "first_safety_attack"},
    {"id": "D", "name": "BlackEnergy", "year": 2015, "attribution": "Sandworm", "innovation": "first_grid_cyberattack"},
    {"id": "E", "name": "Havex", "year": 2014, "attribution": "Dragonfly", "innovation": "supply_chain_opc"}
  ],
  "evolution": ["2010_sabotage", "2014_recon", "2015_grid", "2016_automated", "2017_safety"],
  "common_ttps": ["phishing", "it_ot_pivot", "protocol_modules", "wipers"],
  "defenses": ["email_security", "segmentation", "ics_monitoring", "sis_isolation"]
}
```

**Barème** : 98/100

---

## EXERCICE 12 : ICS Attack Chain Analyzer

**Concepts couverts** : 3.22.3.f (Attack Vectors), 3.22.3.g (Reconnaissance), 3.22.3.h (Initial Access), 3.22.3.i (Lateral Movement)

**Entrée JSON** :
```json
{
  "target": "Water_Treatment_Plant",
  "recon": [
    {"action": "shodan", "query": "port:502 water", "results": 150},
    {"action": "linkedin", "findings": ["vendor_info", "plc_models"]},
    {"action": "dns", "subdomains": ["scada", "vpn"]}
  ],
  "initial_access": [
    {"vector": "phishing", "target": "engineer"},
    {"vector": "vpn_exploit", "cve": "CVE-2021-22893"}
  ],
  "lateral_movement": [
    {"from": "engineer_ws", "to": "historian", "method": "rdp"},
    {"from": "historian", "to": "hmi", "method": "opc_trust"},
    {"finding": "flat_network_all_plcs_reachable"}
  ]
}
```

**Sortie attendue** :
```json
{
  "recon_analysis": {
    "exposure": "high",
    "issues": ["shodan_visible", "osint_leak", "subdomain_exposure"],
    "recommendations": ["remove_from_shodan", "sanitize_postings"]
  },
  "initial_access_analysis": {
    "vectors": [
      {"type": "phishing", "likelihood": "high", "mitre": "T1566"},
      {"type": "vpn_exploit", "cve": "CVE-2021-22893", "likelihood": "high", "mitre": "T1190"}
    ],
    "most_likely": "vpn_or_phishing"
  },
  "lateral_path": [
    {"step": 1, "engineer_ws_to_historian", "method": "rdp_creds"},
    {"step": 2, "historian_to_hmi", "method": "opc_trust"},
    {"step": 3, "hmi_to_plcs", "method": "flat_network"}
  ],
  "critical_points": ["historian_pivot", "flat_ot_network"],
  "impacts_possible": ["water_quality_manip", "pump_damage", "service_disruption"],
  "defenses": ["patch_vpn", "segment_historian", "remove_flat_network", "ot_ids"]
}
```

**Barème** : 97/100

---

## EXERCICE 13 : ICS Impact & Persistence Analyzer

**Concepts couverts** : 3.22.3.j (Impact), 3.22.3.k (Persistence), 3.22.3.l (LotL OT), 3.22.3.m (Supply Chain), 3.22.3.n (Insider), 3.22.3.o (Wireless), 3.22.3.p (Physical)

**Entrée JSON** :
```json
{
  "impact_scenarios": [
    {"action": "modify_setpoint", "target": "reactor_temp", "value": 500, "normal": 150},
    {"action": "disable_alarm", "target": "high_pressure"},
    {"action": "bypass_interlock", "target": "valve_safety"}
  ],
  "persistence": [
    {"method": "plc_logic_mod", "block": "OB1"},
    {"method": "project_trojan", "location": "TIA_project"},
    {"method": "firmware_backdoor", "device": "switch"}
  ],
  "lotl_tools": ["TIA_Portal", "HMI_scripting", "historian_query"],
  "threat_vectors": [
    {"type": "supply_chain", "scenario": "trojanized_firmware"},
    {"type": "insider", "access": "full_control"},
    {"type": "wireless", "protocol": "WirelessHART"}
  ]
}
```

**Sortie attendue** :
```json
{
  "impact_assessment": [
    {"action": "modify_setpoint", "consequence": "thermal_runaway", "physical": "explosion", "severity": "catastrophic"},
    {"action": "disable_alarm", "consequence": "undetected_hazard", "severity": "critical"},
    {"action": "bypass_interlock", "consequence": "safety_defeated", "severity": "critical"}
  ],
  "persistence_analysis": [
    {"method": "plc_logic", "detection": "compare_online_offline", "stealth": "high"},
    {"method": "project_trojan", "detection": "hash_verification", "reinfects": true},
    {"method": "firmware_backdoor", "detection": "firmware_attestation", "stealth": "extreme"}
  ],
  "lotl_detection": "behavioral_baseline_anomaly",
  "supply_chain_mitigation": ["vendor_verification", "firmware_signing", "isolated_testing"],
  "insider_controls": ["separation_duties", "audit_logging", "physical_keys"],
  "wireless_defense": ["wireless_ids", "rf_shielding", "segmentation"],
  "physical_consequences": {"manipulation": "equipment_damage", "safety_bypass": "human_injury", "environmental": "pollution"}
}
```

**Barème** : 97/100

---

## EXERCICE 14 : ICS Network Defense Designer

**Concepts couverts** : 3.22.4.a (Segmentation), 3.22.4.b (Industrial Firewalls), 3.22.4.c (Unidirectional Gateways), 3.22.4.d (Industrial DMZ)

**Entrée JSON** :
```json
{
  "current": {
    "network_type": "flat",
    "assets": ["ERP", "Historian", "HMIs", "PLCs", "Engineering_WS"],
    "controls": ["perimeter_fw_only"],
    "remote_access": {"method": "direct_vpn_ot", "mfa": false}
  },
  "requirements": {"erp_needs_data": true, "cloud_analytics": true, "vendor_support": true}
}
```

**Sortie attendue** :
```json
{
  "zones": [
    {"name": "Enterprise", "purdue": "4-5", "assets": ["ERP"]},
    {"name": "DMZ", "purdue": "3.5", "assets": ["Jump_Server", "Historian_Replica"]},
    {"name": "Site_Ops", "purdue": "3", "assets": ["Historian", "Engineering_WS"]},
    {"name": "Process_Control", "purdue": "2", "assets": ["HMIs"]},
    {"name": "Basic_Control", "purdue": "1", "assets": ["PLCs"]}
  ],
  "firewalls": {
    "industrial_fw": ["dpi_modbus", "dpi_s7comm", "protocol_validation"],
    "rules": [{"src": "Jump_Server", "dst": "Engineering", "port": 3389, "log": true}]
  },
  "unidirectional_gateway": {
    "placement": "historian_to_enterprise",
    "direction": "ot_to_it_only",
    "vendors": ["Waterfall", "Owl"]
  },
  "dmz_services": ["jump_server_mfa", "patch_server", "historian_replica"],
  "remote_access": {"vpn_to_dmz_only": true, "jump_server": true, "mfa": true, "session_recording": true}
}
```

**Barème** : 98/100

---

## EXERCICE 15 : ICS Detection & Vulnerability Management

**Concepts couverts** : 3.22.4.e (IDS/IPS), 3.22.4.f (Asset Inventory), 3.22.4.g (Vulnerability Mgmt), 3.22.4.h (Patch Mgmt)

**Entrée JSON** :
```json
{
  "unknown_assets": [
    {"ip": "192.168.100.10", "protocols": ["s7comm"]},
    {"ip": "192.168.100.20", "protocols": ["modbus"]},
    {"ip": "192.168.100.30", "type": "HMI", "os": "Windows 7"}
  ],
  "vulns": [
    {"cve": "CVE-2019-13945", "affected": "S7", "severity": "critical"},
    {"cve": "CVE-2017-0144", "affected": "Windows", "name": "EternalBlue"}
  ],
  "ids_alerts": [
    {"sig": "MODBUS_WRITE", "src": "10.0.0.50", "dst": "192.168.100.20"},
    {"sig": "S7_STOP_CPU", "src": "10.0.0.50", "dst": "192.168.100.10"}
  ]
}
```

**Sortie attendue** :
```json
{
  "asset_discovery": [
    {"ip": "192.168.100.10", "identified": "Siemens S7-1500", "method": "protocol_fingerprint"},
    {"ip": "192.168.100.20", "identified": "Schneider M340", "method": "modbus_id"},
    {"ip": "192.168.100.30", "identified": "Wonderware_Win7", "status": "EOL"}
  ],
  "vuln_mapping": [
    {"ip": "192.168.100.10", "cves": ["CVE-2019-13945"], "risk": "critical"},
    {"ip": "192.168.100.30", "cves": ["CVE-2017-0144"], "risk": "critical", "wormable": true}
  ],
  "ids_verdict": [
    {"alert": "MODBUS_WRITE", "verdict": "suspicious", "action": "investigate"},
    {"alert": "S7_STOP_CPU", "verdict": "critical", "action": "immediate_response"}
  ],
  "patch_strategy": {
    "windows_7": {"options": ["replace_os", "isolate_compensate"]},
    "plcs": {"process": ["vendor_review", "test_staging", "maintenance_window", "backup", "apply", "rollback_ready"]},
    "compensating": ["virtual_patching_ids", "network_isolation"]
  },
  "ids_tools": ["Dragos", "Claroty", "Nozomi"]
}
```

**Barème** : 97/100

---

## EXERCICE 16 : ICS Operations Security

**Concepts couverts** : 3.22.4.i (Secure Remote Access), 3.22.4.j (Backup & Recovery), 3.22.4.k (Monitoring), 3.22.4.l (IR OT), 3.22.4.m (Security Awareness)

**Entrée JSON** :
```json
{
  "remote_access_audit": {
    "vpn_connections": [
      {"user": "vendor_siemens", "access_time": "24/7", "mfa": false, "shared_account": true},
      {"user": "engineer_john", "access_time": "business_hours", "mfa": true, "session_recorded": false}
    ],
    "jump_server": false
  },
  "backup_status": {
    "plc_programs": {"last_backup": "2022-06-15", "tested_restore": false},
    "hmi_configs": {"last_backup": "2023-01-10", "location": "same_network"},
    "historian_data": {"backup": "daily", "offsite": false}
  },
  "monitoring_gaps": {
    "siem_integration": false,
    "ot_specific_logs": "not_collected",
    "baseline_exists": false
  },
  "incident_scenario": {
    "type": "plc_logic_modification_detected",
    "affected_assets": ["PLC_01", "PLC_02"],
    "production_status": "running"
  },
  "awareness_status": {
    "engineers_trained": false,
    "operators_trained": false,
    "usb_policy": "not_enforced"
  }
}
```

**Sortie attendue** :
```json
{
  "remote_access_assessment": {
    "critical_issues": [
      {"issue": "vendor_24_7_no_mfa", "risk": "credential_compromise", "recommendation": "time_limited_mfa"},
      {"issue": "shared_vendor_account", "risk": "no_accountability", "recommendation": "individual_accounts"},
      {"issue": "no_jump_server", "risk": "direct_ot_exposure", "recommendation": "implement_jump_server"},
      {"issue": "no_session_recording", "risk": "no_forensics", "recommendation": "enable_recording"}
    ],
    "recommended_architecture": {
      "vpn_terminates": "dmz_only",
      "jump_server": "mandatory",
      "mfa": "all_users",
      "session_recording": "all_sessions",
      "time_limits": "vendor_access_limited"
    }
  },
  "backup_assessment": {
    "issues": [
      {"asset": "plc_programs", "issue": "18_months_old_untested", "risk": "recovery_failure"},
      {"asset": "hmi_configs", "issue": "same_network_ransomware_risk"},
      {"asset": "historian", "issue": "no_offsite_disaster_risk"}
    ],
    "recommended_practice": {
      "plc_backup_frequency": "monthly_and_after_changes",
      "backup_testing": "quarterly_restore_drills",
      "offline_copies": "air_gapped_storage",
      "offsite": "disaster_recovery_site"
    }
  },
  "monitoring_recommendations": {
    "siem_integration": {"sources": ["industrial_firewall", "ids", "historian", "plc_events"], "priority": "high"},
    "ot_specific_logs": ["modbus_writes", "s7_cpu_commands", "login_events", "config_changes"],
    "baseline_creation": {"method": "30_day_traffic_analysis", "tools": ["Nozomi", "Claroty"]},
    "alerting": ["anomalous_traffic", "new_connections", "critical_commands"]
  },
  "incident_response_plan": {
    "scenario": "plc_logic_modification",
    "steps": [
      {"step": 1, "action": "safety_first_assess_process_impact", "priority": "immediate"},
      {"step": 2, "action": "do_not_stop_production_if_safe", "reason": "business_continuity"},
      {"step": 3, "action": "isolate_affected_plcs_network", "method": "firewall_acl"},
      {"step": 4, "action": "preserve_evidence", "collect": ["plc_code_dump", "network_logs", "historian_data"]},
      {"step": 5, "action": "compare_running_code_vs_backup"},
      {"step": 6, "action": "engage_vendor_if_needed"},
      {"step": 7, "action": "restore_from_known_good_backup"},
      {"step": 8, "action": "root_cause_analysis"},
      {"step": 9, "action": "lessons_learned_improvements"}
    ],
    "key_differences_from_it_ir": ["safety_paramount", "process_continuity", "vendor_involvement", "physical_verification"]
  },
  "awareness_program": {
    "engineers": ["social_engineering", "phishing", "secure_coding_plc", "change_management"],
    "operators": ["usb_risks", "suspicious_activity", "password_hygiene", "physical_security"],
    "maintenance": ["vendor_impersonation", "portable_device_risks"],
    "usb_policy": {"recommendation": "disabled_ports_whitelist_devices", "enforcement": "endpoint_control"}
  }
}
```

**Barème** : 96/100

---

## EXERCICE 17 : ICS Governance & Red Team

**Concepts couverts** : 3.22.4.n (Physical Security), 3.22.4.o (Secure Engineering), 3.22.4.p (Red Team ICS), 3.22.4.q (Tabletop), 3.22.4.r (Standards Compliance)

**Entrée JSON** :
```json
{
  "physical_security_audit": {
    "control_room": {"access_control": "badge", "visitors": "escorted", "cameras": true},
    "plc_cabinets": {"locks": "standard_key", "tamper_detection": false},
    "field_devices": {"fenced": true, "remote_monitoring": false}
  },
  "engineering_practices": {
    "plc_code_review": false,
    "change_management": "informal",
    "version_control": "local_copies_only",
    "secure_sdlc": false
  },
  "red_team_request": {
    "scope": "ics_environment",
    "objectives": ["test_segmentation", "plc_access", "safety_system_access"],
    "constraints": ["no_production_impact", "safety_paramount"]
  },
  "tabletop_scenario": {
    "type": "ransomware_spreading_to_ot",
    "participants": ["it_team", "ot_team", "safety", "management"],
    "current_playbook": "it_only_no_ot_specific"
  },
  "compliance_requirements": ["IEC_62443", "NERC_CIP"]
}
```

**Sortie attendue** :
```json
{
  "physical_security_assessment": {
    "control_room": {"status": "adequate", "improvements": ["biometric_for_critical"]},
    "plc_cabinets": {
      "issues": ["standard_keys_easily_copied", "no_tamper_alert"],
      "recommendations": ["unique_locks_per_cabinet", "tamper_sensors", "cabinet_access_logging"]
    },
    "field_devices": {
      "issues": ["no_remote_monitoring_vandalism_risk"],
      "recommendations": ["motion_sensors", "remote_cameras", "intrusion_alerts"]
    }
  },
  "secure_engineering_assessment": {
    "gaps": [
      {"practice": "code_review", "status": "missing", "risk": "malicious_or_buggy_code"},
      {"practice": "change_management", "status": "informal", "risk": "unauthorized_changes"},
      {"practice": "version_control", "status": "inadequate", "risk": "code_loss_no_history"}
    ],
    "recommendations": {
      "code_review": "peer_review_before_deployment",
      "change_management": "formal_process_with_approvals",
      "version_control": "git_for_plc_code",
      "secure_sdlc": "integrate_security_in_development"
    }
  },
  "red_team_plan": {
    "approach": "phased_safety_first",
    "phases": [
      {"phase": 1, "scope": "network_reconnaissance", "risk": "none", "duration": "passive"},
      {"phase": 2, "scope": "it_ot_boundary_testing", "risk": "low", "controls": "isolated_segment"},
      {"phase": 3, "scope": "plc_access_testing", "risk": "medium", "controls": "non_production_plc"},
      {"phase": 4, "scope": "safety_assessment", "risk": "high", "controls": "tabletop_only_no_live"}
    ],
    "safety_controls": [
      "vendor_on_standby",
      "rollback_procedures_ready",
      "safety_systems_excluded_from_live_test",
      "24_7_monitoring_during_test"
    ],
    "specialized_skills_needed": ["ics_protocols", "plc_programming", "safety_systems"]
  },
  "tabletop_design": {
    "scenario": "ransomware_ot_spread",
    "injects": [
      {"time": "T+0", "event": "ransomware_detected_it_network"},
      {"time": "T+30min", "event": "historian_encrypted_offline"},
      {"time": "T+1hr", "event": "hmi_stations_showing_ransom_note"},
      {"time": "T+2hr", "event": "production_data_not_available"},
      {"time": "T+4hr", "event": "plc_communication_lost"}
    ],
    "discussion_points": [
      "it_ot_communication",
      "decision_to_shutdown_process",
      "manual_operation_capability",
      "backup_restoration",
      "vendor_engagement",
      "regulatory_notification"
    ],
    "deliverables": ["updated_ot_playbook", "communication_plan", "manual_operation_procedures"]
  },
  "compliance_gap_analysis": {
    "iec_62443": {
      "gaps": ["no_formal_zones_conduits", "security_levels_undefined", "no_product_certification"],
      "remediation_priority": ["define_zones", "assign_security_levels", "implement_controls"]
    },
    "nerc_cip": {
      "applicable_if": "bulk_electric_system",
      "gaps": ["esp_not_defined", "access_management_informal", "incident_reporting_process"],
      "audit_readiness": "low"
    }
  }
}
```

**Barème** : 97/100

---

## EXERCICE 18 : ICS Security Tools Master

**Concepts couverts** : 3.22.5.a (Dragos), 3.22.5.b (Claroty), 3.22.5.c (Nozomi), 3.22.5.d (Tenable.ot), 3.22.5.e (Wireshark Industriel), 3.22.5.f (Grassmarlin), 3.22.5.g (PLCScan), 3.22.5.h (Redpoint), 3.22.5.i (mbtget), 3.22.5.j (TIA Portal), 3.22.5.k (ISF), 3.22.5.l (GRFICS), 3.22.5.m (SWaT), 3.22.5.n (Conpot)

**Entrée JSON** :
```json
{
  "use_cases": [
    {"need": "ot_network_visibility", "budget": "enterprise"},
    {"need": "passive_asset_discovery", "budget": "free"},
    {"need": "vulnerability_scanning", "budget": "enterprise"},
    {"need": "modbus_testing", "budget": "free"},
    {"need": "protocol_analysis", "budget": "free"},
    {"need": "plc_scanning", "budget": "free"},
    {"need": "siemens_engineering", "budget": "licensed"},
    {"need": "ics_exploitation_framework", "budget": "free"},
    {"need": "training_lab", "budget": "free"},
    {"need": "attack_research_dataset", "budget": "free"},
    {"need": "honeypot_deployment", "budget": "free"}
  ],
  "traffic_sample": {
    "protocols_detected": ["modbus", "s7comm", "dnp3", "opcua"],
    "anomalies": ["unknown_modbus_master", "s7_stop_command"]
  }
}
```

**Sortie attendue** :
```json
{
  "tool_recommendations": [
    {
      "need": "ot_network_visibility",
      "tools": [
        {"name": "Dragos", "type": "commercial", "features": ["threat_detection", "asset_discovery", "worldview_intel", "playbooks"]},
        {"name": "Claroty", "type": "commercial", "features": ["continuous_monitoring", "secure_access", "vulnerability_mgmt"]},
        {"name": "Nozomi", "type": "commercial", "features": ["guardian_sensors", "anomaly_detection", "siem_integration"]}
      ],
      "selection_criteria": "integration_needs_and_threat_intel"
    },
    {
      "need": "passive_asset_discovery",
      "tools": [
        {"name": "Grassmarlin", "type": "free_nsa", "features": ["passive_mapping", "protocol_parsing", "network_visualization"]},
        {"name": "Wireshark", "type": "free", "features": ["industrial_dissectors", "manual_analysis"]}
      ]
    },
    {
      "need": "vulnerability_scanning",
      "tools": [
        {"name": "Tenable.ot", "type": "commercial", "features": ["ot_vuln_database", "risk_scoring", "compliance"]},
        {"name": "Redpoint", "type": "free", "features": ["ics_specific_checks", "digital_bond"]}
      ]
    },
    {
      "need": "modbus_testing",
      "tools": [
        {"name": "mbtget", "type": "free", "features": ["read_write_registers", "coil_scanning", "unit_id_enum"]},
        {"name": "ModbusPal", "type": "free", "features": ["slave_simulator", "testing"]}
      ]
    },
    {
      "need": "protocol_analysis",
      "tool": {"name": "Wireshark", "dissectors": ["modbus", "dnp3", "s7comm", "ethernetip", "opcua", "iec104", "goose"]},
      "usage": "capture_decode_analyze_anomalies"
    },
    {
      "need": "plc_scanning",
      "tool": {"name": "PLCScan", "features": ["plc_discovery", "fingerprinting", "modbus_s7_support"]}
    },
    {
      "need": "siemens_engineering",
      "tool": {"name": "TIA_Portal", "use": "security_analysis", "features": ["code_review", "project_comparison", "security_settings"]}
    },
    {
      "need": "ics_exploitation",
      "tool": {"name": "ISF", "type": "free", "features": ["metasploit_for_ics", "protocol_modules", "exploit_development"]}
    },
    {
      "need": "training_lab",
      "tool": {"name": "GRFICS", "type": "free_virtual", "features": ["simulated_ics", "attack_defense_practice", "multiple_scenarios"]}
    },
    {
      "need": "research_dataset",
      "tool": {"name": "SWaT", "type": "free_academic", "features": ["water_treatment_data", "labeled_attacks", "ml_training"]}
    },
    {
      "need": "honeypot",
      "tool": {"name": "Conpot", "type": "free", "features": ["protocol_emulation", "attack_capture", "modbus_s7_dnp3_support"]}
    }
  ],
  "traffic_analysis_with_tools": {
    "wireshark_filters": {
      "modbus": "modbus",
      "s7comm": "s7comm",
      "dnp3": "dnp3",
      "opcua": "opcua"
    },
    "anomaly_investigation": [
      {"anomaly": "unknown_modbus_master", "tool": "Nozomi_Claroty", "action": "baseline_comparison_alert"},
      {"anomaly": "s7_stop_command", "tool": "Dragos", "action": "immediate_alert_investigate"}
    ]
  },
  "tool_deployment_strategy": {
    "phase_1_free": ["Wireshark", "Grassmarlin", "PLCScan", "mbtget"],
    "phase_2_monitoring": ["Dragos_or_Claroty_or_Nozomi"],
    "phase_3_vuln_mgmt": ["Tenable.ot"],
    "training": ["GRFICS_lab", "SWaT_dataset"],
    "deception": ["Conpot_honeypots"]
  }
}
```

**Barème** : 97/100

---

## RÉCAPITULATIF MODULE 3.22

| Exercice | Concepts | Note |
|----------|----------|------|
| Ex01 | 3.22.1 a,b,r | 97 |
| Ex02 | 3.22.1 c,d,e,f,g | 96 |
| Ex03 | 3.22.1 h,i,m,o,p | 97 |
| Ex04 | 3.22.1 j,k,l,n,q | 96 |
| Ex05 | 3.22.2 a,b,r | 97 |
| Ex06 | 3.22.2 c,d,e,f | 97 |
| Ex07 | 3.22.2 g,h,i | 96 |
| Ex08 | 3.22.2 j,k,l | 97 |
| Ex09 | 3.22.2 m,n,o,p,q | 96 |
| Ex10 | 3.22.2 s,t | 97 |
| Ex11 | 3.22.3 a,b,c,d,e | 98 |
| Ex12 | 3.22.3 f,g,h,i | 97 |
| Ex13 | 3.22.3 j,k,l,m,n,o,p | 97 |
| Ex14 | 3.22.4 a,b,c,d | 98 |
| Ex15 | 3.22.4 e,f,g,h | 97 |
| Ex16 | 3.22.4 i,j,k,l,m | 96 |
| Ex17 | 3.22.4 n,o,p,q,r | 97 |
| Ex18 | 3.22.5 a-n (14) | 97 |

**Total concepts couverts** : 86/86 (100%)
**Note moyenne** : 96.8/100
**Exercices** : 18
