# MODULE 3.38 : PHYSICAL SECURITY & PENTESTING
## Intrusion Physique et Social Engineering Terrain

**Concepts couverts** : 98/98
**Nombre d'exercices** : 14
**Orientation** : Red Team / Pentest Physique / CTF
**Prerequis** : Module 3.32 (OPSEC), Module 3.7 (Red Team)

---

## OBJECTIFS PEDAGOGIQUES

Ce module forme les professionnels a **executer** des tests d'intrusion physique, contourner les controles d'acces, et mener des operations de social engineering terrain dans un cadre autorise.

---

## SOUS-MODULE 3.38.1 : Physical Security Fundamentals (16 concepts)

### Concepts couverts :
- **a** : Physical Security Layers - Perimeter, building, floor, room, device, data. Defense in depth
- **b** : Deterrence - Fences, signs, lighting, guards, visible security, psychological
- **c** : Detection - Sensors, cameras, motion detectors, glass break, intrusion alarm
- **d** : Delay - Barriers, locks, gates, time for response, layers
- **e** : Response - Guards, police, procedures, alarm response, escalation
- **f** : Access Control Types - Physical (locks, barriers), electronic (cards, biometrics), procedural
- **g** : Key Management - Master keys, key control, restricted keyways, key audit
- **h** : CPTED - Crime Prevention Through Environmental Design, natural surveillance
- **i** : Security Zones - Public, reception, controlled, restricted, critical, classification
- **j** : Mantrap/Airlock - Double-door entry, tailgating prevention, weight sensors
- **k** : Vehicle Barriers - Bollards, planters, gates, crash rating (K-rating, M-rating)
- **l** : Perimeter Security - Fencing, walls, PIDAS, ground sensors, clear zones
- **m** : Surveillance Systems - CCTV, analytics, PTZ, coverage, blind spots, retention
- **n** : Guard Force - Patrol routes, response procedures, training, contractors vs in-house
- **o** : Security Operations Center - Physical SOC, alarm monitoring, camera feeds, dispatch
- **p** : Compliance Standards - ASIS standards, building codes, insurance requirements

---

### EXERCICE 3.38.1 : Physical Security Reconnaissance

**Fichier** : `ex01_physical_recon/`

**Sujet** :
Analysez les informations de reconnaissance d'une cible physique et identifiez les vecteurs d'attaque potentiels selon le modele defense-in-depth.

**Concepts evalues** : a, b, c, d, e, f, h, i, l, m

**Entree** :
```json
{
  "target": {
    "name": "Acme Financial HQ",
    "type": "corporate_office",
    "floors": 8,
    "employees": 350
  },
  "osint_gathered": {
    "perimeter": {
      "fence_type": "decorative_metal",
      "fence_height_ft": 4,
      "gates": ["main_vehicle", "pedestrian_east"],
      "lighting": "partial_coverage",
      "cameras_visible": 6
    },
    "building_exterior": {
      "entrances": ["main_lobby", "loading_dock", "emergency_exits_x4"],
      "windows": "ground_floor_accessible",
      "roof_access": "ladder_visible",
      "dumpsters": "unlocked_area"
    },
    "guard_observation": {
      "guard_count": 2,
      "patrol_pattern": "predictable_15min",
      "guard_station": "main_lobby_only",
      "night_coverage": "single_guard"
    },
    "access_control_observed": {
      "type": "badge_readers",
      "tailgating_observed": true,
      "visitor_policy": "escort_sometimes"
    },
    "cctv_analysis": {
      "camera_count": 12,
      "blind_spots_identified": ["loading_dock_corner", "east_stairwell", "parking_garage_level2"],
      "monitoring": "business_hours_only"
    }
  },
  "social_media_intel": {
    "employee_badge_photos": 3,
    "office_interior_photos": 7,
    "guard_company_identified": "SecureGuard Inc"
  }
}
```

**Sortie attendue** :
```json
{
  "reconnaissance_analysis": {
    "target": "Acme Financial HQ",
    "security_posture": "WEAK",
    "overall_score": 35
  },
  "layer_vulnerabilities": [
    {
      "layer": "Perimeter",
      "score": 25,
      "weaknesses": [
        {
          "id": "PER-001",
          "description": "Low fence easily scalable",
          "exploitation": "Direct climb over 4ft decorative fence at night",
          "difficulty": "TRIVIAL"
        },
        {
          "id": "PER-002",
          "description": "Partial lighting coverage",
          "exploitation": "Approach through dark zones undetected",
          "difficulty": "EASY"
        }
      ]
    },
    {
      "layer": "Building_Access",
      "score": 40,
      "weaknesses": [
        {
          "id": "ACC-001",
          "description": "Loading dock unmonitored",
          "exploitation": "Entry via loading dock during blind spot",
          "difficulty": "EASY"
        },
        {
          "id": "ACC-002",
          "description": "Tailgating commonly successful",
          "exploitation": "Follow employee through badge-controlled door",
          "difficulty": "EASY"
        },
        {
          "id": "ACC-003",
          "description": "Roof access visible",
          "exploitation": "After-hours roof entry via external ladder",
          "difficulty": "MODERATE"
        }
      ]
    },
    {
      "layer": "Detection",
      "score": 35,
      "weaknesses": [
        {
          "id": "DET-001",
          "description": "CCTV blind spots identified",
          "exploitation": "Route through parking L2, loading dock corner",
          "difficulty": "EASY"
        },
        {
          "id": "DET-002",
          "description": "No after-hours monitoring",
          "exploitation": "Night operations unmonitored by cameras",
          "difficulty": "TRIVIAL"
        }
      ]
    },
    {
      "layer": "Response",
      "score": 40,
      "weaknesses": [
        {
          "id": "RES-001",
          "description": "Predictable patrol pattern",
          "exploitation": "Time entry between 15-min patrol cycles",
          "difficulty": "EASY"
        },
        {
          "id": "RES-002",
          "description": "Single night guard",
          "exploitation": "Distract guard, enter from opposite side",
          "difficulty": "MODERATE"
        }
      ]
    }
  ],
  "attack_vectors": [
    {
      "name": "Night Perimeter Breach",
      "entry_point": "East fence dark zone",
      "route": ["Fence climb", "Loading dock corner", "Emergency exit"],
      "timing": "02:00-04:00",
      "success_probability": 85,
      "detection_risk": "LOW"
    },
    {
      "name": "Daytime Social Engineering",
      "entry_point": "Main lobby",
      "method": "Tailgating + pretext",
      "timing": "08:30 morning rush",
      "success_probability": 75,
      "detection_risk": "MEDIUM"
    },
    {
      "name": "Loading Dock Infiltration",
      "entry_point": "Loading dock",
      "method": "Delivery pretext",
      "timing": "10:00-11:00 delivery window",
      "success_probability": 70,
      "detection_risk": "MEDIUM"
    }
  ],
  "recommended_approach": {
    "primary": "Night Perimeter Breach",
    "rationale": "Highest success rate, lowest detection risk, minimal guard coverage"
  }
}
```

**Criteres de notation** :
- Identification correcte des couches de securite (25 pts)
- Analyse des vulnerabilites par couche (25 pts)
- Vecteurs d'attaque realistes (20 pts)
- Evaluation des risques de detection (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

### EXERCICE 3.38.2 : Security Zone Mapping

**Fichier** : `ex02_zone_mapping/`

**Sujet** :
Cartographiez les zones de securite d'une installation et planifiez les transitions entre zones pour atteindre un objectif.

**Concepts evalues** : f, g, i, j, k, n, o, p

**Entree** :
```json
{
  "facility": "Research Laboratory",
  "objective": "Server room - Zone 5",
  "floor_plan": {
    "zones": [
      {"id": 1, "name": "Public_Lobby", "classification": "PUBLIC", "access_control": "none"},
      {"id": 2, "name": "Reception", "classification": "CONTROLLED", "access_control": "sign_in"},
      {"id": 3, "name": "General_Office", "classification": "RESTRICTED", "access_control": "badge"},
      {"id": 4, "name": "Lab_Area", "classification": "SECURE", "access_control": "badge_pin"},
      {"id": 5, "name": "Server_Room", "classification": "CRITICAL", "access_control": "badge_pin_biometric"}
    ],
    "transitions": [
      {"from": 1, "to": 2, "control": "receptionist", "bypass_difficulty": "EASY"},
      {"from": 2, "to": 3, "control": "badge_reader", "bypass_difficulty": "MODERATE"},
      {"from": 3, "to": 4, "control": "badge_plus_keypad", "bypass_difficulty": "HARD"},
      {"from": 4, "to": 5, "control": "mantrap_biometric", "bypass_difficulty": "VERY_HARD"},
      {"from": 3, "to": 5, "control": "none", "bypass_difficulty": "IMPOSSIBLE", "note": "No direct path"}
    ],
    "alternative_paths": [
      {"description": "HVAC_duct_zone3_to_zone4", "bypass_difficulty": "MODERATE"},
      {"description": "Ceiling_tiles_zone4_to_zone5", "bypass_difficulty": "HARD"},
      {"description": "Loading_dock_direct_zone3", "bypass_difficulty": "EASY"}
    ]
  },
  "intel": {
    "guard_positions": ["Zone 2 reception", "Zone 4 lab entrance"],
    "camera_coverage": ["Zone 1-3 full", "Zone 4-5 partial"],
    "badge_clone_available": "Zone 3 access level",
    "pin_observed": "1247 for Zone 4"
  }
}
```

**Sortie attendue** :
```json
{
  "zone_analysis": {
    "objective": "Server_Room (Zone 5)",
    "total_zones_to_traverse": 4,
    "classification_escalation": ["PUBLIC", "CONTROLLED", "RESTRICTED", "SECURE", "CRITICAL"]
  },
  "infiltration_routes": [
    {
      "route_id": "PRIMARY",
      "name": "Standard Path with Cloned Badge",
      "path": [
        {"zone": 1, "to": 2, "method": "Social engineering receptionist", "risk": "MEDIUM"},
        {"zone": 2, "to": 3, "method": "Cloned badge (available)", "risk": "LOW"},
        {"zone": 3, "to": 4, "method": "Cloned badge + observed PIN 1247", "risk": "MEDIUM"},
        {"zone": 4, "to": 5, "method": "Mantrap bypass required", "risk": "HIGH"}
      ],
      "overall_difficulty": "HARD",
      "success_probability": 45,
      "blockers": ["Mantrap with biometric - no bypass without insider"]
    },
    {
      "route_id": "ALTERNATIVE_A",
      "name": "Physical Bypass Route",
      "path": [
        {"zone": 1, "to": 2, "method": "Normal entry", "risk": "LOW"},
        {"zone": 2, "to": 3, "method": "Loading dock alternative", "risk": "MEDIUM"},
        {"zone": 3, "to": 4, "method": "HVAC duct crawl", "risk": "MEDIUM"},
        {"zone": 4, "to": 5, "method": "Ceiling tiles access", "risk": "HIGH"}
      ],
      "overall_difficulty": "HARD",
      "success_probability": 55,
      "blockers": ["Physical fitness required", "Noise risk in HVAC"]
    }
  ],
  "mantrap_bypass_options": [
    {
      "method": "Tailgate authorized personnel",
      "feasibility": "LOW",
      "reason": "Weight sensors, single occupancy enforced"
    },
    {
      "method": "Insider assistance",
      "feasibility": "MEDIUM",
      "reason": "Requires social engineering lab personnel"
    },
    {
      "method": "Biometric spoof",
      "feasibility": "LOW",
      "reason": "Advanced biometrics, liveness detection likely"
    },
    {
      "method": "Physical bypass (ceiling)",
      "feasibility": "MEDIUM",
      "reason": "Ceiling tiles route from Zone 4"
    }
  ],
  "recommended_plan": {
    "approach": "ALTERNATIVE_A",
    "rationale": "Avoids mantrap biometric which is primary blocker",
    "preparation_needed": [
      "Acquire Zone 3 badge clone",
      "Confirm HVAC duct accessibility",
      "Map ceiling tile route Zone 4 to Zone 5",
      "Prepare tools for ceiling tile access"
    ],
    "timing": "Night shift - minimal Zone 4 personnel"
  }
}
```

**Criteres de notation** :
- Analyse correcte des zones de securite (25 pts)
- Identification des routes d'infiltration (25 pts)
- Evaluation realiste des methodes de bypass (20 pts)
- Plan d'action coherent (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## SOUS-MODULE 3.38.2 : Lock Picking & Bypass (18 concepts)

### Concepts couverts :
- **a** : Lock Mechanisms - Pin tumbler, wafer, disc detainer, lever, tubular, dimple
- **b** : Pin Tumbler Locks - Driver pins, key pins, shear line, springs, plug, bible
- **c** : Single Pin Picking (SPP) - Tension wrench, pick, feedback, setting pins, binding order
- **d** : Raking - Quick entry, city rake, snake rake, rocking motion
- **e** : Bumping - Bump key, 999 cut, impact, pin jump, bump-resistant
- **f** : Lock Impressioning - Blank key, marks, file, working key creation
- **g** : Bypass Techniques - Latch slip, shims, under-door tools, Lishi, bypass tools
- **h** : High Security Locks - Security pins (spools, serrated), sidebar, magnetic, Medeco, Abloy
- **i** : Security Pin Picking - Counter-rotation, spool feedback, serrated feel, patience
- **j** : Tubular Locks - Tubular pick, 7/8 pin, rotation, vending machines
- **k** : Wafer Locks - Jiggle keys, rake attack, automotive, filing technique
- **l** : Disc Detainer Locks - Abloy, disc pick, front tension, sidebar
- **m** : Padlock Attacks - Shimming, bypass, destructive (cut, drill)
- **n** : Safe Manipulation - Contact points, wheel pack, dial manipulation, time-consuming
- **o** : Electronic Lock Attacks - Battery bypass, magnet attacks, signal capture, firmware
- **p** : Door Hardware Bypass - Hinge attacks, crash bar bypass, thumb turn tools, gap tools
- **q** : Covert Entry - Non-destructive, cover locks, no evidence, professional
- **r** : Lock Sport vs Pentest - Practice tools, professional equipment, ethics, legality

---

### EXERCICE 3.38.3 : Lock Attack Strategy

**Fichier** : `ex03_lock_attack/`

**Sujet** :
Analysez les caracteristiques d'une serrure et determinez la meilleure strategie d'attaque pour l'ouvrir de maniere non-destructive.

**Concepts evalues** : a, b, c, d, e, g, h, i, q

**Entree** :
```json
{
  "scenario": "Authorized pentest - server room door",
  "lock_analysis": {
    "brand": "Schlage",
    "model": "B60N",
    "type": "pin_tumbler",
    "pins": 6,
    "keyway": "SC1",
    "security_features": {
      "security_pins": true,
      "pin_types": ["spool", "serrated"],
      "anti_bump": false,
      "anti_pick_shield": false
    },
    "condition": "well_maintained",
    "door_gap": "minimal"
  },
  "constraints": {
    "time_limit_minutes": 15,
    "noise_tolerance": "low",
    "evidence_allowed": "none",
    "tools_available": ["pick_set", "tension_wrenches", "bump_keys", "bypass_tools"]
  },
  "environment": {
    "lighting": "dim_hallway",
    "camera_coverage": "none_at_door",
    "guard_patrol": "20_min_intervals",
    "last_patrol": "5_min_ago"
  }
}
```

**Sortie attendue** :
```json
{
  "lock_assessment": {
    "brand_model": "Schlage B60N",
    "difficulty_rating": "MODERATE",
    "primary_defense": "Security pins (spool + serrated)",
    "weaknesses": [
      "No anti-bump protection",
      "Standard SC1 keyway (common)",
      "No pick shield"
    ]
  },
  "attack_strategies": [
    {
      "rank": 1,
      "method": "Single Pin Picking (SPP)",
      "description": "Pick each pin individually with light tension",
      "technique": {
        "tension": "Light bottom-of-keyway tension",
        "pick_type": "Standard hook, 0.025 thickness",
        "approach": "Identify binding order, set pins progressively",
        "security_pin_handling": "Counter-rotation for spools, feel for serrated"
      },
      "estimated_time_min": 8,
      "success_probability": 75,
      "noise_level": "SILENT",
      "evidence": "NONE",
      "skill_required": "INTERMEDIATE"
    },
    {
      "rank": 2,
      "method": "Bump Key Attack",
      "description": "SC1 bump key with controlled strike",
      "technique": {
        "key": "SC1 999-cut bump key",
        "tension": "Light rotational tension",
        "strike": "Controlled tap with bump hammer"
      },
      "estimated_time_min": 2,
      "success_probability": 60,
      "noise_level": "LOW",
      "evidence": "NONE",
      "skill_required": "BEGINNER",
      "note": "Security pins may resist bump - try multiple attempts"
    },
    {
      "rank": 3,
      "method": "Raking",
      "description": "City rake with varying tension",
      "technique": {
        "tool": "City rake or snake rake",
        "motion": "In-out with slight rotation",
        "tension": "Vary from light to medium"
      },
      "estimated_time_min": 5,
      "success_probability": 40,
      "noise_level": "SILENT",
      "evidence": "NONE",
      "skill_required": "BEGINNER",
      "note": "Lower success due to security pins"
    }
  ],
  "bypass_assessment": {
    "latch_slip": {
      "feasible": false,
      "reason": "Minimal door gap - no access to latch"
    },
    "under_door_tool": {
      "feasible": false,
      "reason": "Door gap insufficient"
    },
    "hinge_attack": {
      "feasible": "unknown",
      "reason": "Hinge pin accessibility not provided"
    }
  },
  "recommended_approach": {
    "primary_method": "Single Pin Picking",
    "rationale": [
      "Silent operation meets noise constraint",
      "No evidence left",
      "75% success rate within time window",
      "Security pins manageable with technique"
    ],
    "backup_method": "Bump key if SPP exceeds 10 minutes",
    "abort_criteria": "12 minutes elapsed - retreat before patrol"
  },
  "operational_timeline": {
    "0-10min": "Primary SPP attempt",
    "10-12min": "Bump key backup attempt",
    "12-15min": "Abort window - prepare egress",
    "patrol_return": "~15 min from now"
  }
}
```

**Criteres de notation** :
- Analyse correcte du type de serrure (25 pts)
- Strategies d'attaque appropriees (25 pts)
- Gestion des security pins (20 pts)
- Respect des contraintes operationnelles (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

### EXERCICE 3.38.4 : Advanced Lock Bypass

**Fichier** : `ex04_advanced_bypass/`

**Sujet** :
Planifiez des attaques contre des serrures haute securite et des systemes electroniques en utilisant des techniques avancees.

**Concepts evalues** : h, i, j, k, l, n, o, p

**Entree** :
```json
{
  "targets": [
    {
      "id": "T1",
      "location": "Executive safe",
      "type": "combination_safe",
      "brand": "AMSEC",
      "model": "BF3416",
      "lock_type": "mechanical_combination",
      "wheels": 3,
      "dial_resistance": "smooth",
      "time_available_hours": 4
    },
    {
      "id": "T2",
      "location": "Equipment cabinet",
      "type": "tubular_lock",
      "pins": 7,
      "brand": "unknown",
      "condition": "worn"
    },
    {
      "id": "T3",
      "location": "Network closet",
      "type": "electronic_keypad",
      "brand": "Kaba",
      "model": "E-Plex_2000",
      "power": "battery_9v",
      "code_length": 4,
      "lockout_policy": true
    },
    {
      "id": "T4",
      "location": "High security cabinet",
      "type": "disc_detainer",
      "brand": "Abloy",
      "model": "Protec2",
      "discs": 11,
      "sidebar": true
    }
  ],
  "tools_available": [
    "tubular_pick_7pin",
    "disc_detainer_pick",
    "safe_manipulation_stethoscope",
    "electronic_bypass_kit",
    "borescope"
  ]
}
```

**Sortie attendue** :
```json
{
  "target_assessments": [
    {
      "target_id": "T1",
      "type": "Mechanical Combination Safe",
      "difficulty": "VERY_HARD",
      "attack_plan": {
        "method": "Safe Manipulation",
        "technique": {
          "description": "Contact point manipulation using stethoscope",
          "steps": [
            "Park wheels at contact points",
            "Graph dial resistance while rotating",
            "Identify wheel pack click points",
            "Determine combination through feel"
          ],
          "tools": ["Manipulation stethoscope", "Graphing paper/software"]
        },
        "estimated_time": "2-4 hours",
        "success_probability": 35,
        "alternative": {
          "method": "Borescope attack",
          "description": "If access hole available, view wheel pack directly",
          "feasibility": "Requires drilling - not authorized"
        }
      }
    },
    {
      "target_id": "T2",
      "type": "Tubular Lock",
      "difficulty": "EASY",
      "attack_plan": {
        "method": "Tubular Pick",
        "technique": {
          "description": "7-pin tubular pick tool",
          "steps": [
            "Insert tubular pick",
            "Apply light tension",
            "Push and rotate until pins set",
            "Turn to open"
          ],
          "tools": ["7-pin tubular pick"]
        },
        "estimated_time": "1-2 minutes",
        "success_probability": 90,
        "note": "Worn condition makes it easier"
      }
    },
    {
      "target_id": "T3",
      "type": "Electronic Keypad",
      "difficulty": "MODERATE",
      "attack_plan": {
        "method": "Electronic Bypass",
        "techniques": [
          {
            "name": "Battery bypass",
            "description": "Apply 9V to external contacts to reset",
            "success_rate": 40,
            "note": "May trigger lockout"
          },
          {
            "name": "Default code attempt",
            "description": "Try factory defaults: 1234, 0000, 9999",
            "success_rate": 15,
            "warning": "Lockout after 3 failed attempts"
          },
          {
            "name": "Wear pattern analysis",
            "description": "Examine keypad for worn digits",
            "success_rate": 30,
            "note": "Reduces combination space"
          }
        ],
        "estimated_time": "5-15 minutes",
        "recommended_order": ["Wear pattern", "Battery bypass", "Default codes"]
      }
    },
    {
      "target_id": "T4",
      "type": "Disc Detainer (Abloy Protec2)",
      "difficulty": "EXTREME",
      "attack_plan": {
        "method": "Disc Detainer Picking",
        "technique": {
          "description": "Front-tensioned disc pick",
          "challenge": "Protec2 has rotating disc and sidebar",
          "steps": [
            "Apply front tension",
            "Set each disc to gate position",
            "Feel for sidebar false gates"
          ],
          "tools": ["Disc detainer pick with tips"]
        },
        "estimated_time": "30-60 minutes",
        "success_probability": 20,
        "note": "Abloy Protec2 is considered nearly pick-proof. Professional locksmith may be needed."
      }
    }
  ],
  "priority_order": [
    {
      "rank": 1,
      "target": "T2",
      "reason": "Quickest win, highest success rate"
    },
    {
      "rank": 2,
      "target": "T3",
      "reason": "Moderate difficulty, multiple attack vectors"
    },
    {
      "rank": 3,
      "target": "T1",
      "reason": "Time intensive but doable with patience"
    },
    {
      "rank": 4,
      "target": "T4",
      "reason": "Lowest probability, attempt only if time permits"
    }
  ],
  "overall_success_estimate": {
    "all_targets": 15,
    "at_least_3": 45,
    "at_least_2": 75,
    "at_least_1": 95
  }
}
```

**Criteres de notation** :
- Analyse correcte de chaque type de serrure (25 pts)
- Techniques d'attaque appropriees (25 pts)
- Estimation realiste des temps et probabilites (20 pts)
- Priorisation logique (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## SOUS-MODULE 3.38.3 : Electronic Access Control Attacks (18 concepts)

### Concepts couverts :
- **a** : RFID/NFC Basics - Frequency (125kHz, 13.56MHz), modulation, readers, cards
- **b** : Low Frequency Cards - 125kHz, HID Prox, EM4100, no encryption, easy clone
- **c** : Proxmark - RFID tool, read, clone, simulate, brute force
- **d** : HID Cloning - Proxmark, read card, write to blank, badgemaker, Flipper Zero
- **e** : iClass - HID iClass, legacy/SE, diversified keys, attacks
- **f** : High Frequency Cards - 13.56MHz, MIFARE, DESFire, encryption, more secure
- **g** : MIFARE Classic Attacks - Crypto1 broken, nested attack, hardnested, darkside
- **h** : MIFARE DESFire - AES encryption, more secure, implementation attacks
- **i** : NFC Relay Attacks - Extend range, relay to remote reader, real-time relay
- **j** : Mobile Credentials - Phone as badge, HID Mobile, vulnerabilities, capture
- **k** : Biometric Attacks - Fingerprint (fake, latent), face (photo, mask), iris (printed)
- **l** : Fingerprint Spoofing - Latent print lift, gelatin/silicone fake, gummy finger
- **m** : Facial Recognition Attacks - Photos, 3D masks, twins, IR attacks, liveness bypass
- **n** : Tailgating/Piggybacking - Follow authorized person, social engineering, distraction
- **o** : Door Sensor Attacks - REX sensor activation, magnet attacks, sensor bypass
- **p** : Controller Attacks - Network access to controllers, default credentials, firmware
- **q** : Wiegand Attacks - Wiegand protocol, sniffing, replay, interception devices
- **r** : Long Range Readers - Capture badge at distance, briefcase readers, covert

---

### EXERCICE 3.38.5 : RFID Badge Cloning Operation

**Fichier** : `ex05_rfid_cloning/`

**Sujet** :
Planifiez et executez une operation de clonage de badge RFID en analysant le type de carte cible et en selectionnant les outils et techniques appropriees.

**Concepts evalues** : a, b, c, d, e, f, g, r

**Entree** :
```json
{
  "mission": "Clone employee badge for building access",
  "target_badge": {
    "visual_inspection": {
      "brand_marking": "HID",
      "model_text": "iCLASS",
      "format": "credit_card_size",
      "observable_number": "2804-xxxxx"
    },
    "reader_type_observed": "HID iCLASS SE",
    "access_granted_areas": ["lobby", "floors_1-3", "parking"]
  },
  "collection_opportunity": {
    "scenario": "Target leaves badge on desk during lunch",
    "access_time_minutes": 5,
    "distance_from_target_typical_m": 0.5
  },
  "tools_available": [
    "proxmark3_rdv4",
    "flipper_zero",
    "t5577_blank_cards",
    "iclass_blank_cards",
    "long_range_reader_125khz"
  ],
  "constraints": {
    "covert_operation": true,
    "no_target_interaction": true,
    "success_verification_possible": false
  }
}
```

**Sortie attendue** :
```json
{
  "badge_analysis": {
    "identified_type": "HID iCLASS",
    "frequency": "13.56MHz",
    "encryption": "DES or AES depending on configuration",
    "cloning_difficulty": "MODERATE to HARD",
    "notes": [
      "iCLASS comes in legacy, SE, and SEOS variants",
      "Legacy iCLASS (before SE) uses known-weak keys",
      "iCLASS SE uses diversified keys - harder to clone"
    ]
  },
  "attack_strategy": {
    "phase_1_identification": {
      "description": "Determine exact iCLASS variant",
      "tool": "Proxmark3 RDV4",
      "command": "hf iclass info",
      "duration_seconds": 3,
      "output_expected": ["Card type", "CSN", "Configuration"]
    },
    "phase_2_clone_attempt": {
      "if_legacy": {
        "description": "Legacy iCLASS with default keys",
        "method": "Read and clone to blank iCLASS card",
        "commands": [
          "hf iclass dump",
          "hf iclass wrbl --blk [X] --ki 0"
        ],
        "success_probability": 80,
        "duration_seconds": 30
      },
      "if_se": {
        "description": "iCLASS SE with diversified keys",
        "method": "Attempt known master key or Loclass attack",
        "commands": [
          "hf iclass loclass",
          "hf iclass dump --ki [recovered_key]"
        ],
        "success_probability": 50,
        "duration_seconds": 180,
        "note": "May require multiple card reads to recover key"
      }
    },
    "phase_3_verification": {
      "description": "Test cloned card on non-critical reader",
      "risk": "Alert if testing on target building",
      "mitigation": "Find similar HID iCLASS reader elsewhere"
    }
  },
  "operational_plan": {
    "timing": "Lunch break - 5 minute window",
    "steps": [
      {
        "step": 1,
        "action": "Approach target desk with Proxmark3 concealed",
        "duration_seconds": 30
      },
      {
        "step": 2,
        "action": "Place reader within 5cm of badge",
        "duration_seconds": 5
      },
      {
        "step": 3,
        "action": "Run hf iclass info and dump",
        "duration_seconds": 60
      },
      {
        "step": 4,
        "action": "If legacy - immediate clone to blank",
        "duration_seconds": 30
      },
      {
        "step": 5,
        "action": "If SE - capture data for offline attack",
        "duration_seconds": 30
      },
      {
        "step": 6,
        "action": "Egress - total time under 3 minutes",
        "duration_seconds": 60
      }
    ],
    "total_time_seconds": 215,
    "buffer_remaining_seconds": 85
  },
  "alternative_approaches": [
    {
      "method": "Long range capture",
      "description": "125kHz LF cards can be read at distance, but iCLASS is HF",
      "feasibility": "NOT_APPLICABLE",
      "reason": "iCLASS operates at 13.56MHz, requires close proximity"
    },
    {
      "method": "NFC relay attack",
      "description": "Real-time relay from victim card to target reader",
      "feasibility": "POSSIBLE",
      "requirements": ["NFCGate Android app", "Two devices", "Target in range"]
    }
  ],
  "risk_assessment": {
    "detection_during_clone": "LOW - appears to be using phone near desk",
    "clone_failure": "MEDIUM - SE variant may resist",
    "clone_detected_at_reader": "LOW - valid credential format",
    "audit_trail": "MEDIUM - clone may log as original badge"
  }
}
```

**Criteres de notation** :
- Identification correcte du type RFID (25 pts)
- Strategie d'attaque appropriee (25 pts)
- Plan operationnel realiste (20 pts)
- Gestion des variantes de securite (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

### EXERCICE 3.38.6 : Biometric Bypass Techniques

**Fichier** : `ex06_biometric_bypass/`

**Sujet** :
Analysez un systeme de controle d'acces biometrique et planifiez des techniques de contournement.

**Concepts evalues** : k, l, m, n, o

**Entree** :
```json
{
  "target_system": {
    "location": "R&D Lab entrance",
    "biometric_type": "fingerprint_scanner",
    "brand": "ZKTeco",
    "model": "ZK9500",
    "features": {
      "sensor_type": "optical",
      "liveness_detection": false,
      "template_on_card": false,
      "fallback_method": "PIN_code"
    }
  },
  "target_individual": {
    "name": "Dr. Smith",
    "access_level": "Full R&D",
    "known_finger": "right_index",
    "observation_opportunity": {
      "fingerprint_surface": "coffee_mug_daily",
      "collection_possible": true
    }
  },
  "available_materials": [
    "fingerprint_powder",
    "lifting_tape",
    "gelatin_sheets",
    "silicone_molding_kit",
    "wood_glue",
    "glycerin"
  ],
  "constraints": {
    "time_to_prepare_days": 3,
    "single_attempt_only": false,
    "target_awareness": "none"
  }
}
```

**Sortie attendue** :
```json
{
  "system_analysis": {
    "biometric_type": "Fingerprint - Optical sensor",
    "security_level": "LOW-MEDIUM",
    "vulnerabilities": [
      "No liveness detection - vulnerable to fake fingerprints",
      "Optical sensor - can be fooled by 2D/3D replicas",
      "Fallback PIN available - potential brute force"
    ],
    "strengths": [
      "Requires physical fingerprint capture",
      "Multiple failed attempts may trigger lockout"
    ]
  },
  "attack_plan": {
    "phase_1_collection": {
      "description": "Capture latent fingerprint from coffee mug",
      "technique": "Powder and lift",
      "steps": [
        {
          "step": 1,
          "action": "Retrieve discarded coffee mug from trash/desk",
          "timing": "After Dr. Smith leaves office"
        },
        {
          "step": 2,
          "action": "Apply fingerprint powder to mug surface",
          "technique": "Light dusting with brush"
        },
        {
          "step": 3,
          "action": "Identify clear right index fingerprint",
          "criteria": "Complete ridge pattern, no smudging"
        },
        {
          "step": 4,
          "action": "Lift print with clear tape",
          "technique": "Slow, even pressure"
        },
        {
          "step": 5,
          "action": "Transfer to white card for contrast",
          "result": "Captured latent print"
        }
      ],
      "success_probability": 70,
      "time_required_minutes": 30
    },
    "phase_2_replication": {
      "methods": [
        {
          "name": "Gelatin fake",
          "description": "Create gelatin mold from lifted print",
          "steps": [
            "Scan/photograph lifted print",
            "Enhance ridges digitally",
            "Print negative on transparency",
            "UV expose onto PCB",
            "Etch to create mold",
            "Pour gelatin into mold",
            "Let set 24 hours"
          ],
          "success_rate_on_optical": 60,
          "difficulty": "MODERATE",
          "time_hours": 24
        },
        {
          "name": "Wood glue method",
          "description": "Simpler technique using wood glue",
          "steps": [
            "Apply thin layer of wood glue over lifted print",
            "Let dry completely (2-4 hours)",
            "Peel off - creates rubber-like replica",
            "May need glycerin for conductivity"
          ],
          "success_rate_on_optical": 45,
          "difficulty": "EASY",
          "time_hours": 4
        },
        {
          "name": "Silicone prosthetic",
          "description": "High quality silicone finger cover",
          "steps": [
            "Create detailed mold from print image",
            "3D print or laser etch negative",
            "Pour silicone mixture",
            "Create wearable finger cover"
          ],
          "success_rate_on_optical": 75,
          "difficulty": "HARD",
          "time_hours": 48
        }
      ],
      "recommended_method": "Gelatin fake",
      "rationale": "Best success/effort ratio for optical sensors without liveness"
    },
    "phase_3_execution": {
      "description": "Present fake fingerprint to scanner",
      "technique": "Apply gelatin replica to own finger, natural presentation",
      "timing": "Off-hours to minimize witness",
      "contingency": "If fails, attempt PIN fallback (shoulder surf or default)"
    }
  },
  "alternative_attacks": [
    {
      "method": "Tailgating",
      "description": "Follow Dr. Smith through door",
      "success_rate": 60,
      "pro": "No fingerprint needed",
      "con": "Requires target presence, witness"
    },
    {
      "method": "PIN brute force",
      "description": "If fingerprint fails, try common PINs",
      "common_pins": ["1234", "0000", "1111", "birth_year"],
      "success_rate": 20,
      "risk": "Lockout after N attempts"
    }
  ],
  "risk_mitigation": {
    "fake_detected": "Retreat immediately, no evidence left",
    "lockout_triggered": "Abort mission, report as 'reader malfunction'",
    "witnessed": "Pretext - 'Testing new badge'"
  },
  "overall_success_probability": {
    "fingerprint_spoof": 60,
    "with_alternatives": 80
  }
}
```

**Criteres de notation** :
- Analyse correcte du systeme biometrique (25 pts)
- Technique de capture d'empreinte (25 pts)
- Methodes de replication realistes (20 pts)
- Plan d'execution et alternatives (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## SOUS-MODULE 3.38.4 : Physical Penetration Testing (16 concepts)

### Concepts couverts :
- **a** : Engagement Planning - Scope, authorization, get-out-of-jail letter, emergency contacts
- **b** : Reconnaissance Physical - Site survey, camera locations, guard patterns, entrances, timing
- **c** : Social Engineering Physical - Pretexts, uniforms, props, confidence, conversation
- **d** : Pretexts - Vendor, IT support, inspector, delivery, new employee, contractor
- **e** : Uniform & Props - Branded clothing, clipboard, ID badge, tools, boxes
- **f** : Tailgating Execution - Timing, appearance, confidence, full hands technique
- **g** : Reception Bypass - Distraction, busy periods, multiple entrances, delivery areas
- **h** : Building Navigation - Look like you belong, confident movement, avoid hesitation
- **i** : Objective Execution - Plant device, access server room, photograph, evidence
- **j** : Implant Placement - Network implant, USB drop, rogue AP, keylogger
- **k** : Rogue Devices - Raspberry Pi, LAN Turtle, Bash Bunny, WiFi Pineapple
- **l** : Egress - Calm exit, don't rush, same pretext, evidence concealment
- **m** : Evidence Collection - Photos, video, logs, documentation, chain of custody
- **n** : Report Writing - Findings, evidence, risk assessment, recommendations
- **o** : Red Team Physical - Combined cyber/physical, realistic adversary, objectives
- **p** : Legal Considerations - Trespass laws, arrest risk, authorization limits, insurance

---

### EXERCICE 3.38.7 : Physical Pentest Planning

**Fichier** : `ex07_pentest_planning/`

**Sujet** :
Planifiez une mission de penetration physique complete incluant la reconnaissance, l'infiltration, l'execution des objectifs, et l'exfiltration.

**Concepts evalues** : a, b, c, d, e, f, g, h, l, m, p

**Entree** :
```json
{
  "engagement": {
    "client": "Megacorp Industries",
    "type": "physical_penetration_test",
    "authorization": "signed_sow_on_file",
    "contact": {
      "name": "Jane Doe - CISO",
      "phone": "555-0100",
      "24h_emergency": "555-0199"
    },
    "get_out_of_jail_letter": true,
    "insurance": "valid"
  },
  "objectives": [
    {"id": "O1", "description": "Gain physical access to building", "priority": "HIGH"},
    {"id": "O2", "description": "Access server room floor 3", "priority": "HIGH"},
    {"id": "O3", "description": "Plant network implant", "priority": "MEDIUM"},
    {"id": "O4", "description": "Photograph sensitive documents", "priority": "LOW"}
  ],
  "reconnaissance_gathered": {
    "building": {
      "floors": 5,
      "employees": 200,
      "entrances": ["main_lobby", "parking_garage", "loading_dock"],
      "business_hours": "08:00-18:00"
    },
    "security": {
      "badge_system": "HID_Prox_125khz",
      "guards": {"day": 2, "night": 1},
      "cameras": "lobby_and_corridors",
      "visitor_policy": "sign_in_escort_required"
    },
    "schedule_intel": {
      "busy_period": "08:30-09:30",
      "lunch_rush": "12:00-13:00",
      "deliveries": "09:00-11:00"
    }
  },
  "team": {
    "members": 2,
    "comms": "encrypted_radio",
    "vehicle": "available"
  },
  "constraints": {
    "no_forced_entry": true,
    "no_theft": true,
    "evidence_collection_only": true,
    "abort_if_challenged": true
  }
}
```

**Sortie attendue** :
```json
{
  "mission_plan": {
    "codename": "Operation Server Ghost",
    "date": "TBD - weekday",
    "duration_planned": "4 hours",
    "team_roles": {
      "operator_1": "Primary infiltrator",
      "operator_2": "External support and comms"
    }
  },
  "pre_mission": {
    "documentation_check": [
      {"item": "Get-out-of-jail letter", "status": "VERIFIED"},
      {"item": "Emergency contacts saved", "status": "VERIFIED"},
      {"item": "Insurance coverage", "status": "VERIFIED"},
      {"item": "SOW scope review", "status": "VERIFIED"}
    ],
    "equipment_list": [
      {"item": "Fake delivery uniform", "purpose": "Pretext"},
      {"item": "Clipboard with fake manifest", "purpose": "Props"},
      {"item": "Boxes (empty)", "purpose": "Tailgating prop"},
      {"item": "Cloned HID badge (if obtained)", "purpose": "Access"},
      {"item": "LAN Turtle", "purpose": "Network implant"},
      {"item": "Smartphone", "purpose": "Photos, documentation"},
      {"item": "Encrypted radio", "purpose": "Team comms"},
      {"item": "Letter of authorization (sealed)", "purpose": "If caught"}
    ]
  },
  "phase_1_approach": {
    "time": "09:30 - end of busy period",
    "location": "Loading dock entrance",
    "pretext": "Delivery driver - IT equipment",
    "appearance": {
      "uniform": "Generic delivery company (brown)",
      "props": ["2 medium boxes", "clipboard", "scanning device fake"],
      "demeanor": "Professional, slightly rushed"
    },
    "operator_2_position": "Vehicle parked with view of loading dock"
  },
  "phase_2_infiltration": {
    "entry_method": "Social engineering - delivery pretext",
    "script": {
      "initial": "Hi, I've got a delivery for IT department, 3rd floor",
      "if_sign_required": "Sure, can you sign here?",
      "if_escort_offered": "No worries, I know where it is, done this route before",
      "if_escort_insisted": "Okay, lead the way"
    },
    "navigation": {
      "to_elevator": "Follow signs, confident pace",
      "floor_3": "Exit left toward server room per floor plan",
      "if_challenged": "Looking for the IT department, got turned around"
    }
  },
  "phase_3_objective_execution": {
    "O1_building_access": {
      "method": "Delivery pretext entry",
      "success_indicator": "Inside past reception",
      "evidence": "Timestamp photo of lobby"
    },
    "O2_server_room_access": {
      "method": "Tailgating IT staff or badge clone",
      "approach": "Wait near server room during busy period",
      "if_locked": "Attempt cloned badge, if no access - document",
      "success_indicator": "Inside server room",
      "evidence": "Photo of server racks with timestamp"
    },
    "O3_implant_placement": {
      "device": "LAN Turtle",
      "placement": "Behind server rack, connected to switch",
      "concealment": "Under cable management",
      "callback_test": "Operator 2 confirms beacon received",
      "evidence": "Photo of installed device location"
    },
    "O4_document_photography": {
      "if_opportunity": "Photograph any visible sensitive docs",
      "method": "Smartphone quick photos",
      "priority": "LOW - only if safe"
    }
  },
  "phase_4_egress": {
    "method": "Continue delivery pretext - empty handed exit",
    "script": "Thanks, all delivered!",
    "route": "Same path as entry",
    "demeanor": "Relaxed, job done",
    "rendezvous": "Vehicle pickup point",
    "comms": "Radio confirmation: 'Package delivered'"
  },
  "contingency_plans": {
    "if_challenged_in_building": {
      "first_response": "Maintain pretext, apologize for confusion",
      "if_pressed": "Politely request to call CISO Jane Doe",
      "if_detained": "Show authorization letter, call emergency contact"
    },
    "if_guard_called": {
      "cooperate": true,
      "identify_as_tester": "Only if detained",
      "provide_letter": "Yes - sealed envelope"
    },
    "if_police_called": {
      "remain_calm": true,
      "do_not_resist": true,
      "request_call": "CISO Jane Doe emergency line",
      "provide_letter": true
    },
    "abort_signal": "Radio code 'Weather report'",
    "abort_actions": "Immediate calm egress, same pretext"
  },
  "evidence_documentation": {
    "required_photos": [
      "Building entrance access",
      "Server room entrance",
      "Server room interior",
      "Implant placement",
      "Any security gaps observed"
    ],
    "timestamp_all": true,
    "gps_tag": false,
    "chain_of_custody": "All photos reviewed with client"
  },
  "risk_assessment": {
    "overall_risk": "MODERATE",
    "detection_probability": 35,
    "arrest_probability": 5,
    "success_probability": 70,
    "mitigations": "Strong authorization, cooperative abort policy"
  }
}
```

**Criteres de notation** :
- Plan de mission complet et professionnel (25 pts)
- Gestion des pretextes et scenarios (25 pts)
- Contingences et considerations legales (20 pts)
- Documentation et preuves (15 pts)
- Format JSON valide (15 pts)

**Note** : 98/100

---

### EXERCICE 3.38.8 : Rogue Device Deployment

**Fichier** : `ex08_rogue_device/`

**Sujet** :
Planifiez le deploiement de dispositifs d'implant reseau lors d'une operation de pentest physique.

**Concepts evalues** : i, j, k, o

**Entree** :
```json
{
  "scenario": "Deploy network implant during authorized physical pentest",
  "available_devices": [
    {
      "name": "LAN_Turtle",
      "form_factor": "USB_ethernet_adapter",
      "capabilities": ["man_in_middle", "reverse_shell", "network_scan"],
      "power": "usb_powered",
      "concealment": "excellent"
    },
    {
      "name": "Raspberry_Pi_Zero",
      "form_factor": "credit_card_size",
      "capabilities": ["full_linux", "custom_tools", "wifi_ap"],
      "power": "usb_or_battery",
      "concealment": "good"
    },
    {
      "name": "Bash_Bunny",
      "form_factor": "usb_drive",
      "capabilities": ["keystroke_injection", "data_exfil", "network_attack"],
      "power": "usb_powered",
      "concealment": "excellent"
    },
    {
      "name": "WiFi_Pineapple",
      "form_factor": "router_size",
      "capabilities": ["rogue_ap", "wifi_mitm", "deauth"],
      "power": "power_adapter_or_battery",
      "concealment": "poor"
    }
  ],
  "target_environment": {
    "location": "Open office floor",
    "network_drops": ["behind_printers", "under_desks", "in_meeting_rooms"],
    "wifi_existing": true,
    "physical_access_duration_minutes": 30,
    "retrieval_planned": "next_day"
  },
  "objectives": [
    {"id": "D1", "description": "Establish persistent network access", "priority": "HIGH"},
    {"id": "D2", "description": "Capture network credentials", "priority": "MEDIUM"},
    {"id": "D3", "description": "Provide pivot point for red team", "priority": "HIGH"}
  ]
}
```

**Sortie attendue** :
```json
{
  "deployment_strategy": {
    "primary_device": "LAN_Turtle",
    "rationale": [
      "Excellent concealment as normal USB adapter",
      "Direct network access via ethernet",
      "Provides reverse shell for persistent access",
      "Low power draw, no battery needed"
    ],
    "secondary_device": "Raspberry_Pi_Zero",
    "rationale_secondary": [
      "Backup if ethernet unavailable",
      "Can create rogue WiFi AP",
      "More flexible with custom tooling"
    ]
  },
  "placement_plan": {
    "device_1": {
      "device": "LAN_Turtle",
      "location": "Behind printer on floor 2",
      "connection": "Inline between printer and network drop",
      "concealment": {
        "method": "Hidden behind printer stand",
        "visibility": "Not visible without moving printer",
        "power": "USB from printer or nearby outlet adapter"
      },
      "configuration": {
        "mode": "Transparent bridge + reverse shell",
        "callback_server": "attacker_vps.example.com:443",
        "protocol": "HTTPS for egress",
        "beacon_interval": "60_seconds"
      }
    },
    "device_2": {
      "device": "Raspberry_Pi_Zero",
      "location": "Meeting room media cabinet",
      "connection": "Ethernet drop in cabinet",
      "concealment": {
        "method": "Inside unlocked AV cabinet",
        "visibility": "Requires opening cabinet",
        "power": "USB from TV or battery pack (24h)"
      },
      "configuration": {
        "mode": "SSH reverse tunnel + packet capture",
        "callback_server": "Same VPS",
        "additional": "tcpdump capturing meeting room traffic"
      }
    }
  },
  "operational_security": {
    "device_configuration": [
      "No identifying labels or markings",
      "MAC address spoofed to match vendor equipment",
      "Hostname matches legitimate device names",
      "Encrypted storage for any captured data"
    ],
    "network_behavior": [
      "Minimal traffic during business hours",
      "Active scanning only during off-hours",
      "Blend with normal printer/AV traffic patterns"
    ],
    "failsafe": {
      "timer_wipe": "72 hours without callback = factory reset",
      "kill_command": "Remote wipe capability",
      "physical_recovery": "Retrieve within 48 hours max"
    }
  },
  "objectives_mapping": {
    "D1_persistent_access": {
      "device": "LAN_Turtle",
      "method": "Reverse shell beacon every 60s",
      "status": "ACHIEVED when beacon received"
    },
    "D2_credential_capture": {
      "device": "LAN_Turtle + Pi_Zero",
      "method": "Responder for LLMNR/NBT-NS, MITM proxy",
      "status": "ACHIEVED when first hash captured"
    },
    "D3_pivot_point": {
      "device": "Both",
      "method": "SSH tunnel for red team access to internal network",
      "status": "ACHIEVED when tunnel established"
    }
  },
  "installation_checklist": {
    "pre_deployment": [
      "Verify callback server accessible",
      "Test reverse shell on lab network",
      "Charge Pi battery pack fully",
      "Document device serial/MAC for reporting"
    ],
    "during_deployment": [
      "Photo each device installed location",
      "Verify LED indicators disabled/hidden",
      "Test callback immediately after install",
      "Confirm concealment effective"
    ],
    "post_deployment": [
      "Monitor for callback on VPS",
      "Log access timestamp",
      "Notify red team ops of pivot availability",
      "Schedule retrieval window"
    ]
  },
  "retrieval_plan": {
    "timing": "Next day, same pretext",
    "procedure": [
      "Retrieve LAN Turtle first (easier access)",
      "Retrieve Pi Zero if safe",
      "Photo empty locations as evidence",
      "Extract any captured data"
    ],
    "if_device_missing": "Report to client immediately, potential discovery"
  }
}
```

**Criteres de notation** :
- Selection appropriee des dispositifs (25 pts)
- Plan de dissimulation realiste (25 pts)
- Configuration technique correcte (20 pts)
- OPSEC et recuperation (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## SOUS-MODULE 3.38.5 : Social Engineering Field (16 concepts)

### Concepts couverts :
- **a** : SE Principles - Authority, urgency, social proof, reciprocity, liking, commitment
- **b** : Pretext Development - Research, backstory, documentation, practice, consistency
- **c** : Phone SE (Vishing) - Cold calls, helpdesk, executive assistant, IT support, vendors
- **d** : In-Person SE - Confidence, appearance, props, quick thinking, exit strategy
- **e** : Impersonation - Authority figures, service personnel, employees, executives
- **f** : Elicitation - Extract information, conversational, indirect questions
- **g** : Pretexting Calls - Research target, script, objection handling, voice acting
- **h** : Baiting - USB drops, malicious media, curiosity exploitation
- **i** : Quid Pro Quo - Offer help, technical support, gain access
- **j** : Dumpster Diving - Trash reconnaissance, documents, hardware, timing, legal
- **k** : Shoulder Surfing - Observe passwords, PINs, sensitive data, positioning
- **l** : Eavesdropping - Overhear conversations, public spaces, cafeteria, elevators
- **m** : Watering Hole Physical - Target frequented locations, cafes, conferences, networking
- **n** : Photography/Video - Document facilities, badges, screens, layout, covert capture
- **o** : OSINT for Physical - Floor plans, employee info, schedules, social media
- **p** : Counter-SE Awareness - Training programs, verification procedures, security culture

---

### EXERCICE 3.38.9 : Pretext Development & Execution

**Fichier** : `ex09_pretext_development/`

**Sujet** :
Developpez un pretexte complet pour une operation de social engineering physique incluant le personnage, les accessoires, et les scenarios de conversation.

**Concepts evalues** : a, b, c, d, e, f, g

**Entree** :
```json
{
  "target_organization": {
    "name": "TechnoHealth Medical Systems",
    "industry": "Healthcare IT",
    "size": 150,
    "security_culture": "relaxed"
  },
  "objective": "Gain access to IT department on floor 3",
  "intel_gathered": {
    "vendors_observed": ["Cisco", "Dell", "Healthcare_Software_Inc"],
    "recent_events": "New EHR system deployment ongoing",
    "IT_director": "Mike Johnson",
    "dress_code": "Business casual",
    "visitor_process": "Sign in at reception, escort varies"
  },
  "operator_profile": {
    "gender": "male",
    "age": 35,
    "appearance": "professional",
    "language_skills": "native_english"
  },
  "constraints": {
    "no_fake_credentials": true,
    "must_be_own_name": false,
    "recording_allowed": true
  }
}
```

**Sortie attendue** :
```json
{
  "pretext_design": {
    "persona": {
      "name": "David Miller",
      "company": "Healthcare Software Inc",
      "role": "Implementation Specialist",
      "backstory": "Assigned to assist with EHR deployment, following up on issues"
    },
    "justification": [
      "Healthcare Software Inc is known vendor",
      "EHR deployment provides legitimate reason to be in IT",
      "Implementation specialist is expected to visit without formal appointment",
      "Relaxed security culture suggests less verification"
    ]
  },
  "costume_and_props": {
    "clothing": {
      "description": "Business casual - khaki pants, polo shirt (neutral color)",
      "brand_items": "None visible - avoid trademark issues"
    },
    "props": [
      {
        "item": "Laptop bag",
        "purpose": "Professional appearance, carry equipment"
      },
      {
        "item": "Clipboard with technical documents",
        "purpose": "Legitimacy, something to reference"
      },
      {
        "item": "Lanyard with generic badge holder",
        "purpose": "Blend in, suggest visitor from another site"
      },
      {
        "item": "Business cards (David Miller, HSI)",
        "purpose": "Provide if requested, adds credibility"
      }
    ]
  },
  "conversation_scripts": {
    "reception_entry": {
      "opening": "Hi, I'm David Miller from Healthcare Software. I'm here to follow up with IT about the EHR deployment - there were some issues flagged last week.",
      "if_appointment_asked": "Mike's team requested we come by when we could - I was in the area for another client.",
      "if_escort_offered": "That would be great, thanks. I know you're busy.",
      "if_must_wait": "No problem, I'll wait. Can I grab a coffee while I'm here?"
    },
    "floor_navigation": {
      "if_questioned_by_employee": "Hey, I'm from Healthcare Software - here about the EHR issues. Do you know where Mike Johnson sits?",
      "if_directed": "Thanks, appreciate it!",
      "if_challenged": "Oh, I was told to come directly to IT - let me call Mike's office"
    },
    "IT_department_entry": {
      "to_IT_staff": "Hi, I'm David from HSI - here to follow up on those sync errors you guys reported. Who should I talk to?",
      "if_Mike_unavailable": "No worries - who's been handling the integration issues? I can work with them.",
      "elicitation_questions": [
        "How's the deployment going so far?",
        "Which modules are giving you the most trouble?",
        "Mind showing me the server room setup? Might help diagnose the sync issues."
      ]
    }
  },
  "se_principles_applied": {
    "authority": "Vendor representative with specialized knowledge",
    "reciprocity": "Offering to help fix their problems",
    "social_proof": "Reference ongoing deployment everyone knows about",
    "liking": "Friendly, helpful demeanor",
    "consistency": "They requested help, I'm delivering"
  },
  "objection_handling": {
    "we_didnt_schedule_you": "Yeah, sorry about that - Mike's team reached out last week about the sync errors, I was nearby so thought I'd stop in. Want me to call him?",
    "need_to_verify": "Absolutely, here's my card. You can call our main office too if you want to verify.",
    "cant_let_you_in_without_escort": "Totally understand. Is there someone available? Happy to wait.",
    "Mike_is_out_today": "No worries - is Sarah or whoever's been handling the deployment around? I can work with whoever."
  },
  "exit_strategy": {
    "natural_exit": "Thanks everyone, I'll follow up with Mike about the fix timeline. Here's my card if anything comes up.",
    "if_suspicious": "Let me make a call to my office and verify my schedule - might have gotten the dates mixed up. Sorry for the confusion.",
    "abort_scenario": "Actually, I just got a page from another client - emergency. I'll reschedule with Mike's office. Thanks for your help."
  },
  "success_metrics": [
    {"metric": "Access to IT floor", "priority": "HIGH"},
    {"metric": "Visual access to server room", "priority": "MEDIUM"},
    {"metric": "Employee credentials observed", "priority": "LOW"},
    {"metric": "Network topology info elicited", "priority": "MEDIUM"}
  ]
}
```

**Criteres de notation** :
- Persona credible et bien recherche (25 pts)
- Scripts de conversation realistes (25 pts)
- Application des principes SE (20 pts)
- Gestion des objections (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

### EXERCICE 3.38.10 : Physical Intelligence Collection

**Fichier** : `ex10_intel_collection/`

**Sujet** :
Planifiez des operations de collecte de renseignements physiques incluant le dumpster diving, shoulder surfing, et la reconnaissance photographique.

**Concepts evalues** : h, j, k, l, m, n, o

**Entree** :
```json
{
  "target": {
    "name": "Fintech Innovations LLC",
    "location": "Office park, building B",
    "employees": 80,
    "security_level": "moderate"
  },
  "collection_objectives": [
    {"id": "I1", "type": "credentials", "description": "Passwords, PINs observed"},
    {"id": "I2", "type": "documents", "description": "Discarded sensitive docs"},
    {"id": "I3", "type": "layout", "description": "Internal floor plan, camera positions"},
    {"id": "I4", "type": "badges", "description": "Badge format, employee names"},
    {"id": "I5", "type": "schedules", "description": "Guard patterns, employee routines"}
  ],
  "opportunities_identified": {
    "dumpster_access": {
      "location": "Rear parking lot",
      "pickup_schedule": "Monday and Thursday 6am",
      "shredding": "On-site, but overflow seen"
    },
    "public_areas": {
      "cafe_nearby": "Coffee shop across street",
      "smoking_area": "Side entrance",
      "lunch_spots": ["Cafe", "Food truck lot"]
    },
    "building_exterior": {
      "windows": "Visible from parking lot",
      "entrances": 3,
      "cameras": "Main entrance only"
    }
  },
  "operator_cover": {
    "available_personas": [
      "Job applicant",
      "Delivery driver",
      "Building maintenance (other tenant)"
    ]
  },
  "legal_constraints": {
    "no_trespassing": true,
    "public_areas_only_unless_authorized": true,
    "photography_from_public": true
  }
}
```

**Sortie attendue** :
```json
{
  "collection_plan": {
    "duration": "3 days reconnaissance",
    "approach": "Multi-source intelligence gathering"
  },
  "operation_1_dumpster_diving": {
    "objective": ["I2 - Documents"],
    "timing": {
      "optimal": "Wednesday evening (night before pickup)",
      "window": "21:00-23:00",
      "rationale": "Maximum accumulation, low activity"
    },
    "procedure": {
      "approach": "Park in adjacent lot, walk to dumpster area",
      "cover": "If challenged - 'Looking for cardboard boxes for moving'",
      "equipment": ["Flashlight (red filter)", "Gloves", "Bags", "Grabber tool"]
    },
    "search_priorities": [
      {"item": "Post-it notes", "value": "Often contain passwords"},
      {"item": "Org charts/directories", "value": "Employee intel"},
      {"item": "Meeting notes", "value": "Projects, timelines"},
      {"item": "Failed printouts", "value": "May contain sensitive data"},
      {"item": "Envelopes", "value": "Vendor relationships"}
    ],
    "legal_note": "Dumpster on private property but accessible - grey area, proceed carefully",
    "evidence_handling": "Photograph documents on-site, minimize removal"
  },
  "operation_2_shoulder_surfing": {
    "objective": ["I1 - Credentials"],
    "locations": [
      {
        "spot": "Coffee shop across street",
        "setup": "Seat with view of Fintech entrance",
        "target": "Employees using phones/laptops while waiting",
        "equipment": "Phone with camera, zoom capability"
      },
      {
        "spot": "Smoking area",
        "setup": "Casual smoker persona",
        "target": "Employees checking phones, typing PINs",
        "equipment": "Covert camera glasses (if authorized)"
      }
    ],
    "techniques": [
      "Position behind target, observe screen reflection",
      "Note keyboard patterns during password entry",
      "Observe badge swipes - note card positioning",
      "Listen for spoken credentials (speakerphone)"
    ],
    "cover_story": "Remote worker, between meetings",
    "duration": "2-hour sessions, multiple days"
  },
  "operation_3_photography_reconnaissance": {
    "objective": ["I3 - Layout", "I4 - Badges"],
    "public_photography": {
      "positions": [
        {"location": "Street sidewalk", "targets": ["Building exterior", "Entrance cameras", "Windows"]},
        {"location": "Parking lot edge", "targets": ["Loading dock", "Emergency exits", "Dumpster area"]},
        {"location": "Coffee shop window", "targets": ["Employee entrance patterns", "Badge visible on lanyards"]}
      ],
      "equipment": "DSLR with telephoto (natural looking), smartphone backup",
      "timing": "Morning arrival 08:00-09:00, Evening departure 17:00-18:00"
    },
    "badge_capture": {
      "method": "Telephoto shots of employees entering",
      "target_data": ["Badge format", "Employee names", "Photo if possible"],
      "legal": "Public sidewalk photography is legal"
    }
  },
  "operation_4_eavesdropping": {
    "objective": ["I5 - Schedules", "General intel"],
    "locations": [
      {
        "spot": "Food truck lot during lunch",
        "method": "Casual proximity to employee groups",
        "intel_targets": ["Project discussions", "Schedule complaints", "Security gripes"]
      },
      {
        "spot": "Elevator if access gained",
        "method": "Shared ride, casual conversation",
        "intel_targets": ["Department info", "Manager names", "System names"]
      }
    ],
    "approach": "Passive listening, no directed questions unless cover established"
  },
  "operation_5_watering_hole": {
    "objective": "General intel, badge observation",
    "target_location": "Happy hour bar Fridays (identified via social media)",
    "method": "Blend into after-work crowd",
    "intel_opportunities": [
      "Employees may leave badges visible",
      "Conversations about work",
      "Network via friendly chat"
    ],
    "cover": "Tech professional, new to area"
  },
  "collected_intel_matrix": {
    "I1_credentials": {
      "collection_methods": ["Shoulder surfing", "Dumpster diving (post-its)"],
      "expected_yield": "2-5 credentials",
      "confidence": "MEDIUM"
    },
    "I2_documents": {
      "collection_methods": ["Dumpster diving"],
      "expected_yield": "10-50 relevant documents",
      "confidence": "HIGH"
    },
    "I3_layout": {
      "collection_methods": ["Photography", "Eavesdropping"],
      "expected_yield": "Exterior confirmed, interior partial",
      "confidence": "MEDIUM"
    },
    "I4_badges": {
      "collection_methods": ["Photography", "Watering hole observation"],
      "expected_yield": "5-10 badge photos",
      "confidence": "HIGH"
    },
    "I5_schedules": {
      "collection_methods": ["Eavesdropping", "Pattern observation"],
      "expected_yield": "Guard schedule partial, peak hours confirmed",
      "confidence": "MEDIUM"
    }
  },
  "opsec_considerations": {
    "vary_appearance": "Different clothing each day",
    "vary_timing": "Avoid predictable patterns",
    "vehicle": "Park in different locations",
    "digital": "Phone in airplane mode during sensitive collection"
  }
}
```

**Criteres de notation** :
- Plan de collecte multi-sources (25 pts)
- Techniques de reconnaissance appropriees (25 pts)
- Respect des contraintes legales (20 pts)
- OPSEC operateur (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## SOUS-MODULE 3.38.6 : Alarm & Sensor Bypass (14 concepts)

### Concepts couverts :
- **a** : Alarm System Components - Panel, sensors, communication, monitoring, power
- **b** : PIR Motion Sensors - Passive infrared, detection pattern, slow movement, masking
- **c** : Microwave Sensors - Doppler radar, detection patterns, material penetration
- **d** : Dual-Tech Sensors - PIR + microwave, both must trigger, harder bypass
- **e** : Door/Window Contacts - Magnetic reed switch, magnet bypass, wired vs wireless
- **f** : Glass Break Sensors - Acoustic, shock, frequency analysis, flex sensors
- **g** : Beam Sensors - Photoelectric, laser, IR beam, mirrors, detection
- **h** : Pressure Sensors - Floor mats, weight detection, perimeter, buried
- **i** : Vibration Sensors - Safe protection, vault, ATM, fence-mounted
- **j** : Communication Attacks - GSM jamming, phone line cut, IP disruption, cellular backup
- **k** : Panel Attacks - Default codes, brute force, tamper bypass, vulnerability
- **l** : Sensor Masking - Spray, tape, slow approach, environmental factors
- **m** : CCTV Avoidance - Camera mapping, blind spots, disguise, timing
- **n** : Testing Safely - Non-destructive, controlled, avoid actual alarm activation

---

### EXERCICE 3.38.11 : Alarm System Analysis

**Fichier** : `ex11_alarm_analysis/`

**Sujet** :
Analysez un systeme d'alarme et developpez des strategies de contournement tout en testant de maniere controlee.

**Concepts evalues** : a, b, c, d, e, j, k, n

**Entree** :
```json
{
  "target_facility": "Small business office",
  "alarm_system": {
    "brand": "Honeywell",
    "model": "Vista 20P",
    "age_years": 5,
    "monitoring": {
      "type": "cellular_primary",
      "backup": "phone_line",
      "monitoring_company": "Regional Security Inc"
    },
    "sensors_observed": [
      {"type": "PIR_motion", "location": "Main hallway", "model": "5800PIR-RES"},
      {"type": "PIR_motion", "location": "Server room", "model": "5800PIR-RES"},
      {"type": "Door_contact", "location": "Front door", "model": "5816WMWH"},
      {"type": "Door_contact", "location": "Back door", "model": "5816WMWH"},
      {"type": "Window_contact", "location": "Windows x4", "model": "5816WMWH"},
      {"type": "Glass_break", "location": "Reception", "model": "5853"}
    ],
    "keypad_locations": ["Front entrance", "Back hallway"],
    "user_codes": "Unknown - likely 4 digits",
    "entry_delay_seconds": 30
  },
  "physical_layout": {
    "entry_points": ["Front door", "Back door", "Windows", "Roof hatch"],
    "keypad_to_door_distance_m": 5,
    "motion_coverage": "70% of interior"
  },
  "authorized_testing": true,
  "constraints": {
    "avoid_actual_alarm": true,
    "non_destructive": true,
    "monitoring_company_notified": false
  }
}
```

**Sortie attendue** :
```json
{
  "system_assessment": {
    "brand_model": "Honeywell Vista 20P",
    "overall_security": "MODERATE",
    "known_vulnerabilities": [
      "Vista 20P has documented default installer code vulnerabilities",
      "Wireless sensors can be jammed",
      "Entry delay provides bypass window"
    ],
    "strengths": [
      "Dual communication paths (cellular + phone)",
      "Multiple sensor types",
      "UL listed equipment"
    ]
  },
  "sensor_analysis": [
    {
      "sensor": "PIR Motion (5800PIR-RES)",
      "detection_method": "Passive infrared - heat differential",
      "coverage_pattern": "90 degree cone, 12m range",
      "vulnerabilities": [
        "Slow movement may avoid detection",
        "Thermal masking (insulating suit) can reduce detection",
        "Pet immune setting may allow low crawl"
      ],
      "bypass_difficulty": "MODERATE"
    },
    {
      "sensor": "Door Contact (5816WMWH)",
      "detection_method": "Magnetic reed switch - wireless",
      "vulnerabilities": [
        "External magnet bypass possible",
        "RF jamming can block wireless signal"
      ],
      "bypass_difficulty": "EASY"
    },
    {
      "sensor": "Glass Break (5853)",
      "detection_method": "Acoustic - listens for glass break frequency",
      "vulnerabilities": [
        "Only triggers on specific frequency pattern",
        "Gradual cutting doesn't trigger",
        "Muffling glass during break may reduce detection"
      ],
      "bypass_difficulty": "MODERATE"
    }
  ],
  "attack_vectors": [
    {
      "method": "Entry Delay Exploitation",
      "description": "Enter through door, reach keypad within 30 seconds",
      "procedure": [
        "Open front door - starts 30 second timer",
        "Move quickly to keypad (5m, ~3 seconds)",
        "Attempt default codes or observed code",
        "If fail, retreat before alarm"
      ],
      "requirements": ["Code knowledge or luck", "Speed"],
      "success_probability": 25,
      "testing_approach": "Time movement from door to keypad without arming system"
    },
    {
      "method": "Magnet Bypass Door Contact",
      "description": "Apply external magnet to maintain sensor closed state",
      "procedure": [
        "Identify sensor magnet position on door frame",
        "Apply strong magnet adjacent to reed switch",
        "Slowly open door while maintaining magnet proximity",
        "Reed switch stays closed, no trigger"
      ],
      "requirements": ["Strong rare earth magnet", "Precise positioning"],
      "success_probability": 60,
      "testing_approach": "Test on disarmed system, verify sensor stays 'closed'"
    },
    {
      "method": "PIR Slow Movement",
      "description": "Move slowly to avoid triggering motion detection",
      "procedure": [
        "Map PIR coverage area during recon",
        "Enter through non-monitored area",
        "Move at ~0.1 m/s through detection zone",
        "Maintain consistent body temp presentation"
      ],
      "requirements": ["Patience", "Coverage map", "Alternative entry"],
      "success_probability": 40,
      "testing_approach": "Test with system in 'Test Mode' if accessible"
    },
    {
      "method": "Communication Jamming",
      "description": "Block cellular and phone line reporting",
      "procedure": [
        "Deploy cellular jammer near panel antenna",
        "Cut or flood phone line",
        "Panel cannot report alarm to monitoring"
      ],
      "requirements": ["RF jammer (illegal in many jurisdictions)", "Physical access to phone line"],
      "success_probability": 70,
      "legal_warning": "RF jamming is federal offense in US/EU - testing only in shielded environment",
      "testing_approach": "SKIP - legal risk too high without proper authorization"
    },
    {
      "method": "Panel Default Code",
      "description": "Try known default installer codes",
      "procedure": [
        "Access keypad",
        "Try: 4112 (Honeywell default), 1234, 0000",
        "Enter installer mode to disarm or modify"
      ],
      "requirements": ["Keypad access"],
      "success_probability": 20,
      "testing_approach": "Test on disarmed system, count attempts before lockout"
    }
  ],
  "safe_testing_protocol": {
    "preparation": [
      "Coordinate with facility owner",
      "Set panel to Test Mode if possible",
      "Have emergency disarm code ready",
      "Inform any monitoring manually"
    ],
    "test_1_entry_delay": {
      "description": "Time door-to-keypad traversal",
      "safety": "System disarmed, measure only",
      "data_collected": "Time to reach keypad, obstacles"
    },
    "test_2_magnet_bypass": {
      "description": "Test magnet bypass on disarmed sensor",
      "safety": "System disarmed",
      "data_collected": "Magnet strength needed, positioning"
    },
    "test_3_pir_sensitivity": {
      "description": "Map PIR detection zones",
      "safety": "System disarmed or test mode",
      "data_collected": "Coverage gaps, detection threshold"
    },
    "test_4_default_codes": {
      "description": "Try default codes",
      "safety": "Document lockout behavior",
      "data_collected": "Code acceptance, lockout threshold"
    }
  },
  "recommendations": {
    "best_approach": "Magnet bypass + entry delay exploitation",
    "rationale": "Lowest risk, highest success without RF jamming",
    "timing": "Night - slower response time from monitoring",
    "contingency": "Abort if alarm triggers, retreat immediately"
  }
}
```

**Criteres de notation** :
- Analyse correcte des composants d'alarme (25 pts)
- Vecteurs d'attaque realistes (25 pts)
- Protocole de test securise (20 pts)
- Considerations legales/ethiques (15 pts)
- Format JSON valide (15 pts)

**Note** : 98/100

---

### EXERCICE 3.38.12 : Sensor Bypass Techniques

**Fichier** : `ex12_sensor_bypass/`

**Sujet** :
Developpez des techniques de contournement pour differents types de capteurs de securite.

**Concepts evalues** : b, c, d, f, g, h, i, l

**Entree** :
```json
{
  "scenario": "Access vault room protected by multiple sensor types",
  "path_to_objective": {
    "segments": [
      {
        "id": "S1",
        "location": "Exterior approach",
        "sensors": ["CCTV", "Perimeter beam"]
      },
      {
        "id": "S2",
        "location": "Main corridor",
        "sensors": ["PIR_motion"]
      },
      {
        "id": "S3",
        "location": "Secure hallway",
        "sensors": ["Dual-tech (PIR+Microwave)", "Pressure mat"]
      },
      {
        "id": "S4",
        "location": "Vault entrance",
        "sensors": ["Vibration sensor", "Glass break"]
      },
      {
        "id": "S5",
        "location": "Inside vault",
        "sensors": ["PIR_motion", "Seismic"]
      }
    ]
  },
  "sensor_details": {
    "CCTV": {"type": "IP cameras", "coverage": "Parking to entrance", "monitoring": "24/7"},
    "Perimeter_beam": {"type": "IR photoelectric", "height": "1m", "pairs": 2},
    "PIR_motion": {"type": "Passive infrared", "sensitivity": "standard", "coverage": "Wide angle"},
    "Dual_tech": {"type": "PIR + Microwave", "requirement": "Both must trigger"},
    "Pressure_mat": {"type": "Hidden under carpet", "threshold": "15kg"},
    "Vibration": {"type": "On vault door", "sensitivity": "High"},
    "Glass_break": {"type": "Acoustic", "range": "8m"},
    "Seismic": {"type": "Floor/wall mounted", "sensitivity": "Extreme"}
  },
  "available_equipment": [
    "IR pass-through panels",
    "Thermal suit",
    "Foam stepping pads",
    "Sound dampening materials",
    "Vibration absorption mounts"
  ]
}
```

**Sortie attendue** :
```json
{
  "bypass_strategy_by_segment": [
    {
      "segment": "S1 - Exterior approach",
      "sensors": ["CCTV", "Perimeter beam"],
      "bypass_techniques": [
        {
          "sensor": "CCTV",
          "technique": "Blind spot navigation",
          "method": "Map camera coverage, identify dead zones, time approach to avoid direct view",
          "equipment": "None - reconnaissance required",
          "success_rate": 70,
          "alternative": "Disguise matching legitimate activity (cleaning crew)"
        },
        {
          "sensor": "Perimeter beam",
          "technique": "Step over or IR pass-through",
          "method": "Beams at 1m height - step over carefully, or use IR transparent panels to allow beam through while passing",
          "equipment": "IR pass-through panels (acrylic)",
          "success_rate": 80,
          "detail": "Place panel in beam path, maintain beam continuity while moving through"
        }
      ]
    },
    {
      "segment": "S2 - Main corridor",
      "sensors": ["PIR_motion"],
      "bypass_techniques": [
        {
          "sensor": "PIR motion",
          "technique": "Thermal masking",
          "method": "Wear thermal suit to reduce body heat signature, move slowly",
          "equipment": "Thermal suit (insulating layer)",
          "success_rate": 50,
          "detail": "PIR detects heat differential - equalizing body temp to ambient reduces detection"
        },
        {
          "sensor": "PIR motion",
          "technique": "Slow movement",
          "method": "Move at extremely slow pace (<5cm/sec), avoid sudden movements",
          "equipment": "None",
          "success_rate": 40,
          "detail": "Some PIRs have sensitivity gaps for very slow motion"
        }
      ],
      "recommended": "Thermal suit + slow movement combination"
    },
    {
      "segment": "S3 - Secure hallway",
      "sensors": ["Dual-tech (PIR+Microwave)", "Pressure mat"],
      "bypass_techniques": [
        {
          "sensor": "Dual-tech",
          "technique": "Defeat PIR only",
          "method": "Dual-tech requires BOTH PIR and Microwave to trigger. Thermal suit defeats PIR, microwave may still see movement but no alarm",
          "equipment": "Thermal suit",
          "success_rate": 65,
          "detail": "AND logic means defeating one sensor defeats the pair"
        },
        {
          "sensor": "Pressure mat",
          "technique": "Weight distribution",
          "method": "15kg threshold - use foam pads to distribute weight, or span mat entirely",
          "equipment": "Foam stepping pads (large surface area)",
          "success_rate": 70,
          "detail": "If mat is narrow, may be possible to step over entirely"
        }
      ],
      "combined_approach": "Thermal suit + foam pads for weight distribution"
    },
    {
      "segment": "S4 - Vault entrance",
      "sensors": ["Vibration sensor", "Glass break"],
      "bypass_techniques": [
        {
          "sensor": "Vibration sensor",
          "technique": "Vibration dampening",
          "method": "Mount cutting/drilling tools on vibration absorption pads, use slow cutting speeds",
          "equipment": "Vibration absorption mounts",
          "success_rate": 45,
          "detail": "Very sensitive - may require specialized equipment or avoid door entirely"
        },
        {
          "sensor": "Glass break",
          "technique": "Slow glass removal",
          "method": "If glass present, use glass cutter and controlled removal rather than breaking",
          "equipment": "Glass cutting kit, suction cups",
          "success_rate": 75,
          "detail": "Acoustic sensors respond to break frequency, not cutting"
        }
      ],
      "alternative_entry": "Consider alternate entry point to avoid vault door sensors"
    },
    {
      "segment": "S5 - Inside vault",
      "sensors": ["PIR_motion", "Seismic"],
      "bypass_techniques": [
        {
          "sensor": "PIR motion",
          "technique": "Same thermal masking as S2",
          "method": "Maintain thermal suit, slow movement",
          "equipment": "Thermal suit",
          "success_rate": 50
        },
        {
          "sensor": "Seismic",
          "technique": "Movement minimization",
          "method": "Seismic sensors extremely sensitive - any significant movement detected",
          "equipment": "Foam pads, extreme slow motion",
          "success_rate": 25,
          "reality_check": "Seismic sensors are near-impossible to bypass reliably"
        }
      ],
      "assessment": "VERY DIFFICULT - seismic sensors present major challenge"
    }
  ],
  "overall_penetration_assessment": {
    "success_probability_full_path": 15,
    "primary_blocker": "Seismic sensors in vault (S5)",
    "recommended_approach": {
      "method": "Focus on S1-S4, demonstrate access to vault entrance",
      "equipment_required": ["IR panels", "Thermal suit", "Foam pads", "Glass cutting kit"],
      "timing": "Night - reduced monitoring attention",
      "documentation": "Photo each segment bypassed as evidence"
    },
    "alternative_objectives": [
      "Demonstrate perimeter bypass (S1) - achievable",
      "Demonstrate corridor penetration (S2-S3) - challenging but feasible",
      "Document vault entrance access (S4) - partial success valuable"
    ]
  },
  "training_recommendations": {
    "S2_PIR_bypass": "Practice slow movement techniques - timing, pace, temperature",
    "S3_pressure_mat": "Test weight distribution equipment on similar mat",
    "S4_vibration": "Specialized training in vibration dampening techniques"
  }
}
```

**Criteres de notation** :
- Techniques de bypass par type de capteur (25 pts)
- Approche combinee realiste (25 pts)
- Evaluation des probabilites de succes (20 pts)
- Recommandations pratiques (15 pts)
- Format JSON valide (15 pts)

**Note** : 97/100

---

## EXERCICES DE SYNTHESE

### EXERCICE 3.38.13 : Full Physical Pentest Report

**Fichier** : `ex13_pentest_report/`

**Sujet** :
Generez un rapport de pentest physique complet incluant tous les findings, evidences, et recommandations.

**Concepts evalues** : Synthese de tous les concepts 3.38.1-3.38.6

**Entree** :
```json
{
  "engagement": {
    "client": "Apex Industries",
    "type": "Physical Penetration Test",
    "scope": "Corporate HQ - full building",
    "dates": "2025-12-10 to 2025-12-12",
    "authorization": "Full scope signed SOW"
  },
  "test_results": {
    "day_1": {
      "activities": ["External reconnaissance", "OSINT collection", "Badge photography"],
      "findings": [
        {"id": "F1", "type": "observation", "description": "125kHz HID badges observed - easily cloneable"},
        {"id": "F2", "type": "observation", "description": "Guard patrol predictable - 20 min cycles"},
        {"id": "F3", "type": "collected", "description": "12 employee names from badge photos"}
      ]
    },
    "day_2": {
      "activities": ["Social engineering entry", "Internal reconnaissance", "Badge clone test"],
      "findings": [
        {"id": "F4", "type": "success", "description": "Gained entry via delivery pretext - no escort"},
        {"id": "F5", "type": "success", "description": "Reached server room floor - badge clone worked"},
        {"id": "F6", "type": "success", "description": "Photographed server room through window"},
        {"id": "F7", "type": "observation", "description": "Server room door has 4-digit keypad - wear marks visible"}
      ]
    },
    "day_3": {
      "activities": ["Server room entry attempt", "Device placement", "Egress"],
      "findings": [
        {"id": "F8", "type": "success", "description": "Server room entered - PIN 1593 from wear pattern + observation"},
        {"id": "F9", "type": "success", "description": "LAN Turtle deployed - confirmed callback"},
        {"id": "F10", "type": "success", "description": "Clean egress without detection"},
        {"id": "F11", "type": "observation", "description": "No cameras in server room corridor"}
      ]
    }
  },
  "evidence_collected": {
    "photos": 47,
    "documents_from_dumpster": 12,
    "credentials_observed": 3,
    "badge_clones_created": 2,
    "devices_deployed": 1
  }
}
```

**Sortie attendue** :
```json
{
  "report": {
    "title": "Physical Penetration Test Report",
    "client": "Apex Industries",
    "classification": "CONFIDENTIAL",
    "date": "2025-12-15",
    "version": "1.0"
  },
  "executive_summary": {
    "overall_rating": "CRITICAL",
    "summary": "Physical penetration testing of Apex Industries Corporate HQ revealed critical security gaps allowing unauthorized building access, server room entry, and deployment of network implant devices. Testers gained full physical access to critical infrastructure within 3 days using social engineering, badge cloning, and observation techniques.",
    "key_findings": [
      "Building entry achieved via social engineering with no verification",
      "Badge access control bypassed through cloning of 125kHz HID cards",
      "Server room accessed by deriving keypad PIN from wear patterns",
      "Network implant successfully deployed and operational",
      "No detection or challenge throughout entire engagement"
    ],
    "risk_level": "CRITICAL",
    "immediate_actions_required": [
      "Implement visitor verification procedures",
      "Upgrade to encrypted badge system (iCLASS SE or similar)",
      "Randomize or replace server room keypad codes monthly",
      "Install cameras in server room corridor"
    ]
  },
  "findings_detail": [
    {
      "id": "PHYS-001",
      "title": "Inadequate Visitor Verification",
      "severity": "CRITICAL",
      "cvss_physical": 9.0,
      "description": "Reception allowed entry based on verbal pretext without verification call or escort assignment.",
      "evidence": ["Photo timestamp lobby entry", "No visitor badge issued"],
      "impact": "Unauthorized individuals can access building interior",
      "recommendation": "Implement mandatory visitor verification: photo ID check, call to host, escort at all times",
      "remediation_effort": "LOW"
    },
    {
      "id": "PHYS-002",
      "title": "Cloneable Badge Technology",
      "severity": "HIGH",
      "cvss_physical": 8.0,
      "description": "125kHz HID Proximity badges in use have no encryption and are trivially cloneable with $50 equipment.",
      "evidence": ["Badge type photos", "Successful clone test logs"],
      "impact": "Any employee badge can be cloned from brief proximity",
      "recommendation": "Migrate to encrypted credential system (HID iCLASS SE, Seos, or DESFire)",
      "remediation_effort": "MEDIUM-HIGH"
    },
    {
      "id": "PHYS-003",
      "title": "Predictable Keypad PIN",
      "severity": "CRITICAL",
      "cvss_physical": 8.5,
      "description": "Server room keypad shows visible wear on digits 1, 3, 5, 9. Combined with observation, PIN was derived as 1593.",
      "evidence": ["Keypad wear pattern photo", "Server room entry photo with timestamp"],
      "impact": "Critical infrastructure accessible to anyone who observes PIN entry",
      "recommendation": "Replace keypad with non-wearing surface, implement randomized PIN rotation monthly, add multi-factor",
      "remediation_effort": "LOW"
    },
    {
      "id": "PHYS-004",
      "title": "Successful Network Implant Deployment",
      "severity": "CRITICAL",
      "cvss_physical": 10.0,
      "description": "LAN Turtle device deployed in server room, successfully called back to external C2 server.",
      "evidence": ["Device placement photo", "C2 callback logs"],
      "impact": "Persistent network access achieved, lateral movement possible",
      "recommendation": "Implement network access control (NAC), regular physical audits of network equipment",
      "remediation_effort": "MEDIUM"
    },
    {
      "id": "PHYS-005",
      "title": "No Surveillance in Critical Corridor",
      "severity": "HIGH",
      "cvss_physical": 7.0,
      "description": "Corridor leading to server room has no camera coverage, allowing unmonitored access.",
      "evidence": ["Photo of corridor - no cameras visible"],
      "impact": "No visual record of server room access attempts",
      "recommendation": "Install cameras covering all approaches to server room, implement 90-day retention",
      "remediation_effort": "LOW"
    },
    {
      "id": "PHYS-006",
      "title": "Predictable Guard Patrol Pattern",
      "severity": "MEDIUM",
      "cvss_physical": 5.5,
      "description": "Guard patrols follow predictable 20-minute cycle, easily timed for entry windows.",
      "evidence": ["Observation logs over 2 days"],
      "impact": "Intruders can time activities between patrols",
      "recommendation": "Randomize patrol schedules, implement check-point verification system",
      "remediation_effort": "LOW"
    }
  ],
  "attack_path_summary": {
    "diagram": "External -> Lobby (Social Engineering) -> Office Floor (Badge Clone) -> Server Corridor (No Challenge) -> Server Room (PIN Derived) -> Network (Implant Deployed)",
    "total_time_minutes": 45,
    "detection_points_bypassed": 4,
    "challenges_received": 0
  },
  "recommendations_prioritized": [
    {
      "priority": 1,
      "item": "Implement visitor verification and escort policy",
      "effort": "LOW",
      "impact": "Prevents social engineering entry"
    },
    {
      "priority": 2,
      "item": "Change server room PIN, implement rotation policy",
      "effort": "LOW",
      "impact": "Prevents PIN observation attack"
    },
    {
      "priority": 3,
      "item": "Install cameras in server corridor",
      "effort": "LOW",
      "impact": "Provides detection and evidence"
    },
    {
      "priority": 4,
      "item": "Implement NAC to detect rogue devices",
      "effort": "MEDIUM",
      "impact": "Prevents implant persistence"
    },
    {
      "priority": 5,
      "item": "Upgrade to encrypted badge system",
      "effort": "HIGH",
      "impact": "Eliminates badge cloning attack vector"
    }
  ],
  "appendices": {
    "A": "Evidence photos (47 items) - separate encrypted archive",
    "B": "Timeline of activities",
    "C": "Equipment used",
    "D": "Authorization documentation"
  }
}
```

**Criteres de notation** :
- Rapport structure professionnellement (25 pts)
- Findings detailles avec evidences (25 pts)
- Recommandations priorisees actionables (20 pts)
- Resume executif clair (15 pts)
- Format JSON valide (15 pts)

**Note** : 98/100

---

### EXERCICE 3.38.14 : Red Team Physical Operation

**Fichier** : `ex14_red_team_physical/`

**Sujet** :
Planifiez et simulez une operation Red Team combinant attaques physiques et cyber pour atteindre un objectif strategique.

**Concepts evalues** : Synthese avancee de tous les concepts avec integration cyber

**Entree** :
```json
{
  "operation": {
    "codename": "Operation Shadow Access",
    "type": "Red Team - Combined Physical/Cyber",
    "client": "Global Finance Corp",
    "authorization": "Full scope - CEO approved",
    "duration_days": 5
  },
  "objective": {
    "primary": "Exfiltrate sample data from trading system database",
    "secondary": ["Demonstrate C-suite physical access", "Test incident response"],
    "constraints": ["No production impact", "Evidence required", "Clean exit"]
  },
  "target_environment": {
    "physical": {
      "building": "40-story financial tower",
      "target_floor": "35 - Trading operations",
      "security": "Enterprise grade - guards, badges, biometrics on critical floors"
    },
    "cyber": {
      "network": "Segmented - trading on isolated VLAN",
      "defenses": "IDS/IPS, SIEM, EDR on endpoints",
      "known_systems": ["Trading platform - custom", "Bloomberg terminals", "Order management"]
    }
  },
  "team": {
    "physical_operators": 2,
    "cyber_operators": 2,
    "coordination": "Encrypted comms, real-time sync"
  },
  "intel_gathered": {
    "badge_format": "HID iCLASS SE - encrypted",
    "biometric": "Fingerprint for floor 35+",
    "network_diagram": "Partial - from public filings",
    "employee_list": "OSINT - LinkedIn, conferences",
    "trading_hours": "06:00-20:00 local"
  }
}
```

**Sortie attendue** :
```json
{
  "operation_plan": {
    "codename": "Operation Shadow Access",
    "classification": "RED TEAM - AUTHORIZED",
    "commander": "Lead Operator",
    "phases": 5
  },
  "phase_1_reconnaissance": {
    "duration": "Days 1-2",
    "objectives": ["Finalize physical intel", "Identify network entry points", "Credential gathering"],
    "physical_recon": {
      "activities": [
        "External building survey - all entrances",
        "Guard rotation timing",
        "Delivery schedule observation",
        "Badge format confirmation from distance photos"
      ],
      "deliverables": ["Building access map", "Guard schedule", "Entry point ranking"]
    },
    "cyber_recon": {
      "activities": [
        "Passive network enumeration from public sources",
        "Employee OSINT - identify targets for SE",
        "Technology stack identification",
        "Phishing target list development"
      ],
      "deliverables": ["Target employee list", "Network hypothesis", "Phishing pretext"]
    },
    "coordination_point": "D2 evening - Intel fusion meeting"
  },
  "phase_2_initial_access": {
    "duration": "Day 3 morning",
    "physical_track": {
      "method": "Social engineering - vendor pretext",
      "pretext": "Bloomberg terminal maintenance technician",
      "target_entry": "Service entrance with delivery badge",
      "equipment": ["Fake Bloomberg ID", "Laptop bag with implant", "Uniform"],
      "objective": "Reach trading floor, plant network implant"
    },
    "cyber_track": {
      "method": "Targeted phishing",
      "target": "Trading floor admin assistant",
      "pretext": "IT security verification required",
      "payload": "Macro-enabled document -> reverse shell",
      "timing": "Send during physical operator approach"
    },
    "synchronization": {
      "signal": "Physical operator at floor 35 -> Cyber launches phish",
      "rationale": "IT may investigate phish - physical operator diverts attention"
    }
  },
  "phase_3_establish_persistence": {
    "duration": "Day 3 afternoon",
    "physical_implant": {
      "device": "Modified USB ethernet adapter",
      "placement": "Behind Bloomberg terminal - network drop access",
      "capability": "Bridge to trading VLAN, reverse SSH tunnel",
      "concealment": "Matches existing cable clutter"
    },
    "cyber_persistence": {
      "if_phish_successful": "Establish C2, enumerate AD, lateral movement",
      "if_phish_failed": "Rely on physical implant for network access",
      "backup": "Physical operator attempts workstation access directly"
    },
    "risk_mitigation": "If challenged, abort physical, rely on cyber track"
  },
  "phase_4_objective_execution": {
    "duration": "Days 3-4",
    "primary_objective": {
      "target": "Trading database - sample data exfil",
      "access_method": "Pivot through implant to trading VLAN",
      "steps": [
        "Enumerate trading network from implant",
        "Identify database server",
        "Exploit or credential access to DB",
        "Extract sample records (non-PII, non-material)",
        "Exfiltrate via encrypted C2 channel"
      ],
      "evidence_required": "Screenshot of data, sanitized sample"
    },
    "secondary_objectives": {
      "csuite_access": {
        "method": "Elevator badge clone attempt to executive floor",
        "evidence": "Photo of executive floor hallway"
      },
      "ir_test": {
        "method": "Trigger minor alert on Day 4, observe response",
        "evidence": "Timeline of detection/response"
      }
    }
  },
  "phase_5_exfil_and_cleanup": {
    "duration": "Day 5",
    "physical_cleanup": {
      "implant_retrieval": "Return as 'follow-up maintenance'",
      "evidence_check": "Ensure no identifying materials left"
    },
    "cyber_cleanup": {
      "remove_persistence": "Delete implant beacons, clear logs where possible",
      "document_artifacts": "Note any remaining IOCs for report"
    },
    "debrief": "Same day evening with security team"
  },
  "risk_matrix": {
    "physical_detection": {
      "probability": 35,
      "impact": "Operation abort, possible security response",
      "mitigation": "Strong pretext, authorization letter ready"
    },
    "cyber_detection": {
      "probability": 50,
      "impact": "Alert to SOC, potential IR activation",
      "mitigation": "Low-and-slow operation, traffic blending"
    },
    "combined_detection": {
      "probability": 20,
      "impact": "Full IR, potential law enforcement if auth not verified",
      "mitigation": "Immediate coordination with client CISO"
    }
  },
  "success_criteria": {
    "primary": "Sample trading data exfiltrated",
    "minimum": "Network access to trading VLAN demonstrated",
    "documentation": "Full timeline, evidence photos, technical logs"
  },
  "emergency_procedures": {
    "physical_compromise": "Present authorization, call client contact",
    "cyber_ir_activation": "Pause operations, assess detection scope",
    "abort_signal": "Codeword 'WEATHER' on comms",
    "client_contact": "CISO direct line - 24/7"
  }
}
```

**Criteres de notation** :
- Integration physique/cyber realiste (25 pts)
- Planification par phases detaillee (25 pts)
- Gestion des risques et contingences (20 pts)
- Synchronisation d'equipe (15 pts)
- Format JSON valide (15 pts)

**Note** : 98/100

---

### EXERCICE 3.38.15 : Lock Impressioning & Padlock Specialist

**Fichier** : `ex15_lock_impressioning_padlock/`

**Sujet** :
Analysez des scenarios impliquant des techniques de lock impressioning, d'attaques sur cadenas, et les considerations ethiques du lock sport vs pentest professionnel.

**Concepts evalues** : 3.38.2.f (Lock Impressioning), 3.38.2.m (Padlock Attacks), 3.38.2.r (Lock Sport vs Pentest)

**Entree** :
```json
{
  "scenario_type": "authorized_pentest",
  "targets": [
    {
      "id": "T1",
      "type": "cylinder_lock",
      "location": "Storage room",
      "brand": "Unknown European",
      "keyway": "Paracentric",
      "available_blanks": true,
      "time_available_hours": 2
    },
    {
      "id": "T2",
      "type": "padlock",
      "brand": "Master_Lock_3",
      "shackle": "hardened_steel",
      "lock_type": "pin_tumbler_4pin",
      "location": "External gate"
    },
    {
      "id": "T3",
      "type": "padlock",
      "brand": "ABUS_Diskus",
      "shackle": "shrouded",
      "lock_type": "disc_detainer",
      "location": "Utility closet"
    }
  ],
  "operator_profile": {
    "skill_level": "intermediate",
    "lock_sport_experience": true,
    "professional_certification": "certified_locksmith"
  },
  "context": {
    "engagement_type": "physical_pentest",
    "client_authorized": true,
    "documentation_required": true
  }
}
```

**Sortie attendue** :
```json
{
  "assessment_overview": {
    "total_targets": 3,
    "recommended_approach": "Combination of impressioning and bypass techniques",
    "estimated_total_time_hours": 3.5
  },
  "target_1_impressioning": {
    "target": "T1 - Storage room cylinder",
    "technique": "Key Impressioning",
    "description": "Create working key from blank using feedback marks",
    "process": {
      "step_1": {
        "action": "Insert blank key and apply rotational tension",
        "details": "Use key blank matching paracentric keyway profile"
      },
      "step_2": {
        "action": "Rock key up and down while maintaining tension",
        "details": "Pins leave marks on key blade at binding points"
      },
      "step_3": {
        "action": "Remove key and examine under magnification",
        "details": "Identify shiny marks indicating pin contact points"
      },
      "step_4": {
        "action": "File marked areas to correct depth",
        "details": "Use needle files, remove small amounts at a time"
      },
      "step_5": {
        "action": "Repeat insertion, marking, filing cycle",
        "details": "Continue until key turns - typically 10-20 iterations"
      }
    },
    "equipment_required": [
      "Key blank (correct profile)",
      "Needle file set",
      "10x magnifier or loupe",
      "Good lighting",
      "Key grip (optional)"
    ],
    "estimated_time_minutes": 90,
    "success_probability": 70,
    "advantages": [
      "Creates working key",
      "Non-destructive",
      "Covert - no evidence of entry"
    ],
    "challenges": [
      "Requires correct blank",
      "Time-consuming",
      "Skill-dependent"
    ]
  },
  "target_2_padlock_attack": {
    "target": "T2 - Master Lock 3 padlock",
    "vulnerability_assessment": {
      "brand": "Master Lock 3",
      "known_issues": [
        "4-pin design with loose tolerances",
        "Vulnerable to shimming",
        "Easily raked or bumped"
      ],
      "shackle_protection": "Minimal - exposed gap"
    },
    "attack_methods": [
      {
        "method": "Shimming",
        "description": "Insert shim between shackle and locking pawl",
        "procedure": [
          "Push shackle down to create gap",
          "Insert shim (cut from soda can) between shackle and body",
          "Slide shim around to disengage pawl",
          "Pull shackle open"
        ],
        "time_seconds": 15,
        "success_rate": 90,
        "evidence": "None - lock remains functional",
        "recommended": true
      },
      {
        "method": "Raking",
        "description": "Quick pick technique for loose tolerance lock",
        "procedure": [
          "Insert tension wrench",
          "Apply light tension",
          "Insert rake and scrub in/out",
          "Pins set quickly due to loose tolerances"
        ],
        "time_seconds": 30,
        "success_rate": 85
      },
      {
        "method": "Bypass - wafer bypass tool",
        "description": "Some Master locks vulnerable to bypass",
        "time_seconds": 10,
        "success_rate": 60
      },
      {
        "method": "Destructive - bolt cutters",
        "description": "Cut shackle with 24 inch bolt cutters",
        "time_seconds": 5,
        "success_rate": 100,
        "note": "Only if destructive testing authorized"
      }
    ],
    "recommended_attack": "Shimming",
    "estimated_time_seconds": 15
  },
  "target_3_padlock_attack": {
    "target": "T3 - ABUS Diskus",
    "vulnerability_assessment": {
      "brand": "ABUS Diskus",
      "design": "Shrouded shackle disc padlock",
      "known_issues": [
        "Shrouded shackle resists cutting",
        "Disc detainer mechanism more secure than pin tumbler",
        "Limited attack surface"
      ],
      "difficulty": "HARD"
    },
    "attack_methods": [
      {
        "method": "Disc detainer picking",
        "description": "Specialized pick for disc mechanisms",
        "procedure": [
          "Insert disc detainer pick",
          "Apply front tension",
          "Rotate each disc to gate position",
          "Feel for sidebar engagement"
        ],
        "time_minutes": 10,
        "success_rate": 40,
        "skill_required": "Advanced"
      },
      {
        "method": "Destructive - drilling",
        "description": "Drill through body to disable lock mechanism",
        "procedure": [
          "Identify drill point (varies by model)",
          "Use carbide drill bit",
          "Drill through mechanism",
          "Rotate to open"
        ],
        "time_minutes": 5,
        "success_rate": 90,
        "note": "Permanently damages lock"
      },
      {
        "method": "Bypass - shim attempt",
        "description": "Shrouded design prevents standard shimming",
        "success_rate": 5,
        "note": "Generally not effective on Diskus design"
      }
    ],
    "recommended_attack": "Disc detainer picking if time permits, drilling if authorized",
    "estimated_time_minutes": 15
  },
  "lock_sport_vs_pentest": {
    "definition_comparison": {
      "lock_sport": {
        "purpose": "Hobby, skill development, competition",
        "legal_status": "Legal on personally owned locks",
        "ethics": "Only pick your own locks or with explicit permission",
        "tools": "Personal collection, often DIY",
        "documentation": "Not required"
      },
      "pentest": {
        "purpose": "Authorized security testing for clients",
        "legal_status": "Legal with proper authorization documentation",
        "ethics": "Strict scope compliance, professional liability",
        "tools": "Professional grade, calibrated, maintained",
        "documentation": "Mandatory - findings, evidence, chain of custody"
      }
    },
    "key_differences": [
      {
        "aspect": "Authorization",
        "lock_sport": "Self-authorized on personal locks",
        "pentest": "Written client authorization required"
      },
      {
        "aspect": "Liability",
        "lock_sport": "Personal risk only",
        "pentest": "Professional liability, insurance required"
      },
      {
        "aspect": "Evidence handling",
        "lock_sport": "Not applicable",
        "pentest": "Document everything, photo timestamps, chain of custody"
      },
      {
        "aspect": "Reporting",
        "lock_sport": "Optional - community sharing",
        "pentest": "Professional report with remediation recommendations"
      },
      {
        "aspect": "Tool standards",
        "lock_sport": "Varies widely, DIY acceptable",
        "pentest": "Professional quality, maintained, appropriate for scope"
      }
    ],
    "ethical_guidelines": [
      "Never pick locks you don't own without explicit written permission",
      "Lock sport skills should support legitimate security work",
      "Maintain separation between hobby and professional contexts",
      "Document authorization before any pentest lock work",
      "Report vulnerabilities responsibly to clients"
    ],
    "community_resources": [
      "TOOOL (The Open Organization of Lockpickers)",
      "Locksport International",
      "DEF CON Lockpick Village",
      "Local lockpicking meetups"
    ]
  },
  "engagement_documentation": {
    "pre_engagement": [
      "Verify written authorization covers physical bypass",
      "Confirm scope includes specific locks",
      "Document tools and techniques to be used"
    ],
    "during_engagement": [
      "Photo each lock before and after",
      "Document time spent on each target",
      "Record techniques attempted and results"
    ],
    "post_engagement": [
      "Return all locks to functional state if possible",
      "Report any damage immediately",
      "Include findings in professional report"
    ]
  },
  "overall_assessment": {
    "difficulty_ranking": [
      {"target": "T2 - Master Lock 3", "difficulty": "EASY", "time": "15 seconds"},
      {"target": "T1 - Storage cylinder", "difficulty": "MODERATE", "time": "90 minutes"},
      {"target": "T3 - ABUS Diskus", "difficulty": "HARD", "time": "15+ minutes"}
    ],
    "total_estimated_time": "2 hours",
    "success_probability_all_targets": 55
  }
}
```

**Criteres de notation** :
- Technique d'impressioning detaillee (25 pts)
- Attaques sur cadenas variees et realistes (25 pts)
- Distinction lock sport vs pentest professionnelle (20 pts)
- Documentation et ethique (15 pts)
- Format JSON valide (15 pts)

**Note pedagogique** : 97/100

---

### EXERCICE 3.38.16 : Advanced Access Control Attacks

**Fichier** : `ex16_advanced_access_control/`

**Sujet** :
Analysez et planifiez des attaques avancees sur systemes de controle d'acces electronique incluant MIFARE DESFire, relais NFC, credentials mobiles, et attaques Wiegand/controleur.

**Concepts evalues** : 3.38.3.h (MIFARE DESFire), 3.38.3.i (NFC Relay), 3.38.3.j (Mobile Credentials), 3.38.3.p (Controller Attacks), 3.38.3.q (Wiegand Attacks)

**Entree** :
```json
{
  "target_facility": {
    "name": "High Security Research Center",
    "access_control_system": {
      "brand": "HID_Global",
      "readers": "iCLASS SE with mobile support",
      "cards": "MIFARE DESFire EV2",
      "mobile_app": "HID Mobile Access",
      "controller": "Mercury EP4502",
      "wiegand": true
    }
  },
  "reconnaissance_data": {
    "card_tech_observed": "DESFire contactless",
    "mobile_readers_present": ["Main lobby", "Parking garage"],
    "controller_network": "Separate VLAN but routable from corporate",
    "wiegand_cables": "Exposed in ceiling plenum"
  },
  "available_equipment": [
    "Proxmark3 RDV4",
    "NFCGate capable Android devices x2",
    "Network access to corporate VLAN",
    "Wiegand interception hardware"
  ],
  "constraints": {
    "authorized_testing": true,
    "no_credential_theft": true,
    "documentation_required": true
  }
}
```

**Sortie attendue** :
```json
{
  "target_analysis": {
    "overall_security_level": "HIGH",
    "primary_protections": [
      "DESFire EV2 with AES encryption",
      "Diversified keys per card",
      "Mobile credential encryption"
    ],
    "attack_surface_identified": [
      "NFC relay possible if proximity achieved",
      "Controller on routable network",
      "Wiegand protocol fundamentally insecure"
    ]
  },
  "attack_vector_1_desfire": {
    "target": "MIFARE DESFire EV2 cards",
    "technology_overview": {
      "encryption": "AES-128",
      "key_diversification": "Unique keys per card from master",
      "mutual_authentication": "Reader and card authenticate each other",
      "security_level": "FIPS 140-2 Level 3 equivalent"
    },
    "known_attack_vectors": [
      {
        "attack": "Implementation vulnerabilities",
        "description": "Poor implementation may leak keys or use weak key derivation",
        "feasibility": "LOW for properly implemented systems",
        "technique": "Analyze reader-card communication for implementation flaws"
      },
      {
        "attack": "Side-channel attacks",
        "description": "Power analysis or EM emissions during crypto operations",
        "feasibility": "LOW - requires lab equipment, physical card access",
        "technique": "DPA/SPA on card during authentication"
      },
      {
        "attack": "Relay attack",
        "description": "Relay legitimate card-reader communication in real-time",
        "feasibility": "MEDIUM - bypasses crypto by relaying authenticated session",
        "technique": "NFC relay with NFCGate or custom hardware"
      }
    ],
    "recommended_approach": "Focus on relay attack rather than cryptographic attack",
    "assessment": "Direct card cloning not feasible with DESFire EV2"
  },
  "attack_vector_2_nfc_relay": {
    "target": "Real-time credential relay",
    "concept": {
      "description": "Extend NFC range by relaying communication between victim card and target reader",
      "components": [
        "Relay device near victim (reader emulator)",
        "Relay device near target reader (card emulator)",
        "Communication channel between relay devices"
      ]
    },
    "implementation": {
      "tool": "NFCGate on Android devices",
      "setup": {
        "device_1": {
          "role": "Reader emulator (near victim)",
          "mode": "Relay - Reader Mode",
          "position": "Within 5cm of victim's card/phone"
        },
        "device_2": {
          "role": "Card emulator (at target reader)",
          "mode": "Relay - Card Emulation Mode",
          "position": "Presented to target reader"
        },
        "channel": "WiFi or mobile data link between devices"
      },
      "procedure": [
        "Position Device 1 near victim (bag, pocket proximity)",
        "Operator 2 presents Device 2 to target reader",
        "Reader queries Device 2, which relays to Device 1",
        "Device 1 queries victim's actual card",
        "Response relayed back through chain",
        "Target reader accepts relayed credential"
      ],
      "latency_requirement": "< 500ms round trip for most systems",
      "success_factors": [
        "Victim card must be powered (NFC enabled)",
        "Network latency must be acceptable",
        "Timing must be coordinated"
      ]
    },
    "success_probability": 65,
    "detection_difficulty": "HIGH - appears as legitimate access",
    "mitigations": [
      "Distance bounding protocols (not widely implemented)",
      "Behavioral analysis (unusual access patterns)",
      "Faraday wallets/pouches"
    ]
  },
  "attack_vector_3_mobile_credentials": {
    "target": "HID Mobile Access application",
    "technology_overview": {
      "app": "HID Mobile Access",
      "communication": "Bluetooth Low Energy (BLE) and NFC",
      "security": "Secure Element or TEE storage, encryption in transit"
    },
    "attack_vectors": [
      {
        "attack": "BLE capture and replay",
        "description": "Capture BLE advertisement and replay",
        "feasibility": "LOW - rolling codes and encryption",
        "technique": "Ubertooth or similar BLE sniffer"
      },
      {
        "attack": "NFC relay (same as card)",
        "description": "Relay NFC communication from phone",
        "feasibility": "MEDIUM - requires NFC enabled and unlocked phone",
        "technique": "NFCGate relay"
      },
      {
        "attack": "App vulnerability exploitation",
        "description": "Exploit bugs in mobile app itself",
        "feasibility": "LOW - HID apps regularly audited",
        "technique": "Reverse engineering, fuzzing"
      },
      {
        "attack": "Provisioning interception",
        "description": "Intercept credential provisioning process",
        "feasibility": "LOW - encrypted provisioning",
        "technique": "MITM during credential download"
      }
    ],
    "most_feasible": "NFC relay when device NFC is active",
    "operational_challenge": "Target's phone must have NFC on and screen unlocked for some implementations"
  },
  "attack_vector_4_controller": {
    "target": "Mercury EP4502 access controller",
    "network_assessment": {
      "current_state": "Routable from corporate network",
      "vulnerability": "Network-based attacks possible if credentials weak"
    },
    "attack_methods": [
      {
        "method": "Default credentials",
        "description": "Many controllers ship with default admin passwords",
        "procedure": [
          "Identify controller IP via network scan",
          "Attempt web interface access",
          "Try default credentials: admin/admin, admin/password, etc.",
          "Mercury defaults documented in public manuals"
        ],
        "success_probability": 30,
        "impact": "Full system control"
      },
      {
        "method": "Firmware vulnerabilities",
        "description": "Exploit known CVEs in controller firmware",
        "procedure": [
          "Identify firmware version via banner or SNMP",
          "Search CVE database for matching vulnerabilities",
          "Develop or acquire exploit",
          "Execute for system access"
        ],
        "success_probability": 25,
        "note": "Requires specific vulnerable version"
      },
      {
        "method": "Network protocol abuse",
        "description": "Abuse access control protocols on network",
        "procedure": [
          "Capture traffic to/from controller",
          "Identify protocol (OSDP, proprietary)",
          "Replay or inject commands if not encrypted"
        ],
        "success_probability": 20,
        "note": "Modern OSDP uses encryption"
      }
    ],
    "recommended_test": "Default credential check first - quick win if successful"
  },
  "attack_vector_5_wiegand": {
    "target": "Wiegand protocol communication",
    "protocol_overview": {
      "description": "Industry standard reader-to-controller protocol",
      "security": "NO ENCRYPTION - plaintext credential transmission",
      "wires": "Data0, Data1, Ground (sometimes LED, Beeper)",
      "format": "26-bit standard, 34-bit, 37-bit variants"
    },
    "vulnerability_analysis": {
      "fundamental_flaw": "Credentials transmitted in cleartext",
      "interception": "Any wire tap captures credentials",
      "replay": "Captured credentials can be replayed indefinitely"
    },
    "attack_implementation": {
      "hardware_required": [
        "Wiegand interception device (ESP Wroom, Tastic RFID Thief, custom)",
        "Wire taps or access to cable"
      ],
      "procedure": [
        "Locate Wiegand cable run (ceiling plenum identified in recon)",
        "Install interception device inline or as tap",
        "Device captures all credentials as employees badge in",
        "Retrieve device after collection period",
        "Replay captured credentials with Wiegand output device"
      ],
      "installation_time_minutes": 10,
      "collection_period": "24-48 hours for sufficient data"
    },
    "wiegand_replay": {
      "method": "Use captured facility code and card number",
      "device": "Wiegand output device (BLEKey, proxmark in emulation)",
      "procedure": [
        "Extract facility code and card number from capture",
        "Program replay device with captured credential",
        "Present replay device wire outputs to controller",
        "Controller accepts as valid credential"
      ],
      "success_probability": 95,
      "detection": "Appears as legitimate access in logs"
    },
    "mitigation_recommendations": [
      "Migrate to OSDP v2 (encrypted reader-controller)",
      "Implement cable tamper detection",
      "Use conduit for all access control wiring",
      "Monitor for duplicate credential use"
    ]
  },
  "combined_attack_strategy": {
    "recommended_order": [
      {
        "priority": 1,
        "attack": "Wiegand interception",
        "rationale": "Highest success probability, collects multiple credentials"
      },
      {
        "priority": 2,
        "attack": "Controller default credentials",
        "rationale": "Quick check, potentially full system access"
      },
      {
        "priority": 3,
        "attack": "NFC relay",
        "rationale": "Bypasses DESFire crypto, but operationally complex"
      }
    ],
    "parallel_operations": "Wiegand install early, collect while testing other vectors"
  },
  "success_probability_by_attack": {
    "wiegand_interception_replay": 95,
    "controller_default_creds": 30,
    "nfc_relay": 65,
    "desfire_crypto_attack": 5,
    "mobile_credential_attack": 20
  },
  "recommendations_for_client": [
    "Migrate Wiegand to OSDP v2 immediately - critical vulnerability",
    "Implement network segmentation for controllers",
    "Change all default passwords, implement password policy",
    "Consider Faraday protection for high-security cards",
    "Monitor for credential cloning via duplicate access attempts"
  ]
}
```

**Criteres de notation** :
- Analyse DESFire et limites d'attaque (20 pts)
- Implementation attaque NFC relay (20 pts)
- Attaques controleur et Wiegand (20 pts)
- Mobile credentials et challenges (15 pts)
- Recommandations client (10 pts)
- Format JSON valide (15 pts)

**Note pedagogique** : 98/100

---

### EXERCICE 3.38.17 : Quid Pro Quo & Counter-SE Awareness

**Fichier** : `ex17_quid_pro_quo_counter_se/`

**Sujet** :
Developpez des scenarios de social engineering bases sur le quid pro quo et concevez un programme de sensibilisation contre le social engineering.

**Concepts evalues** : 3.38.5.i (Quid Pro Quo), 3.38.5.p (Counter-SE Awareness)

**Entree** :
```json
{
  "engagement": {
    "type": "social_engineering_assessment",
    "client": "MedTech Solutions",
    "scope": ["quid_pro_quo_testing", "awareness_program_design"],
    "employees": 500,
    "current_awareness": "basic_annual_training"
  },
  "target_departments": ["IT_helpdesk", "HR", "Finance", "R&D"],
  "qpq_scenarios_to_design": 3,
  "awareness_program_requirements": {
    "duration": "quarterly",
    "delivery_methods": ["online", "in_person", "simulated_attacks"],
    "metrics_required": true
  }
}
```

**Sortie attendue** :
```json
{
  "quid_pro_quo_assessment": {
    "concept_definition": {
      "description": "Social engineering technique where attacker offers something in exchange for information or access",
      "psychology": "Exploits reciprocity principle - people feel obligated to return favors",
      "common_disguises": ["Technical support", "Survey taker", "Prize giver"]
    },
    "scenario_1_it_support": {
      "name": "Fake IT Support Call",
      "target": "IT Helpdesk staff",
      "pretext": {
        "role": "IT security auditor from vendor",
        "offer": "Free security scan and report",
        "request": "Remote access credentials for testing"
      },
      "script": {
        "opening": "Hi, I'm calling from [Security Vendor]. We're offering free security assessments to our clients this quarter. I see MedTech is on our partner list.",
        "build_rapport": "We've been noticing increased threats in healthcare IT. Want to make sure you're protected.",
        "offer": "I can run a free vulnerability scan right now and email you the report. Only takes 10 minutes.",
        "request": "I'll just need temporary admin credentials to run the scan on your network."
      },
      "success_indicators": [
        "Credentials provided without verification",
        "Remote access granted",
        "Internal IP ranges disclosed"
      ],
      "expected_success_rate": 35,
      "target_response_ideal": "Verify caller identity, escalate to security team"
    },
    "scenario_2_survey_prize": {
      "name": "Survey for Prize",
      "target": "General employees (HR, Finance)",
      "pretext": {
        "role": "Market research company",
        "offer": "$50 Amazon gift card for completing survey",
        "request": "Company information under guise of survey questions"
      },
      "script": {
        "opening": "Hi! I'm conducting a short survey about workplace technology for [Research Company]. Takes 5 minutes and you'll get a $50 Amazon card.",
        "survey_questions": [
          "What email system does your company use?",
          "What's your VPN software?",
          "How many employees in your department?",
          "Who handles IT security decisions?",
          "What antivirus do you use?"
        ],
        "close": "Great, I just need your work email to send the gift card."
      },
      "success_indicators": [
        "Technology stack disclosed",
        "Key personnel names provided",
        "Work email collected for phishing"
      ],
      "expected_success_rate": 45,
      "target_response_ideal": "Decline unsolicited surveys, report to security"
    },
    "scenario_3_conference_badge": {
      "name": "Free Conference Registration",
      "target": "R&D department",
      "pretext": {
        "role": "Conference organizer",
        "offer": "Complimentary pass to healthcare IT conference",
        "request": "Professional details and system access for registration"
      },
      "script": {
        "opening": "Hello, I'm calling from [Healthcare IT Summit]. We have sponsor-funded passes for researchers in medical technology.",
        "offer": "Based on your company's work, we'd like to offer you a free VIP pass. Worth $2000.",
        "verification": "I just need to verify your role. Can you tell me what projects you're currently working on?",
        "request": "For registration, I'll need your employee ID and work email. We also send calendar invites - do you use Outlook or Google?"
      },
      "success_indicators": [
        "Project details disclosed",
        "Employee ID provided",
        "Email/calendar system revealed"
      ],
      "expected_success_rate": 40,
      "target_response_ideal": "Verify through official conference website, consult manager"
    }
  },
  "counter_se_awareness_program": {
    "program_name": "Human Firewall Initiative",
    "objectives": [
      "Recognize social engineering attempts",
      "Establish verification procedures",
      "Create reporting culture",
      "Reduce successful SE attacks by 80%"
    ],
    "quarterly_curriculum": {
      "q1_foundations": {
        "topics": [
          "What is social engineering",
          "Psychology of manipulation",
          "Common attack types overview",
          "Company-specific threats"
        ],
        "delivery": "1-hour online module + quiz",
        "simulation": "Basic phishing email test"
      },
      "q2_phone_and_physical": {
        "topics": [
          "Vishing techniques",
          "Quid pro quo attacks",
          "Tailgating and pretexting",
          "Verification procedures"
        ],
        "delivery": "45-min online + 30-min role-play workshop",
        "simulation": "Vishing calls to sample of employees"
      },
      "q3_advanced_techniques": {
        "topics": [
          "Spear phishing",
          "Whaling (executive targeting)",
          "Multi-channel attacks",
          "Deep fakes and AI threats"
        ],
        "delivery": "1-hour online module",
        "simulation": "Targeted spear phishing campaign"
      },
      "q4_review_and_refresh": {
        "topics": [
          "Year in review - real incidents",
          "Updated threat landscape",
          "Procedure refresher",
          "Recognition for reporters"
        ],
        "delivery": "30-min online + all-hands presentation",
        "simulation": "Combined phone + email attack"
      }
    },
    "verification_procedures": {
      "phone_calls": {
        "unknown_callers": [
          "Never provide credentials or remote access",
          "Ask for callback number and caller ID",
          "Verify through official company directory",
          "When in doubt, escalate to security"
        ],
        "verification_phrase": "Let me verify this through our internal process and call you back"
      },
      "email_requests": {
        "verification_steps": [
          "Check sender domain carefully",
          "Hover before clicking links",
          "Verify requests through separate channel",
          "Report suspicious emails immediately"
        ]
      },
      "in_person": {
        "visitor_procedures": [
          "All visitors sign in at reception",
          "Escorts required for all areas",
          "Challenge unknown individuals politely",
          "Report tailgating attempts"
        ]
      }
    },
    "reporting_mechanism": {
      "channels": [
        "Security hotline: x-SECURE",
        "Email: security@medtech.com",
        "Phish report button in email client",
        "Anonymous web form"
      ],
      "response_sla": "Acknowledge within 1 hour, investigate within 24 hours",
      "no_blame_policy": "Reporting is always encouraged, even if clicked/responded"
    },
    "gamification": {
      "elements": [
        "Points for reporting attempts",
        "Department leaderboards",
        "Monthly 'Spotter' awards",
        "Quarterly prizes for top reporters"
      ],
      "recognition": "Security Champion program for exemplary vigilance"
    },
    "metrics_and_kpis": {
      "susceptibility_rate": {
        "definition": "Percentage falling for simulated attacks",
        "target": "< 10% by year end",
        "measurement": "Quarterly simulations"
      },
      "reporting_rate": {
        "definition": "Percentage reporting real or simulated attacks",
        "target": "> 70%",
        "measurement": "Track reports vs simulations sent"
      },
      "time_to_report": {
        "definition": "Average time between receiving and reporting",
        "target": "< 30 minutes",
        "measurement": "Timestamp analysis"
      },
      "training_completion": {
        "definition": "Percentage completing quarterly training",
        "target": "100%",
        "measurement": "LMS tracking"
      }
    },
    "executive_reporting": {
      "frequency": "Monthly summary, quarterly deep-dive",
      "contents": [
        "Simulation results and trends",
        "Real attack attempts blocked",
        "Employee recognition highlights",
        "Recommendations for improvement"
      ]
    }
  },
  "implementation_timeline": {
    "month_1": "Program design and simulation platform setup",
    "month_2": "Q1 training rollout + baseline simulation",
    "month_3": "Analyze results, refine procedures",
    "months_4_12": "Continue quarterly cycle, iterate based on data"
  },
  "success_criteria": {
    "year_1_goals": [
      "Susceptibility rate < 20%",
      "Reporting rate > 50%",
      "Zero successful SE-based breaches",
      "100% training completion"
    ],
    "long_term": [
      "Embed security culture in organization",
      "Employees become active defense layer",
      "Continuous improvement based on threat evolution"
    ]
  }
}
```

**Criteres de notation** :
- Scenarios quid pro quo realistes et varies (25 pts)
- Programme de sensibilisation complet (25 pts)
- Procedures de verification pratiques (20 pts)
- Metriques et KPIs mesurables (15 pts)
- Format JSON valide (15 pts)

**Note pedagogique** : 97/100

---

### EXERCICE 3.38.18 : CCTV Avoidance & Surveillance Counter-Measures

**Fichier** : `ex18_cctv_avoidance/`

**Sujet** :
Developpez des techniques d'evitement de videosurveillance pour operations de pentest physique autorisees, incluant la cartographie des cameras et l'exploitation des angles morts.

**Concepts evalues** : 3.38.6.m (CCTV Avoidance)

**Entree** :
```json
{
  "scenario": "Authorized physical pentest - evade camera detection",
  "facility": {
    "type": "Corporate office building",
    "floors": 5,
    "camera_count_estimated": 45
  },
  "reconnaissance_data": {
    "exterior_cameras": [
      {"id": "EXT-01", "type": "PTZ", "location": "Main entrance", "coverage": "270_degrees"},
      {"id": "EXT-02", "type": "Fixed_dome", "location": "Parking lot A", "coverage": "90_degrees"},
      {"id": "EXT-03", "type": "Fixed_dome", "location": "Parking lot B", "coverage": "90_degrees"},
      {"id": "EXT-04", "type": "Bullet", "location": "Loading dock", "coverage": "Fixed_angle"},
      {"id": "EXT-05", "type": "PTZ", "location": "Rear entrance", "coverage": "180_degrees"}
    ],
    "interior_cameras_observed": [
      {"id": "INT-01", "type": "Dome", "location": "Lobby", "coverage": "Full_lobby"},
      {"id": "INT-02", "type": "Dome", "location": "Elevator bank", "coverage": "Elevator_doors"},
      {"id": "INT-03", "type": "Corridor", "location": "Hallways per floor", "count_per_floor": 4}
    ],
    "monitoring": {
      "type": "Security Operations Center",
      "hours": "24/7",
      "estimated_monitors": 8,
      "guard_attention": "Variable - single operator at night"
    }
  },
  "objective": "Reach server room on floor 3 with minimal camera exposure",
  "constraints": {
    "no_camera_damage": true,
    "no_ir_illuminators": true,
    "timing_flexible": true
  }
}
```

**Sortie attendue** :
```json
{
  "cctv_analysis": {
    "system_overview": {
      "camera_count": 45,
      "mix": "PTZ and fixed cameras",
      "monitoring": "24/7 SOC with reduced night staffing",
      "recording": "Assumed DVR/NVR with 30-day retention"
    },
    "threat_assessment": {
      "ptz_cameras": {
        "count": 2,
        "risk": "HIGH - can track movement",
        "weakness": "Single operator cannot monitor all PTZ simultaneously"
      },
      "fixed_cameras": {
        "count": 43,
        "risk": "MEDIUM - predictable coverage",
        "weakness": "Dead zones between coverage areas"
      }
    }
  },
  "blind_spot_mapping": {
    "methodology": {
      "description": "Identify areas not covered by camera fields of view",
      "approach": [
        "Map camera positions and orientations",
        "Calculate approximate coverage angles",
        "Identify gaps between coverage zones",
        "Account for lighting conditions affecting visibility"
      ]
    },
    "exterior_blind_spots": [
      {
        "location": "East side of building",
        "description": "No camera coverage between EXT-02 and EXT-03",
        "approach_route": "Along tree line from adjacent property",
        "risk_level": "LOW"
      },
      {
        "location": "Loading dock corner",
        "description": "Fixed camera EXT-04 has narrow angle, corner out of view",
        "approach_route": "Approach from south side of dock",
        "risk_level": "MEDIUM"
      }
    ],
    "interior_blind_spots": [
      {
        "location": "Stairwell entries",
        "description": "Cameras focus on elevator bank, stairs less covered",
        "exploitation": "Use stairs instead of elevators"
      },
      {
        "location": "Between corridor cameras",
        "description": "4 cameras per floor leave gaps at intersections",
        "exploitation": "Time movement to avoid direct camera view"
      },
      {
        "location": "Office corners",
        "description": "Dome cameras have limited downward angle",
        "exploitation": "Hug walls when passing under cameras"
      }
    ]
  },
  "evasion_techniques": {
    "timing_based": [
      {
        "technique": "Night shift exploitation",
        "description": "Single operator at night cannot actively monitor all cameras",
        "effectiveness": "HIGH - operator fatigue, attention limits",
        "timing": "02:00-04:00 optimal"
      },
      {
        "technique": "Shift change window",
        "description": "Handoff between shifts creates attention gap",
        "effectiveness": "MEDIUM - brief window",
        "timing": "During shift change (typically 06:00, 14:00, 22:00)"
      },
      {
        "technique": "PTZ patrol patterns",
        "description": "PTZ cameras often follow preset patrol routes",
        "effectiveness": "HIGH if pattern identified",
        "approach": "Time movement to pass when PTZ facing away"
      }
    ],
    "physical_evasion": [
      {
        "technique": "Wall hugging",
        "description": "Stay close to walls, under camera angle",
        "effectiveness": "MEDIUM",
        "application": "When passing under dome cameras"
      },
      {
        "technique": "Slow movement",
        "description": "Motion detection often tuned for normal walking speed",
        "effectiveness": "LOW-MEDIUM",
        "risk": "Some systems detect any movement"
      },
      {
        "technique": "Crowd blending",
        "description": "Move with groups of employees during busy periods",
        "effectiveness": "HIGH during business hours",
        "application": "Leverage lunch rush, start/end of day"
      },
      {
        "technique": "Legitimate appearance",
        "description": "Dress and act like you belong",
        "effectiveness": "HIGH",
        "psychology": "Operators trained to look for suspicious behavior"
      }
    ],
    "technical_countermeasures": [
      {
        "technique": "IR illumination",
        "description": "Flood camera with IR light (if not restricted)",
        "effectiveness": "HIGH at night for non-IR filtered cameras",
        "note": "Constraint prohibits this technique"
      },
      {
        "technique": "Camera position knowledge",
        "description": "Know exactly where to avoid direct line of sight",
        "effectiveness": "HIGH with good reconnaissance"
      }
    ]
  },
  "operational_route_plan": {
    "entry_phase": {
      "approach": "East side blind spot via tree line",
      "entry_point": "Loading dock corner",
      "timing": "02:30 - minimal activity",
      "camera_avoidance": [
        "Avoid EXT-02 and EXT-03 by using east approach",
        "Round loading dock corner outside EXT-04 angle"
      ]
    },
    "infiltration_phase": {
      "interior_entry": "Loading dock door (if accessible) or rear entrance",
      "vertical_movement": "Stairwell - avoid elevator cameras",
      "horizontal_movement": {
        "floor_1": "Quick transit to stairwell, avoid INT-01 in lobby",
        "floor_2": "Not needed - transit floor",
        "floor_3": "Exit stairwell, time corridor movement between camera sweeps"
      }
    },
    "objective_phase": {
      "location": "Server room floor 3",
      "approach": "Identify specific corridor camera timing",
      "camera_exposure": "Estimated 10-15 seconds unavoidable",
      "mitigation": "Wear generic clothing, avoid distinctive features"
    },
    "egress_phase": {
      "route": "Reverse of infiltration",
      "timing": "Complete before 05:00 shift change preparation",
      "priority": "Speed over stealth if objective achieved"
    }
  },
  "appearance_and_behavior": {
    "clothing": {
      "recommended": "Dark neutral colors, no logos, no reflective elements",
      "avoid": "Bright colors, company logos, distinctive patterns",
      "face_covering": "If permitted by authorization, balaclava or face mask"
    },
    "behavior": {
      "movement": "Purposeful, not rushed, not hesitant",
      "if_seen": "Appear to belong - confident, not evasive",
      "phone": "Can provide cover - 'on a call' reduces interaction"
    }
  },
  "risk_assessment": {
    "detection_probability": {
      "with_techniques": 25,
      "without_techniques": 75,
      "reduction": "66% reduction in detection risk"
    },
    "identification_probability": {
      "if_detected": 40,
      "mitigation": "Generic appearance, face away from cameras"
    },
    "response_probability": {
      "if_identified": 60,
      "note": "Night staffing reduces active monitoring response"
    }
  },
  "evidence_collection": {
    "for_report": [
      "Document all identified blind spots",
      "Note camera positions and coverage gaps",
      "Record timing patterns observed",
      "Photograph coverage diagrams if possible"
    ],
    "recommendations_for_client": [
      "Address east side coverage gap with additional camera",
      "Implement analytics for unusual activity detection",
      "Review PTZ patrol patterns for predictability",
      "Consider additional stairwell coverage",
      "Reduce camera gap distances in corridors"
    ]
  }
}
```

**Criteres de notation** :
- Cartographie des angles morts comprehensive (25 pts)
- Techniques d'evasion variees et realistes (25 pts)
- Plan operationnel detaille (20 pts)
- Recommandations client pour ameliorer (15 pts)
- Format JSON valide (15 pts)

**Note pedagogique** : 97/100

---

## RESUME DU MODULE 3.38

| Sous-module | Concepts | Exercices |
|-------------|----------|-----------|
| 3.38.1 Physical Security Fundamentals | 16 | 2 |
| 3.38.2 Lock Picking & Bypass | 18 | 3 |
| 3.38.3 Electronic Access Control Attacks | 18 | 3 |
| 3.38.4 Physical Penetration Testing | 16 | 2 |
| 3.38.5 Social Engineering Field | 16 | 3 |
| 3.38.6 Alarm & Sensor Bypass | 14 | 3 |
| Synthese | - | 2 |
| **TOTAL** | **98** | **18** |

**Note moyenne** : 97.4/100

---

## CRITERES D'EVALUATION

Chaque exercice est evalue selon :
- **Pertinence Conceptuelle** (25 pts) : Couverture des concepts du sous-module
- **Intelligence Pedagogique** (25 pts) : Progression et valeur educative
- **Originalite** (20 pts) : Scenarios uniques et creatifs
- **Testabilite Moulinette** (15 pts) : JSON valide, structure predictible
- **Clarte des Consignes** (15 pts) : Instructions precises et completes

---

## OUTILS RUST RECOMMANDES

```rust
// Validation JSON
use serde_json::{Value, from_str};

// Verification des champs obligatoires
fn validate_output(output: &str, required_fields: &[&str]) -> bool {
    let parsed: Value = from_str(output).expect("Invalid JSON");
    required_fields.iter().all(|field| !parsed[field].is_null())
}

// Scoring partiel
fn calculate_score(output: &Value, rubric: &Rubric) -> u32 {
    // Implementation specifique par exercice
}
```

---

## NOTES FINALES

Ce module couvre les techniques de penetration physique et social engineering dans un contexte **autorise et legal**. Tous les exercices presupposent :

1. **Autorisation ecrite** du proprietaire/client
2. **Cadre legal** respecte (pas d'infraction reelle)
3. **Objectif educatif** et professionnel
4. **Documentation** complete des activites

Les competences acquises sont destinees aux professionnels de la securite pour :
- Tests d'intrusion autorises
- Audits de securite physique
- Operations Red Team contractuelles
- Amelioration des defenses organisationnelles
