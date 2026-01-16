# PLAN DES EXERCICES - MODULE 3.1 : Fondamentaux Cryptographiques

## Vue d'ensemble

**Module**: 3.1 - Fondamentaux Cryptographiques
**Sous-modules**: 8 (3.1.1 a 3.1.8)
**Concepts totaux**: 99
**Exercices concus**: 18
**Strategie**: Exercices integratifs couvrant plusieurs concepts pour une comprehension profonde

---

## SYNTHESE DE COUVERTURE

| Sous-module | Concepts | Exercices | Couverture |
|-------------|----------|-----------|------------|
| 3.1.1 Principes de securite | 15 (a-o) | Ex01, Ex02 | 100% |
| 3.1.2 Mathematiques crypto | 12 (a-l) | Ex03, Ex04, Ex05 | 100% |
| 3.1.3 Chiffrement symetrique | 15 (a-o) | Ex06, Ex07, Ex08 | 100% |
| 3.1.4 Chiffrement asymetrique | 16 (a-p) | Ex09, Ex10, Ex11 | 100% |
| 3.1.5 Hachage et MAC | 14 (a-n) | Ex12, Ex13 | 100% |
| 3.1.6 PKI et certificats | 11 (a-k) | Ex14, Ex15 | 100% |
| 3.1.7 Protocoles crypto | 10 (a-j) | Ex16, Ex17 | 100% |
| 3.1.8 Aleatoire et entropie | 6 (a-f) | Ex18 | 100% |

---

## EXERCICES DETAILLES

---

### EXERCICE 01 : "L'Auditeur de Forteresse"
#### Analyse et conception de securite multi-couches

**ID**: `3.1.1_ex01`

**Objectif Pedagogique**:
L'etudiant doit analyser une infrastructure fictive et concevoir un rapport d'audit complet identifiant les violations des principes fondamentaux, proposant des controles de securite, et evaluant les risques selon les frameworks standards.

**Concepts Couverts**:
- 3.1.1.a : Triade CIA (Confidentialite, Integrite, Disponibilite)
- 3.1.1.b : AAA (Authentication, Authorization, Accounting)
- 3.1.1.c : Non-repudiation
- 3.1.1.d : Defense in Depth
- 3.1.1.e : Least Privilege
- 3.1.1.f : Separation of Duties
- 3.1.1.g : Zero Trust
- 3.1.1.h : Attack Surface

**Scenario**:
La startup "CryptoBank SA" vous engage comme auditeur. Vous recevez un fichier JSON decrivant leur infrastructure: serveurs, applications, flux de donnees, comptes utilisateurs, politiques actuelles. Votre mission: identifier toutes les violations des principes de securite et proposer des remediation concretes.

**Format d'Entree**:
```json
{
  "infrastructure": {
    "servers": [...],
    "applications": [...],
    "data_flows": [...],
    "users": [...],
    "policies": {...}
  }
}
```

**Format de Sortie**:
```json
{
  "audit_report": {
    "violations": [
      {
        "principle": "least_privilege",
        "location": "user:admin_bob",
        "severity": "critical",
        "description": "...",
        "remediation": "..."
      }
    ],
    "risk_score": 0-100,
    "priority_actions": [...]
  }
}
```

**Pieges Pedagogiques**:
- Faux positifs intentionnels (configurations qui semblent vulnerables mais respectent un autre principe)
- Conflits entre principes (ex: disponibilite vs confidentialite)
- Violations subtiles noyees dans des configurations correctes

**Criteres de Test**:
1. Detection des 12 violations plantees (10 points chacune)
2. Absence de faux positifs (penalite -5 par faux positif)
3. Coherence du score de risque (15 points)
4. Pertinence des remediations (15 points)

**Auto-evaluation**: 96/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 24 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Force la comprehension profonde des 8 principes en contexte realiste
- Pieges intelligents revelant les confusions communes
- Scenario engageant (audit de startup fintech)
- Sortie JSON parfaitement testable
- Retire 1 point originalite (audits existent) et 1 point clarte (complexite inherente)

---

### EXERCICE 02 : "Le Stratege du Risque"
#### Modelisation des menaces et evaluation des risques

**ID**: `3.1.1_ex02`

**Objectif Pedagogique**:
Maitriser les methodologies de modelisation des menaces (STRIDE, DREAD) et d'evaluation des risques en produisant une analyse complete d'un systeme avec metriques de securite.

**Concepts Couverts**:
- 3.1.1.i : Threat Modeling (STRIDE, DREAD, Attack Trees)
- 3.1.1.j : Risk Assessment (CVSS, matrice de risque, FAIR)
- 3.1.1.k : Security Controls (preventifs, detectifs, correctifs)
- 3.1.1.l : Security Policies
- 3.1.1.m : Security Frameworks (NIST CSF, ISO 27001, CIS)
- 3.1.1.n : Compliance (GDPR, PCI-DSS)
- 3.1.1.o : Security Metrics (MTTD, MTTR)

**Scenario**:
Un systeme de vote electronique est decrit avec ses composants, flux et acteurs. Produire une analyse STRIDE complete, calculer les scores DREAD, proposer des controles, et verifier la conformite reglementaire.

**Format d'Entree**:
```json
{
  "system": {
    "name": "E-Vote 2024",
    "components": [...],
    "data_flows": [...],
    "trust_boundaries": [...],
    "actors": [...],
    "regulations": ["GDPR", "local_election_law"]
  }
}
```

**Format de Sortie**:
```json
{
  "threat_model": {
    "stride_analysis": {
      "spoofing": [...],
      "tampering": [...],
      "repudiation": [...],
      "information_disclosure": [...],
      "denial_of_service": [...],
      "elevation_of_privilege": [...]
    },
    "dread_scores": [...],
    "attack_trees": [...],
    "controls": {
      "preventive": [...],
      "detective": [...],
      "corrective": [...]
    },
    "compliance_gaps": [...],
    "metrics_baseline": {
      "target_mttd_hours": ...,
      "target_mttr_hours": ...
    }
  }
}
```

**Pieges Pedagogiques**:
- Menaces qui affectent plusieurs categories STRIDE
- Scores DREAD necessitant une analyse contextuelle
- Compliance croisee (GDPR + loi electorale avec conflits)

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Couvre 7 concepts complementaires de maniere integree
- Scenario vote electronique hautement pertinent et engageant
- Force la reflexion sur les interactions entre concepts
- Sortie structuree JSON parfaitement testable

---

### EXERCICE 03 : "Les Cles du Royaume"
#### Implementation de l'arithmetique modulaire pour la cryptographie

**ID**: `3.1.2_ex03`

**Objectif Pedagogique**:
Implementer from scratch les operations mathematiques fondamentales de la cryptographie: arithmetique modulaire, PGCD, inverse modulaire, et exponentiation rapide.

**Concepts Couverts**:
- 3.1.2.a : Arithmetique modulaire (operations, classes de congruence)
- 3.1.2.b : PGCD et Bezout (Euclide etendu)
- 3.1.2.c : Inverse modulaire (calcul via Euclide etendu)
- 3.1.2.d : Theoreme de Fermat (petit theoreme)
- 3.1.2.e : Theoreme d'Euler (fonction indicatrice phi)
- 3.1.2.f : Exponentiation modulaire (square-and-multiply)

**Scenario**:
Vous developpez une bibliotheque cryptographique legere pour systemes embarques. Implementez les primitives mathematiques sans utiliser de bibliotheque externe de grands entiers.

**Format d'Entree**:
```json
{
  "operations": [
    {"type": "mod_add", "a": "123456789", "b": "987654321", "n": "1000000007"},
    {"type": "mod_mul", "a": "...", "b": "...", "n": "..."},
    {"type": "gcd_extended", "a": "...", "b": "..."},
    {"type": "mod_inverse", "a": "...", "n": "..."},
    {"type": "mod_exp", "base": "...", "exp": "...", "mod": "..."},
    {"type": "euler_phi", "n": "..."}
  ]
}
```

**Format de Sortie**:
```json
{
  "results": [
    {"operation": 0, "result": "...", "method": "standard"},
    {"operation": 2, "result": {"gcd": "...", "x": "...", "y": "..."}, "method": "extended_euclid"},
    {"operation": 4, "result": "...", "method": "square_and_multiply", "steps": 17}
  ]
}
```

**Contraintes**:
- Implementation en Rust avec uniquement la bibliotheque standard
- Support des grands nombres via String (representation decimale)
- Complexite O(log n) pour l'exponentiation
- Doit gerer les cas ou l'inverse n'existe pas

**Pieges Pedagogiques**:
- Debordement d'entiers (multiplication avant modulo)
- Inverse inexistant (pgcd != 1)
- Exposant 0 (resultat toujours 1)
- Modulo 1 (resultat toujours 0)

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Implementation from scratch force la comprehension profonde
- Les 6 concepts sont intimement lies et bien couverts
- Contexte systeme embarque realiste
- Tests deterministes avec grands nombres

---

### EXERCICE 04 : "Le Theoreme Secret"
#### Application du theoreme des restes chinois et generation de nombres premiers

**ID**: `3.1.2_ex04`

**Objectif Pedagogique**:
Maitriser le CRT pour l'acceleration cryptographique et comprendre la generation/test de nombres premiers avec Miller-Rabin.

**Concepts Couverts**:
- 3.1.2.g : Theoreme des restes chinois (CRT)
- 3.1.2.h : Nombres premiers (Miller-Rabin, generation, distribution)

**Scenario**:
Un systeme de partage de secret utilise le CRT. Vous devez reconstruire des secrets a partir de shares et generer des nombres premiers surs pour le systeme.

**Format d'Entree**:
```json
{
  "crt_problems": [
    {
      "congruences": [
        {"remainder": 2, "modulus": 3},
        {"remainder": 3, "modulus": 5},
        {"remainder": 2, "modulus": 7}
      ]
    }
  ],
  "primality_tests": [
    {"number": "104729", "rounds": 20}
  ],
  "prime_generation": [
    {"bits": 64, "safe_prime": true}
  ]
}
```

**Format de Sortie**:
```json
{
  "crt_solutions": [{"problem": 0, "x": 23, "modulus": 105}],
  "primality_results": [{"number": "104729", "is_prime": true, "confidence": 0.9999999999}],
  "generated_primes": [{"bits": 64, "prime": "...", "is_safe": true, "sophie_germain": "..."}]
}
```

**Pieges Pedagogiques**:
- Modules non coprimes (pas de solution CRT)
- Nombres de Carmichael (echappent aux tests simples de Fermat)
- Safe primes: (p-1)/2 doit aussi etre premier

**Auto-evaluation**: 96/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 24 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Application directe a des problemes crypto reels (RSA-CRT)
- Test de Miller-Rabin bien plus interessant que Fermat simple
- Generation de safe primes = concept avance bien integre

---

### EXERCICE 05 : "Les Structures Algebriques"
#### Groupes cycliques, corps finis et introduction aux courbes elliptiques

**ID**: `3.1.2_ex05`

**Objectif Pedagogique**:
Comprendre les structures algebriques sous-jacentes a la cryptographie moderne: groupes cycliques, corps finis GF(p) et GF(2^n), et operations sur courbes elliptiques.

**Concepts Couverts**:
- 3.1.2.i : Groupes cycliques (generateurs, ordre, logarithme discret)
- 3.1.2.j : Corps finis (GF(p), GF(2^n))
- 3.1.2.k : Courbes elliptiques (equation Weierstrass, addition de points)
- 3.1.2.l : Attaques mathematiques (Pohlig-Hellman, baby-step giant-step)

**Scenario**:
Un CTF vous presente des challenges cryptographiques. Vous devez analyser les structures algebriques pour trouver des generateurs, calculer des logarithmes discrets sur des groupes faibles, et effectuer des operations sur courbes elliptiques.

**Format d'Entree**:
```json
{
  "cyclic_groups": [
    {"modulus": 23, "find": "generators"},
    {"modulus": 23, "base": 5, "target": 8, "find": "discrete_log"}
  ],
  "finite_fields": [
    {"type": "gf_p", "p": 17, "operation": "multiply", "a": 7, "b": 11},
    {"type": "gf_2n", "irreducible": "x^4+x+1", "operation": "multiply", "a": "x^2+1", "b": "x+1"}
  ],
  "elliptic_curves": [
    {"curve": {"a": 2, "b": 3, "p": 97}, "operation": "add", "P": [3, 6], "Q": [80, 87]},
    {"curve": {"a": 2, "b": 3, "p": 97}, "operation": "scalar_mul", "P": [3, 6], "k": 7}
  ],
  "attacks": [
    {"type": "baby_giant", "g": 2, "h": 22, "n": 29}
  ]
}
```

**Format de Sortie**:
```json
{
  "generators": [[5, 7, 10, 11, ...]],
  "discrete_logs": [{"base": 5, "target": 8, "log": 18, "mod": 22}],
  "field_results": [...],
  "ec_results": [
    {"operation": "add", "result": [80, 10]},
    {"operation": "scalar_mul", "result": [...]}
  ],
  "attack_results": [{"type": "baby_giant", "x": 19, "steps": 11}]
}
```

**Pieges Pedagogiques**:
- Point a l'infini sur courbes elliptiques
- Doublement de point vs addition de deux points differents
- Groupes d'ordre non premier (Pohlig-Hellman applicable)
- Polynomes irreductibles pour GF(2^n)

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Exercice tres riche couvrant 4 concepts avances
- Format CTF tres engageant pour les etudiants
- Force la comprehension des attaques (pas juste implementation)
- Tests deterministes possibles malgre la complexite

---

### EXERCICE 06 : "L'Archiviste du Passe"
#### Analyse et cassage de chiffrements historiques

**ID**: `3.1.3_ex06`

**Objectif Pedagogique**:
Comprendre les faiblesses des chiffrements historiques en les implementant et en les cassant via analyse frequentielle et autres techniques.

**Concepts Couverts**:
- 3.1.3.a : Chiffrements historiques (Cesar, Vigenere, analyse frequentielle, Kasiski)
- 3.1.3.b : One-Time Pad (securite parfaite de Shannon)

**Scenario**:
Des archives secretes de la Seconde Guerre mondiale ont ete decouvertes. Certains documents sont chiffres avec des methodes variees. Cassez-les et identifiez la methode utilisee.

**Format d'Entree**:
```json
{
  "ciphertexts": [
    {
      "id": 1,
      "text": "KHOOR ZRUOG",
      "hint": "monoalphabetic"
    },
    {
      "id": 2,
      "text": "LXFOPVEFRNHR",
      "hint": "polyalphabetic",
      "known_plaintext_fragment": "SECRET"
    },
    {
      "id": 3,
      "text_hex": "a1b2c3d4...",
      "otp_reuse_warning": true,
      "ciphertext2_hex": "e5f6..."
    }
  ],
  "frequency_analysis_target": "GCUA VQ...",
  "kasiski_target": "..."
}
```

**Format de Sortie**:
```json
{
  "decryptions": [
    {"id": 1, "plaintext": "HELLO WORLD", "method": "caesar", "key": 3},
    {"id": 2, "plaintext": "...", "method": "vigenere", "key": "LEMON"},
    {"id": 3, "plaintext": "...", "method": "otp_reuse_xor", "recovered_key_fragment": "..."}
  ],
  "frequency_analysis": {
    "letter_frequencies": {...},
    "probable_substitution": {...}
  },
  "kasiski_analysis": {
    "repeated_sequences": [...],
    "probable_key_length": 5,
    "reasoning": "..."
  }
}
```

**Pieges Pedagogiques**:
- Texte avec frequences atypiques (jargon technique)
- Double chiffrement (Cesar + Vigenere)
- OTP reutilise: XOR des deux ciphertexts = XOR des plaintexts
- Faux patterns dans Kasiski

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 24 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- Contexte historique captivant
- Force la comprehension des faiblesses (pas juste implementation)
- Attaque OTP reuse = concept avance bien integre
- Tests deterministes avec solutions connues

---

### EXERCICE 07 : "Le Coffre-Fort Moderne"
#### Implementation et analyse de chiffrements par blocs

**ID**: `3.1.3_ex07`

**Objectif Pedagogique**:
Implementer un chiffrement par blocs simplifie, comprendre les modes d'operation, et identifier les vulnerabilites de chaque mode.

**Concepts Couverts**:
- 3.1.3.c : Stream Ciphers (ChaCha20 simplifie)
- 3.1.3.d : Block Ciphers (Feistel, SPN)
- 3.1.3.e : DES (structure, obsolescence)
- 3.1.3.f : 3DES (EDE, depreciation)
- 3.1.3.g : AES (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- 3.1.3.h : Mode ECB (pattern visibility)
- 3.1.3.i : Mode CBC (IV, chaining, bit-flipping)
- 3.1.3.j : Mode CTR (parallelisation, nonce)

**Scenario**:
Un systeme legacy utilise differents modes de chiffrement. Analysez les donnees chiffrees pour identifier les modes utilises et exploitez leurs faiblesses.

**Format d'Entree**:
```json
{
  "implementations": [
    {"task": "implement_feistel", "rounds": 4, "block_size": 64},
    {"task": "implement_aes_round", "state_hex": "..."}
  ],
  "mode_identification": [
    {"ciphertext_hex": "...", "plaintext_hint": "repeated_blocks"},
    {"ciphertext_hex": "...", "iv_hex": "..."}
  ],
  "attacks": [
    {"mode": "ecb", "ciphertexts": [...], "task": "identify_patterns"},
    {"mode": "cbc", "ciphertext_hex": "...", "iv_hex": "...", "task": "bit_flip_byte_5_to_X"},
    {"mode": "ctr", "ciphertext1_hex": "...", "ciphertext2_hex": "...", "same_nonce": true, "task": "recover_keystream"}
  ]
}
```

**Format de Sortie**:
```json
{
  "implementations": {
    "feistel_encrypt": "function_output",
    "aes_round_result": "state_hex_after_round"
  },
  "mode_identifications": [
    {"index": 0, "mode": "ECB", "evidence": "identical_blocks_at_positions_2_5"},
    {"index": 1, "mode": "CBC", "evidence": "iv_present_randomized_blocks"}
  ],
  "attack_results": [
    {"attack": "ecb_pattern", "identified_blocks": {...}},
    {"attack": "cbc_bitflip", "modified_ciphertext": "...", "resulting_plaintext_byte_5": "X"},
    {"attack": "ctr_nonce_reuse", "recovered_keystream_partial": "...", "xor_plaintexts": "..."}
  ]
}
```

**Pieges Pedagogiques**:
- ECB avec padding qui masque les patterns
- CBC bit-flipping affecte bloc precedent de maniere aleatoire
- CTR nonce reuse vs IV reuse en CBC (consequences differentes)

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 8 concepts cruciaux couverts de maniere integree
- Attaques pratiques forcent la comprehension des faiblesses
- Differenciation fine entre modes similaires
- Implementation partielle AES = comprehension profonde

---

### EXERCICE 08 : "Le Bouclier Authentifie"
#### AEAD, padding et derivation de cles

**ID**: `3.1.3_ex08`

**Objectif Pedagogique**:
Maitriser les chiffrements authentifies modernes (GCM, ChaCha20-Poly1305), comprendre les attaques sur le padding, et implementer la derivation de cles securisee.

**Concepts Couverts**:
- 3.1.3.k : Mode GCM (AEAD, GHASH, nonce fragility)
- 3.1.3.l : ChaCha20-Poly1305
- 3.1.3.m : Padding (PKCS#7, padding oracle)
- 3.1.3.n : Key Derivation (PBKDF2, bcrypt, scrypt, Argon2)
- 3.1.3.o : Implementation securisee (constant-time, zeroization)

**Scenario**:
Vous auditez une application de messagerie securisee. Verifiez les implementations AEAD, testez la resistance aux padding oracles, et evaluez la securite de la derivation de cles.

**Format d'Entree**:
```json
{
  "aead_operations": [
    {
      "algorithm": "aes_gcm",
      "key_hex": "...",
      "nonce_hex": "...",
      "plaintext": "...",
      "aad": "metadata",
      "operation": "encrypt"
    },
    {
      "algorithm": "chacha20_poly1305",
      "operation": "decrypt_verify",
      "ciphertext_hex": "...",
      "tag_hex": "...",
      "tampered": true
    }
  ],
  "padding_analysis": [
    {
      "ciphertext_hex": "...",
      "oracle_available": true,
      "task": "decrypt_via_padding_oracle"
    }
  ],
  "kdf_evaluation": [
    {
      "algorithm": "pbkdf2",
      "password": "hunter2",
      "salt_hex": "...",
      "iterations": 1000,
      "task": "derive_and_evaluate_security"
    },
    {
      "algorithm": "argon2id",
      "params": {"time_cost": 2, "memory_cost": 19456, "parallelism": 1},
      "task": "derive_key"
    }
  ],
  "security_audit": {
    "code_snippet": "fn compare_tags(a: &[u8], b: &[u8]) -> bool { a == b }",
    "task": "identify_vulnerability"
  }
}
```

**Format de Sortie**:
```json
{
  "aead_results": [
    {"operation": "encrypt", "ciphertext_hex": "...", "tag_hex": "..."},
    {"operation": "decrypt", "success": false, "reason": "tag_mismatch_tampered"}
  ],
  "padding_oracle_attack": {
    "decrypted_plaintext": "...",
    "oracle_queries_count": 2048,
    "explanation": "..."
  },
  "kdf_evaluations": [
    {
      "algorithm": "pbkdf2",
      "derived_key_hex": "...",
      "security_rating": "weak",
      "issues": ["iterations_too_low_recommended_600000+"],
      "time_to_crack_estimate": "..."
    }
  ],
  "security_audit": {
    "vulnerability": "timing_attack",
    "fix": "use constant_time_compare",
    "rust_solution": "use subtle::ConstantTimeEq"
  }
}
```

**Pieges Pedagogiques**:
- GCM avec nonce reutilise (catastrophique, mais pas toujours evident)
- Padding oracle sur donnees qui ne ressemblent pas a du padding valide
- PBKDF2 avec iterations insuffisantes mais "semblant securise"
- Comparaison de tags non constant-time

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 5 concepts avances parfaitement integres
- Attaque padding oracle = exercice pratique incontournable
- Evaluation critique des KDF = competence professionnelle reelle
- Audit de code constant-time = securite implementation

---

### EXERCICE 09 : "Les Gardiens Asymetriques"
#### RSA complet - Generation, chiffrement, signatures

**ID**: `3.1.4_ex09`

**Objectif Pedagogique**:
Implementer RSA completement: generation de cles, chiffrement/dechiffrement, signatures, et comprendre les schemes de padding modernes.

**Concepts Couverts**:
- 3.1.4.a : Concepts asymetriques (paire de cles, trapdoor functions)
- 3.1.4.b : RSA generation (p, q, n, phi, e, d)
- 3.1.4.c : RSA chiffrement (textbook vs padding)
- 3.1.4.d : RSA signatures
- 3.1.4.e : RSA padding (PKCS#1 v1.5, OAEP, PSS)
- 3.1.4.f : RSA attaques (low exponent, Wiener, Bleichenbacher)

**Scenario**:
Vous construisez un systeme de signature pour documents legaux. Implementez RSA avec les bonnes pratiques, puis analysez des implementations vulnerables pour comprendre les attaques classiques.

**Format d'Entree**:
```json
{
  "key_generation": {
    "bit_length": 2048,
    "e": 65537
  },
  "operations": [
    {"type": "encrypt_oaep", "public_key": {...}, "message": "..."},
    {"type": "sign_pss", "private_key": {...}, "message": "..."},
    {"type": "verify_pss", "public_key": {...}, "message": "...", "signature": "..."}
  ],
  "vulnerability_analysis": [
    {
      "type": "low_exponent_attack",
      "e": 3,
      "ciphertexts": ["c1", "c2", "c3"],
      "moduli": ["n1", "n2", "n3"],
      "task": "recover_plaintext_hastad"
    },
    {
      "type": "wiener_attack",
      "n": "...",
      "e": "...",
      "task": "recover_d"
    },
    {
      "type": "textbook_rsa_malleability",
      "n": "...",
      "e": "...",
      "ciphertext": "...",
      "task": "create_related_ciphertext"
    }
  ]
}
```

**Format de Sortie**:
```json
{
  "generated_keys": {
    "n": "...",
    "e": 65537,
    "d": "...",
    "p": "...",
    "q": "...",
    "dp": "...",
    "dq": "...",
    "qinv": "..."
  },
  "operation_results": [...],
  "attack_results": [
    {
      "attack": "hastad_broadcast",
      "recovered_plaintext": "...",
      "method": "CRT + cube_root"
    },
    {
      "attack": "wiener",
      "recovered_d": "...",
      "continued_fraction_convergents": [...]
    }
  ]
}
```

**Pieges Pedagogiques**:
- Textbook RSA sans padding (deterministe, maleable)
- e=3 sans padding = cube root attack trivial
- CRT-RSA avec mauvaise implementation
- p et q trop proches (Fermat factorization)

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- RSA complet de A a Z avec 6 concepts
- Attaques classiques implementees = comprehension profonde
- Contexte legal documents = realisme
- Parametres CRT pour acceleration = detail pro

---

### EXERCICE 10 : "L'Echange Secret"
#### Diffie-Hellman, ElGamal et DSA

**ID**: `3.1.4_ex10`

**Objectif Pedagogique**:
Maitriser les protocoles d'echange de cles et signatures bases sur le probleme du logarithme discret.

**Concepts Couverts**:
- 3.1.4.g : Diffie-Hellman (protocole, shared secret)
- 3.1.4.h : DH attaques (MITM, small subgroup, Logjam)
- 3.1.4.i : ElGamal (encryption, malleability)
- 3.1.4.j : DSA (signature, nonce criticality)

**Scenario**:
Deux agents secrets doivent etablir une communication securisee. Implementez le protocole DH, detectez les attaques MITM, et gerez les signatures DSA avec attention particuliere aux nonces.

**Format d'Entree**:
```json
{
  "dh_protocol": {
    "p": "...",
    "g": 2,
    "alice_private": "...",
    "bob_private": "..."
  },
  "dh_attack_detection": [
    {
      "scenario": "mitm_intercept",
      "alice_receives": "...",
      "bob_receives": "...",
      "mallory_a": "...",
      "mallory_b": "...",
      "task": "detect_and_explain"
    },
    {
      "scenario": "small_subgroup",
      "received_public": "...",
      "task": "validate_and_reject_if_unsafe"
    }
  ],
  "elgamal": {
    "encrypt": {"public_key": {...}, "message": "..."},
    "malleability_demo": {"ciphertext": {...}, "multiply_by": 2}
  },
  "dsa_operations": [
    {"type": "sign", "private_key": {...}, "message": "...", "k_nonce": "..."},
    {"type": "verify", "public_key": {...}, "message": "...", "signature": {...}}
  ],
  "dsa_nonce_attack": {
    "signature1": {..., "message1": "..."},
    "signature2": {..., "message2": "..."},
    "same_k_used": true,
    "task": "recover_private_key"
  }
}
```

**Format de Sortie**:
```json
{
  "dh_results": {
    "alice_public": "...",
    "bob_public": "...",
    "shared_secret": "..."
  },
  "attack_detection": [
    {"scenario": "mitm", "detected": true, "evidence": "shared_secrets_differ"},
    {"scenario": "small_subgroup", "rejected": true, "reason": "public^order != 1"}
  ],
  "elgamal_results": {...},
  "dsa_results": [...],
  "nonce_attack_result": {
    "recovered_k": "...",
    "recovered_private_key": "...",
    "verification": "signatures_valid_with_recovered_key"
  }
}
```

**Pieges Pedagogiques**:
- DH sans validation parametres (small subgroup)
- ElGamal malleabilite (c1, c2*2 = encrypt(m*2))
- DSA nonce reutilise = fuite immediate de cle privee (PS3 fail)
- Biais dans nonce (lattice attacks)

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 4 concepts complementaires bien integres
- Attaque nonce DSA = exemple historique crucial (PS3, Android)
- Detection MITM = competence pratique
- ElGamal malleabilite souvent negligee

---

### EXERCICE 11 : "Les Courbes du Futur"
#### Cryptographie sur courbes elliptiques et post-quantique

**ID**: `3.1.4_ex11`

**Objectif Pedagogique**:
Maitriser ECDH, ECDSA, Ed25519, et comprendre les enjeux de la cryptographie post-quantique.

**Concepts Couverts**:
- 3.1.4.k : ECDH (DH sur courbes, courbes recommandees)
- 3.1.4.l : ECDSA (signatures ECC, nonce bias)
- 3.1.4.m : Ed25519 (EdDSA, avantages)
- 3.1.4.n : Post-quantique (Shor, Kyber, Dilithium, SPHINCS+)
- 3.1.4.o : Side-channel attacks (timing, power analysis)
- 3.1.4.p : Implementation securisee (validation points, blinding)

**Scenario**:
Une agence gouvernementale prepare la transition vers la cryptographie post-quantique. Implementez les protocoles actuels (ECDH, Ed25519) et evaluez les candidats PQC.

**Format d'Entree**:
```json
{
  "ecdh": {
    "curve": "P-256",
    "alice_private": "...",
    "bob_private": "..."
  },
  "ecdsa": {
    "curve": "secp256k1",
    "sign": {"private_key": "...", "message": "...", "k": "..."},
    "verify": {"public_key": "...", "message": "...", "signature": {...}}
  },
  "ed25519": {
    "generate_keypair": true,
    "sign": {"message": "..."},
    "verify": {"public_key": "...", "message": "...", "signature": "..."}
  },
  "post_quantum_evaluation": {
    "scenario": "quantum_computer_available",
    "current_algorithms": ["RSA-2048", "ECDSA-P256", "Ed25519"],
    "task": "evaluate_security_and_recommend_pqc"
  },
  "side_channel_audit": {
    "code": "fn scalar_mul(k: BigInt, P: Point) -> Point { ... non-constant-time ... }",
    "task": "identify_timing_vulnerability"
  },
  "point_validation": {
    "curve": "P-256",
    "point": {"x": "...", "y": "..."},
    "task": "validate_on_curve_and_in_subgroup"
  }
}
```

**Format de Sortie**:
```json
{
  "ecdh_result": {
    "alice_public": {...},
    "bob_public": {...},
    "shared_secret": "..."
  },
  "ecdsa_result": {...},
  "ed25519_result": {
    "keypair": {"public": "...", "secret": "..."},
    "signature": "...",
    "verification": true
  },
  "pqc_evaluation": {
    "rsa_2048": {"broken_by": "shor", "time_estimate": "hours"},
    "ecdsa_p256": {"broken_by": "shor", "time_estimate": "minutes"},
    "recommendations": {
      "key_exchange": "Kyber-768",
      "signatures": "Dilithium-3 or Ed25519 (hybrid)",
      "hash_based_alternative": "SPHINCS+-256"
    },
    "migration_strategy": "hybrid_classical_pqc"
  },
  "side_channel_audit": {
    "vulnerability": "timing_leak_via_conditional_branches",
    "exploitable": true,
    "fix": "use_constant_time_scalar_mul_montgomery_ladder"
  },
  "point_validation": {
    "on_curve": true,
    "in_prime_order_subgroup": true,
    "safe_to_use": true
  }
}
```

**Pieges Pedagogiques**:
- Point non sur la courbe (invalid curve attack)
- ECDSA avec nonce biaise (lattice attack)
- Ed25519 non deterministe (implementation incorrecte)
- Confusion Kyber (KEM) vs Dilithium (signatures)

**Auto-evaluation**: 99/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 20 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 6 concepts de pointe parfaitement integres
- Post-quantique = sujet d'actualite majeur
- Side-channels = competence security engineering rare
- Validation de points = subtilite souvent ignoree

---

### EXERCICE 12 : "L'Empreinte Numerique"
#### Fonctions de hachage et leurs proprietes

**ID**: `3.1.5_ex12`

**Objectif Pedagogique**:
Comprendre les proprietes des fonctions de hachage, leurs constructions, et les attaques associees.

**Concepts Couverts**:
- 3.1.5.a : Proprietes (pre-image, second pre-image, collision, avalanche)
- 3.1.5.b : Merkle-Damgard (construction, length extension)
- 3.1.5.c : MD5 (obsolete, collisions)
- 3.1.5.d : SHA-1 (deprecated, SHAttered)
- 3.1.5.e : SHA-2 (SHA-256, securise)
- 3.1.5.f : SHA-3 (Keccak, sponge)
- 3.1.5.g : BLAKE2/BLAKE3

**Scenario**:
Un systeme d'integrite de fichiers utilise differentes fonctions de hachage. Analysez leur securite, exploitez les faiblesses des anciennes, et recommandez les modernes.

**Format d'Entree**:
```json
{
  "hash_operations": [
    {"algorithm": "md5", "input": "test"},
    {"algorithm": "sha1", "input": "test"},
    {"algorithm": "sha256", "input": "test"},
    {"algorithm": "sha3_256", "input": "test"},
    {"algorithm": "blake3", "input": "test"}
  ],
  "property_tests": [
    {"test": "avalanche", "algorithm": "sha256", "input1": "test", "input2": "test2"},
    {"test": "length_extension", "algorithm": "sha256", "known_hash": "...", "known_length": 10, "append": "malicious"}
  ],
  "collision_analysis": [
    {"algorithm": "md5", "prefix": "...", "task": "explain_collision_attack"},
    {"algorithm": "sha1", "task": "reference_shattered_attack"}
  ],
  "comparison": {
    "file_integrity_system": true,
    "performance_requirements": "high_throughput",
    "task": "recommend_algorithm"
  }
}
```

**Format de Sortie**:
```json
{
  "hashes": [
    {"algorithm": "md5", "hash": "098f6bcd4621d373cade4e832627b4f6"},
    ...
  ],
  "avalanche_result": {
    "hamming_distance": 128,
    "percentage_changed": 50.0,
    "satisfies_avalanche": true
  },
  "length_extension": {
    "vulnerable": true,
    "algorithms_vulnerable": ["md5", "sha1", "sha256"],
    "algorithms_safe": ["sha3", "blake3", "hmac_sha256"],
    "forged_hash": "...",
    "explanation": "Merkle-Damgard internal state equals hash output"
  },
  "collision_analysis": {
    "md5": {
      "status": "broken",
      "collision_time": "< 1 second",
      "chosen_prefix_possible": true
    },
    "sha1": {
      "status": "broken",
      "shattered_cost": "~$110,000 GPU-years in 2017"
    }
  },
  "recommendation": {
    "primary": "BLAKE3",
    "reasoning": "fastest, parallelizable, secure, no length extension",
    "alternative": "SHA-256 if compliance required"
  }
}
```

**Pieges Pedagogiques**:
- SHA-256 vulnerable a length extension (pas SHA-3)
- MD5 collisions triviales mais pre-image toujours dur
- BLAKE3 vs BLAKE2 (performance vs compatibilite)
- SHA-3 absorption rate vs security

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 7 concepts de hachage exhaustivement couverts
- Length extension = attaque sous-estimee mais critique
- Comparaison pratique = competence decision-making
- Historique MD5/SHA-1 = contexte important

---

### EXERCICE 13 : "Le Sceau Authentique"
#### HMAC et hachage de mots de passe

**ID**: `3.1.5_ex13`

**Objectif Pedagogique**:
Maitriser HMAC pour l'authentification de messages et les algorithmes specialises pour le hachage de mots de passe.

**Concepts Couverts**:
- 3.1.5.h : HMAC (construction, securite)
- 3.1.5.i : Password Hashing (salt, slow hash)
- 3.1.5.j : bcrypt
- 3.1.5.k : scrypt (memory-hard)
- 3.1.5.l : Argon2 (PHC winner)
- 3.1.5.m : Attaques hachage (rainbow, brute-force, timing)
- 3.1.5.n : Merkle Trees

**Scenario**:
Vous securisez un systeme d'authentification. Implementez HMAC pour les tokens API, configurez correctement le hachage des mots de passe, et construisez un arbre de Merkle pour la verification d'integrite.

**Format d'Entree**:
```json
{
  "hmac_operations": [
    {"key": "secret", "message": "data", "algorithm": "sha256"},
    {"key": "secret", "message": "data", "algorithm": "sha256", "verify": "expected_mac"}
  ],
  "password_hashing": [
    {
      "algorithm": "bcrypt",
      "password": "hunter2",
      "cost": 12
    },
    {
      "algorithm": "argon2id",
      "password": "correct horse battery staple",
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 4
    },
    {
      "algorithm": "scrypt",
      "password": "...",
      "n": 16384,
      "r": 8,
      "p": 1
    }
  ],
  "password_audit": {
    "stored_hashes": [
      {"hash": "$2a$04$...", "username": "alice"},
      {"hash": "$argon2id$v=19$m=1024,t=1,p=1$...", "username": "bob"}
    ],
    "task": "evaluate_security"
  },
  "attack_simulation": {
    "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
    "algorithm": "md5",
    "wordlist": ["password", "123456", "admin", ...],
    "task": "crack_and_explain_why_weak"
  },
  "merkle_tree": {
    "leaves": ["tx1", "tx2", "tx3", "tx4"],
    "task": "build_tree_and_generate_proof_for_tx3"
  }
}
```

**Format de Sortie**:
```json
{
  "hmac_results": [
    {"mac": "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"},
    {"verification": true, "constant_time": true}
  ],
  "password_hashes": [
    {"algorithm": "bcrypt", "hash": "$2b$12$..."},
    {"algorithm": "argon2id", "hash": "$argon2id$v=19$m=65536,t=3,p=4$..."}
  ],
  "security_audit": [
    {
      "username": "alice",
      "algorithm": "bcrypt",
      "cost": 4,
      "verdict": "WEAK - cost too low, upgrade to 12+",
      "time_to_crack": "~2 hours with GPU"
    },
    {
      "username": "bob",
      "algorithm": "argon2id",
      "memory": 1024,
      "verdict": "WEAK - memory too low (1MB vs 64MB recommended)",
      "time_to_crack": "~1 day with GPU"
    }
  ],
  "attack_result": {
    "cracked": true,
    "password": "password",
    "method": "dictionary",
    "time_ms": 2,
    "weakness": "MD5 unsalted + common password"
  },
  "merkle_tree": {
    "root": "...",
    "proof_for_tx3": {
      "leaf_hash": "...",
      "siblings": ["hash_tx4", "hash_tx1_tx2"],
      "directions": ["right", "left"]
    },
    "verification_algorithm": "..."
  }
}
```

**Pieges Pedagogiques**:
- bcrypt cost trop bas (< 10)
- Argon2 avec memoire insuffisante
- HMAC verification non constant-time
- Merkle proof avec mauvais ordre des siblings
- Salt reutilise vs unique

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 7 concepts complementaires parfaitement integres
- Audit de securite = competence professionnelle directe
- Merkle trees = fondation blockchain/Git
- Attaque dictionnaire = realisme pedagogique

---

### EXERCICE 14 : "L'Autorite de Confiance"
#### PKI, certificats X.509 et validation

**ID**: `3.1.6_ex14`

**Objectif Pedagogique**:
Comprendre l'ecosysteme PKI complet: structure des certificats X.509, chaine de confiance, revocation et Certificate Transparency.

**Concepts Couverts**:
- 3.1.6.a : X.509 (structure, extensions)
- 3.1.6.b : CA (Root, Intermediate, chaine de confiance)
- 3.1.6.c : CSR (demande de certificat)
- 3.1.6.d : Revocation (CRL, OCSP, OCSP Stapling)
- 3.1.6.e : Certificate Transparency (logs CT, SCT)
- 3.1.6.f : Let's Encrypt (ACME protocol)

**Scenario**:
Vous gerez l'infrastructure PKI d'une entreprise. Analysez des certificats, validez des chaines, detectez les certificats revoques, et verifiez la presence dans les logs CT.

**Format d'Entree**:
```json
{
  "certificate_analysis": [
    {
      "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
      "task": "parse_and_extract_fields"
    }
  ],
  "chain_validation": {
    "leaf_pem": "...",
    "intermediates": ["..."],
    "trusted_roots": ["..."],
    "current_time": "2024-06-15T12:00:00Z",
    "task": "validate_chain"
  },
  "revocation_check": {
    "cert_pem": "...",
    "crl_url": "...",
    "ocsp_url": "...",
    "task": "check_revocation_status"
  },
  "ct_verification": {
    "cert_pem": "...",
    "sct_list": [...],
    "ct_logs": [...],
    "task": "verify_scts"
  },
  "csr_creation": {
    "common_name": "api.example.com",
    "san": ["api.example.com", "api2.example.com"],
    "organization": "Example Corp",
    "key_algorithm": "ecdsa_p256",
    "task": "generate_csr"
  },
  "acme_simulation": {
    "domain": "test.example.com",
    "challenge_type": "http-01",
    "task": "explain_challenge_response"
  }
}
```

**Format de Sortie**:
```json
{
  "certificate_parsed": {
    "version": 3,
    "serial": "...",
    "issuer": {"CN": "...", "O": "...", "C": "..."},
    "subject": {"CN": "..."},
    "validity": {"not_before": "...", "not_after": "..."},
    "public_key": {"algorithm": "RSA", "size": 2048},
    "extensions": {
      "key_usage": ["digitalSignature", "keyEncipherment"],
      "extended_key_usage": ["serverAuth", "clientAuth"],
      "subject_alt_name": ["DNS:example.com", "DNS:*.example.com"],
      "basic_constraints": {"ca": false},
      "authority_info_access": {...}
    },
    "signature_algorithm": "sha256WithRSAEncryption"
  },
  "chain_validation_result": {
    "valid": true,
    "chain": ["leaf", "intermediate1", "root"],
    "checks_performed": [
      "signature_verification",
      "validity_period",
      "key_usage",
      "basic_constraints",
      "name_constraints"
    ]
  },
  "revocation_status": {
    "crl_check": {"revoked": false, "crl_date": "..."},
    "ocsp_check": {"status": "good", "response_time_ms": 45}
  },
  "ct_verification": {
    "scts_valid": 3,
    "scts_required": 2,
    "logs_verified": ["Google Argon", "DigiCert Yeti"],
    "compliant": true
  },
  "csr_generated": {
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "public_key_hash": "..."
  },
  "acme_challenge": {
    "type": "http-01",
    "token": "...",
    "key_authorization": "token.account_thumbprint",
    "url": "http://test.example.com/.well-known/acme-challenge/TOKEN",
    "expected_content": "..."
  }
}
```

**Pieges Pedagogiques**:
- Certificat expire mais signature valide
- Intermediate CA avec path length constraint
- OCSP response stale (must-staple violation)
- SCT de log CT non reconnu
- Wildcard ne couvrant pas les sous-sous-domaines

**Auto-evaluation**: 97/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 6 concepts PKI fondamentaux parfaitement integres
- Certificate Transparency = sujet moderne crucial
- ACME/Let's Encrypt = competence pratique directe
- Validations multiples = comprehension complete

---

### EXERCICE 15 : "Les Formats de Confiance"
#### Formats de certificats, commandes OpenSSL et alternatives PKI

**ID**: `3.1.6_ex15`

**Objectif Pedagogique**:
Maitriser les differents formats de certificats, les commandes OpenSSL essentielles, et comprendre les modeles alternatifs (Web of Trust, Pinning).

**Concepts Couverts**:
- 3.1.6.g : Types de certificats (DV, OV, EV, Wildcard)
- 3.1.6.h : Formats (PEM, DER, PKCS#12, PKCS#7)
- 3.1.6.i : OpenSSL commandes
- 3.1.6.j : Web of Trust (PGP/GPG)
- 3.1.6.k : Pinning (certificate, HPKP deprecated, CAA)

**Scenario**:
Migration d'une infrastructure PKI: convertissez des certificats entre formats, configurez le pinning, et etablissez un reseau de confiance GPG pour l'equipe.

**Format d'Entree**:
```json
{
  "format_conversion": [
    {"input_format": "pem", "output_format": "der", "input_data": "..."},
    {"input_format": "pem", "output_format": "pkcs12", "cert": "...", "key": "...", "password": "export123"},
    {"input_format": "pkcs12", "output_format": "pem", "input_data": "...", "password": "..."}
  ],
  "certificate_type_analysis": [
    {"cert_pem": "...", "task": "identify_dv_ov_ev"}
  ],
  "openssl_commands": [
    {"task": "generate_rsa_4096_key"},
    {"task": "generate_ecdsa_p256_key"},
    {"task": "create_self_signed_cert", "key": "...", "days": 365, "cn": "test.local"},
    {"task": "verify_certificate_chain", "cert": "...", "ca": "..."},
    {"task": "check_cert_expiry", "cert": "..."}
  ],
  "pgp_web_of_trust": {
    "task": "simulate_key_signing",
    "keys": [
      {"email": "alice@corp.com", "trust_level": "ultimate", "fingerprint": "..."},
      {"email": "bob@corp.com", "trust_level": "full", "signed_by": ["alice"]},
      {"email": "charlie@corp.com", "trust_level": "marginal", "signed_by": ["bob"]}
    ],
    "question": "Can alice verify message from charlie?"
  },
  "pinning_configuration": {
    "domain": "api.secure.com",
    "certificates": [...],
    "task": "generate_pin_hashes_and_caa_record"
  }
}
```

**Format de Sortie**:
```json
{
  "conversions": [
    {"output_format": "der", "output_base64": "..."},
    {"output_format": "pkcs12", "output_base64": "..."},
    {"output_format": "pem", "cert": "...", "key": "..."}
  ],
  "certificate_types": [
    {
      "type": "EV",
      "evidence": {
        "organization_field": "present_and_validated",
        "jurisdiction": "present",
        "ev_oid": "2.23.140.1.1 present in policies"
      }
    }
  ],
  "openssl_commands_output": [
    {"task": "generate_rsa_4096_key", "command": "openssl genrsa -out key.pem 4096", "output": "..."},
    {"task": "generate_ecdsa_p256_key", "command": "openssl ecparam -genkey -name prime256v1 -out key.pem", "output": "..."},
    ...
  ],
  "web_of_trust_analysis": {
    "can_verify": true,
    "trust_path": ["charlie → bob (full) → alice (ultimate)"],
    "trust_calculation": "marginal needs 3 signatures or 1 full, bob is full, path valid"
  },
  "pinning_config": {
    "pin_hashes": [
      {"type": "sha256", "hash": "base64...", "subject": "leaf"},
      {"type": "sha256", "hash": "base64...", "subject": "intermediate_backup"}
    ],
    "caa_record": "example.com. CAA 0 issue \"letsencrypt.org\"",
    "hpkp_header_deprecated": "Public-Key-Pins: ...",
    "recommended_approach": "CAA + application-level pinning, not HPKP"
  }
}
```

**Pieges Pedagogiques**:
- PKCS#12 sans mot de passe (non recommande)
- EV detection sans OID specifique
- Web of Trust: marginal trust insuffisant seul
- HPKP deprecie mais parfois demande
- CAA ne protege pas contre CA compromise

**Auto-evaluation**: 96/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 24 |
| Intelligence Pedagogique | 25 | 24 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 5 concepts complementaires bien couverts
- Commandes OpenSSL = competence indispensable
- Web of Trust = alternative importante a comprendre
- Depreciation HPKP = contexte historique pertinent

---

### EXERCICE 16 : "Les Protocoles Blindes"
#### TLS, SSH et VPN modernes

**ID**: `3.1.7_ex16`

**Objectif Pedagogique**:
Maitriser les protocoles de securisation des communications: TLS 1.2/1.3, SSH, IPsec et WireGuard.

**Concepts Couverts**:
- 3.1.7.a : TLS 1.2 (handshake, cipher suites)
- 3.1.7.b : TLS 1.3 (1-RTT, 0-RTT, ameliorations)
- 3.1.7.c : TLS attaques (BEAST, POODLE, Heartbleed, DROWN)
- 3.1.7.d : SSH Protocol v2 (transport, auth, hardening)
- 3.1.7.e : IPsec (AH, ESP, IKE)
- 3.1.7.f : WireGuard (Noise protocol, simplicite)

**Scenario**:
Audit de securite des protocoles de communication d'une entreprise. Analysez les configurations TLS, durcissez SSH, et comparez les solutions VPN.

**Format d'Entree**:
```json
{
  "tls_analysis": [
    {
      "server": "legacy.example.com",
      "cipher_suites": [
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      ],
      "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
      "task": "audit_and_recommend"
    },
    {
      "server": "modern.example.com",
      "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"],
      "protocols": ["TLSv1.3"],
      "task": "verify_best_practices"
    }
  ],
  "tls_attack_identification": [
    {"symptoms": "server_supports_sslv3_cbc", "task": "identify_attack"},
    {"symptoms": "server_supports_export_dh_512", "task": "identify_attack"},
    {"symptoms": "heartbeat_extension_enabled_openssl_1.0.1", "task": "identify_attack"}
  ],
  "ssh_hardening": {
    "current_config": {
      "PasswordAuthentication": "yes",
      "PermitRootLogin": "yes",
      "Protocol": "2",
      "Ciphers": "default",
      "MACs": "default"
    },
    "task": "harden_configuration"
  },
  "vpn_comparison": {
    "requirements": {
      "users": 500,
      "mobile_support": true,
      "performance": "high",
      "ease_of_config": "important"
    },
    "candidates": ["OpenVPN", "IPsec/IKEv2", "WireGuard"],
    "task": "compare_and_recommend"
  }
}
```

**Format de Sortie**:
```json
{
  "tls_audit": [
    {
      "server": "legacy.example.com",
      "issues": [
        {"severity": "critical", "issue": "TLSv1.0_enabled", "vulnerable_to": "POODLE, BEAST"},
        {"severity": "high", "issue": "3DES_enabled", "vulnerable_to": "Sweet32"},
        {"severity": "medium", "issue": "RSA_key_exchange", "issue_detail": "no_forward_secrecy"}
      ],
      "recommendations": {
        "disable_protocols": ["TLSv1.0", "TLSv1.1"],
        "disable_ciphers": ["*3DES*", "*CBC*SHA"],
        "enable_ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        "consider_upgrade": "TLSv1.3"
      }
    }
  ],
  "attack_identifications": [
    {"symptoms": "sslv3_cbc", "attack": "POODLE", "cve": "CVE-2014-3566"},
    {"symptoms": "export_dh_512", "attack": "Logjam", "cve": "CVE-2015-4000"},
    {"symptoms": "heartbeat_openssl_1.0.1", "attack": "Heartbleed", "cve": "CVE-2014-0160"}
  ],
  "ssh_hardened_config": {
    "PasswordAuthentication": "no",
    "PermitRootLogin": "prohibit-password",
    "PubkeyAuthentication": "yes",
    "AuthenticationMethods": "publickey",
    "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    "MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
    "KexAlgorithms": "curve25519-sha256,diffie-hellman-group16-sha512",
    "HostKeyAlgorithms": "ssh-ed25519,rsa-sha2-512"
  },
  "vpn_comparison": {
    "openvpn": {
      "pros": ["mature", "flexible", "audited"],
      "cons": ["complex_config", "slower", "userspace"]
    },
    "ipsec_ikev2": {
      "pros": ["standard", "mobile_native_support", "strong_crypto"],
      "cons": ["complex", "config_heavy", "debugging_difficult"]
    },
    "wireguard": {
      "pros": ["fast", "simple_config", "kernel_space", "modern_crypto", "roaming"],
      "cons": ["newer", "less_audits", "static_ips_default"]
    },
    "recommendation": "WireGuard",
    "reasoning": "Best fit for mobile, performance, and ease of config requirements"
  }
}
```

**Pieges Pedagogiques**:
- TLS 1.3 0-RTT replay attacks
- SSH avec Protocol 1 residuel
- IPsec AH vs ESP confusion
- WireGuard clés statiques (pas de PFS traditionnel)
- CBC + SHA1 pas forcement vulnerable sans autres conditions

**Auto-evaluation**: 98/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 19 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 6 protocoles essentiels parfaitement couverts
- Attaques TLS historiques = culture securite indispensable
- Hardening SSH = competence directement applicable
- Comparaison VPN = decision architecturale courante

---

### EXERCICE 17 : "Les Gardiens de Session"
#### Signal Protocol, Kerberos et mTLS

**ID**: `3.1.7_ex17`

**Objectif Pedagogique**:
Comprendre les protocoles avances de gestion de session: Double Ratchet (Signal), authentification Kerberos, et mTLS/DNSSEC.

**Concepts Couverts**:
- 3.1.7.g : Signal Protocol (Double Ratchet, X3DH)
- 3.1.7.h : Kerberos (TGT, service tickets, attaques)
- 3.1.7.i : mTLS (mutual TLS)
- 3.1.7.j : DNSSEC (signature DNS)

**Scenario**:
Architecture de securite pour une organisation: implementez une messagerie securisee type Signal, analysez la securite Kerberos de l'AD, deployez mTLS pour les microservices, et securisez le DNS.

**Format d'Entree**:
```json
{
  "signal_protocol": {
    "x3dh_key_agreement": {
      "alice_identity_key": "...",
      "alice_ephemeral_key": "...",
      "bob_identity_key": "...",
      "bob_signed_prekey": "...",
      "bob_one_time_prekey": "...",
      "task": "compute_shared_secret"
    },
    "double_ratchet_simulation": {
      "initial_root_key": "...",
      "messages": [
        {"sender": "alice", "plaintext": "Hello"},
        {"sender": "alice", "plaintext": "How are you?"},
        {"sender": "bob", "plaintext": "Fine!"},
        {"sender": "alice", "plaintext": "Great"}
      ],
      "task": "demonstrate_key_evolution"
    }
  },
  "kerberos_analysis": {
    "scenario": {
      "domain": "CORP.LOCAL",
      "user": "jsmith",
      "service": "HTTP/webapp.corp.local"
    },
    "tasks": [
      "explain_tgt_acquisition",
      "explain_service_ticket_flow",
      "identify_golden_ticket_attack",
      "identify_kerberoasting_attack"
    ],
    "attack_simulation": {
      "captured_service_ticket": "...",
      "service_spn": "MSSQLSvc/db.corp.local",
      "task": "explain_kerberoasting"
    }
  },
  "mtls_deployment": {
    "services": ["api-gateway", "user-service", "payment-service"],
    "task": "design_mtls_architecture",
    "questions": [
      "how_to_handle_cert_rotation",
      "how_to_handle_service_discovery",
      "what_if_ca_compromised"
    ]
  },
  "dnssec": {
    "zone": "example.com",
    "records": [
      {"name": "www", "type": "A", "value": "1.2.3.4"}
    ],
    "task": "explain_signing_and_validation"
  }
}
```

**Format de Sortie**:
```json
{
  "x3dh_result": {
    "dh1": "DH(alice_identity, bob_signed_prekey)",
    "dh2": "DH(alice_ephemeral, bob_identity)",
    "dh3": "DH(alice_ephemeral, bob_signed_prekey)",
    "dh4": "DH(alice_ephemeral, bob_one_time_prekey)",
    "shared_secret": "KDF(DH1 || DH2 || DH3 || DH4)",
    "forward_secrecy": "yes, one-time prekey consumed"
  },
  "double_ratchet_demo": {
    "message_keys": [
      {"msg": 1, "chain": "sending_alice", "key": "mk1", "ratchet_step": "symmetric"},
      {"msg": 2, "chain": "sending_alice", "key": "mk2", "ratchet_step": "symmetric"},
      {"msg": 3, "chain": "sending_bob", "key": "mk3", "ratchet_step": "dh_ratchet_then_symmetric"},
      {"msg": 4, "chain": "sending_alice", "key": "mk4", "ratchet_step": "dh_ratchet_then_symmetric"}
    ],
    "security_properties": {
      "forward_secrecy": "each message has unique key",
      "break_in_recovery": "dh_ratchet regenerates keys after compromise"
    }
  },
  "kerberos_explained": {
    "tgt_flow": [
      "1. Client sends AS-REQ (timestamp encrypted with user's hash)",
      "2. KDC validates, returns TGT (encrypted with krbtgt hash) + session key",
      "3. Client caches TGT for ~10 hours"
    ],
    "service_ticket_flow": [
      "1. Client sends TGS-REQ with TGT to KDC",
      "2. KDC returns service ticket (encrypted with service account hash)",
      "3. Client presents ticket to service"
    ],
    "golden_ticket": {
      "description": "Forge TGT using compromised krbtgt hash",
      "impact": "Domain dominance, any user impersonation",
      "detection": "TGT lifetime anomalies, no AS-REQ for TGT",
      "mitigation": "Reset krbtgt twice, monitoring"
    },
    "kerberoasting": {
      "description": "Request service tickets, crack offline",
      "target": "Services with weak passwords",
      "mitigation": "Strong service account passwords (25+ chars), managed service accounts"
    }
  },
  "mtls_architecture": {
    "design": {
      "internal_ca": "Dedicated intermediate CA for services",
      "cert_per_service": true,
      "spiffe_compatible": true
    },
    "cert_rotation": "Short-lived certs (24h) + automated renewal (cert-manager)",
    "service_discovery": "SAN with DNS name or SPIFFE ID",
    "ca_compromise": "Revoke intermediate, rotate all service certs, investigate scope"
  },
  "dnssec_explanation": {
    "signing": {
      "zsk": "Zone Signing Key signs records (RRSIG)",
      "ksk": "Key Signing Key signs DNSKEY (trust anchor)",
      "chain": "Root → .com → example.com"
    },
    "records_created": {
      "rrsig": "Signature over A record",
      "dnskey": "ZSK and KSK public keys",
      "ds": "Hash of KSK in parent zone"
    },
    "validation": "Resolver verifies RRSIG using DNSKEY, DNSKEY via DS in parent"
  }
}
```

**Pieges Pedagogiques**:
- Signal: prekey one-time vs signed (differentes proprietes)
- Kerberos: confusion TGT vs service ticket
- Golden Ticket vs Silver Ticket (scope different)
- mTLS: client auth optionnel vs requis
- DNSSEC: ne chiffre pas, signe seulement

**Auto-evaluation**: 99/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 20 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 4 protocoles complexes parfaitement expliques
- Signal Double Ratchet = reference cryptographie moderne
- Kerberos attacks = competence pentest AD
- mTLS = zero trust implementation
- DNSSEC = souvent mal compris (signature vs encryption)

---

### EXERCICE 18 : "Les Sources du Chaos"
#### Aleatoire cryptographique et entropie

**ID**: `3.1.8_ex18`

**Objectif Pedagogique**:
Maitriser la generation de nombres aleatoires securises: sources d'entropie, CSPRNG, et detection des faiblesses.

**Concepts Couverts**:
- 3.1.8.a : TRNG vs PRNG
- 3.1.8.b : Sources d'entropie (/dev/random, /dev/urandom, getrandom)
- 3.1.8.c : CSPRNG (ChaCha20, AES-CTR-DRBG)
- 3.1.8.d : Attaques RNG (prediction, faible entropie, Dual_EC)
- 3.1.8.e : Tests statistiques (NIST SP 800-22)
- 3.1.8.f : Best practices

**Scenario**:
Audit d'un systeme IoT qui genere des cles cryptographiques. Evaluez la qualite de l'entropie, detectez les failles dans la generation aleatoire, et recommandez des ameliorations.

**Format d'Entree**:
```json
{
  "rng_classification": [
    {"source": "/dev/random", "task": "classify_trng_prng"},
    {"source": "Mersenne Twister", "task": "classify_and_evaluate_crypto_use"},
    {"source": "RDRAND instruction", "task": "classify_and_discuss_trust"},
    {"source": "ChaCha20-based DRBG", "task": "classify_and_evaluate"}
  ],
  "entropy_analysis": {
    "boot_scenario": {
      "system": "embedded_linux",
      "boot_time_ms": 500,
      "entropy_sources": ["timer_jitter"],
      "first_key_generation_ms": 600,
      "task": "evaluate_entropy_at_key_generation"
    },
    "vm_clone_scenario": {
      "description": "VM cloned from snapshot, both generate SSL keys",
      "task": "identify_problem_and_solution"
    }
  },
  "csprng_implementation_review": {
    "code": {
      "language": "rust",
      "snippet": "use rand::Rng; let key: [u8; 32] = rand::thread_rng().gen();"
    },
    "task": "evaluate_for_cryptographic_use"
  },
  "attack_scenarios": [
    {
      "name": "Debian OpenSSL",
      "year": 2008,
      "task": "explain_vulnerability_and_impact"
    },
    {
      "name": "Dual_EC_DRBG",
      "task": "explain_backdoor_mechanism"
    },
    {
      "name": "Android SecureRandom",
      "year": 2013,
      "task": "explain_bitcoin_wallet_vulnerability"
    }
  ],
  "statistical_testing": {
    "sample_hex": "...(1MB of hex data)...",
    "task": "describe_tests_and_interpret",
    "tests_to_explain": ["frequency", "runs", "longest_run", "fft", "approximate_entropy"]
  },
  "best_practices_quiz": [
    {"question": "Should you use /dev/random or /dev/urandom for key generation?"},
    {"question": "Is time-based seeding acceptable?"},
    {"question": "How to ensure entropy in containers?"},
    {"question": "What is the role of RDSEED vs RDRAND?"}
  ]
}
```

**Format de Sortie**:
```json
{
  "classifications": [
    {
      "source": "/dev/random",
      "type": "CSPRNG (backed by TRNG sources)",
      "crypto_safe": true,
      "notes": "On modern Linux (4.8+), equivalent to /dev/urandom after initial seeding"
    },
    {
      "source": "Mersenne Twister",
      "type": "PRNG",
      "crypto_safe": false,
      "reason": "State recoverable from 624 outputs, not designed for crypto"
    },
    {
      "source": "RDRAND",
      "type": "Hardware CSPRNG (controversial)",
      "crypto_safe": "conditional",
      "notes": "Intel CPU instruction, concerns about verifiability, best mixed with software entropy"
    },
    {
      "source": "ChaCha20-DRBG",
      "type": "CSPRNG",
      "crypto_safe": true,
      "notes": "Modern, fast, secure, used in Linux kernel"
    }
  ],
  "entropy_analysis": {
    "boot_scenario": {
      "verdict": "HIGH RISK",
      "issue": "Insufficient entropy at boot (100ms is not enough)",
      "entropy_estimate": "~50-100 bits vs 256 required",
      "recommendation": "Defer key generation, use hardware RNG, persist entropy across boots"
    },
    "vm_clone": {
      "problem": "Identical RNG state in both VMs → same 'random' keys",
      "impact": "Private key collision, complete security failure",
      "solutions": [
        "Re-seed RNG after clone detection",
        "Use VM-specific entropy injection (virtio-rng)",
        "VMGENID detection and reseed"
      ]
    }
  },
  "code_review": {
    "verdict": "ACCEPTABLE with caveats",
    "analysis": {
      "rand_crate": "Uses ChaCha-based StdRng which is CSPRNG",
      "thread_rng": "Auto-seeded from OS entropy (getrandom)",
      "concern": "Depends on proper OS entropy, fine for server, risk on embedded"
    },
    "recommendation": "For high security, use `getrandom` crate directly or `ring`"
  },
  "attack_explanations": {
    "debian_openssl": {
      "vulnerability": "Accidentally removed entropy sources during code cleanup",
      "impact": "Only PID used as seed → 32,768 possible keys",
      "duration": "2006-2008 (2 years)",
      "affected": "All Debian/Ubuntu SSL keys, SSH keys generated in that period"
    },
    "dual_ec_drbg": {
      "mechanism": "Curve points P and Q with potentially known discrete log(P,Q)",
      "backdoor": "If d known where Q=dP, output can be used to recover internal state",
      "who": "NSA allegedly designed with backdoor, NIST standard",
      "lesson": "Avoid NIST curves with unexplained constants"
    },
    "android_securerandom": {
      "vulnerability": "Improper seeding of SecureRandom in some Android versions",
      "bitcoin_impact": "ECDSA nonce k derived from weak RNG → private key recovery",
      "wallets_affected": "Multiple Bitcoin wallets, funds stolen"
    }
  },
  "statistical_tests": {
    "frequency": "Proportion of 0s and 1s should be ~50%",
    "runs": "Sequence of identical bits should match expected distribution",
    "longest_run": "Longest run of 1s in blocks should not be anomalous",
    "fft": "Detects periodic patterns in the sequence",
    "approximate_entropy": "Measures randomness of overlapping patterns",
    "caveat": "Passing tests does NOT prove crypto security (Dual_EC passed all tests)"
  },
  "best_practices_answers": [
    {
      "question": "random vs urandom",
      "answer": "Use /dev/urandom (or getrandom). /dev/random blocking is legacy behavior with no security benefit on modern Linux"
    },
    {
      "question": "time-based seeding",
      "answer": "NEVER acceptable for crypto. Time is predictable/observable"
    },
    {
      "question": "containers entropy",
      "answer": "Share /dev/urandom from host, use virtio-rng, or haveged daemon"
    },
    {
      "question": "RDSEED vs RDRAND",
      "answer": "RDSEED provides raw entropy, RDRAND provides CSPRNG output. RDSEED for seeding, RDRAND for bulk random"
    }
  ]
}
```

**Pieges Pedagogiques**:
- /dev/random vs /dev/urandom (mythe du blocking = plus securise)
- Mersenne Twister dans libs standard (semble random, pas crypto)
- Tests statistiques passants ≠ securite crypto
- VM clones avec meme entropie
- Dual_EC: backdoor sophistique et instructif

**Auto-evaluation**: 99/100
| Critere | Points | Score |
|---------|--------|-------|
| Pertinence Conceptuelle | 25 | 25 |
| Intelligence Pedagogique | 25 | 25 |
| Originalite | 20 | 20 |
| Testabilite | 15 | 15 |
| Clarte | 15 | 14 |

**Justification**:
- 6 concepts d'entropie exhaustivement couverts
- Cas historiques (Debian, Dual_EC, Android) = apprentissage par l'echec
- Scenarios VM/embedded = problemes reels courants
- Tests statistiques avec mise en garde = nuance importante

---

## TABLEAU RECAPITULATIF DES CONCEPTS

### Sous-module 3.1.1 - Principes de securite (15 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.1.a | Triade CIA | Ex01 |
| 3.1.1.b | AAA | Ex01 |
| 3.1.1.c | Non-repudiation | Ex01 |
| 3.1.1.d | Defense in Depth | Ex01 |
| 3.1.1.e | Least Privilege | Ex01 |
| 3.1.1.f | Separation of Duties | Ex01 |
| 3.1.1.g | Zero Trust | Ex01 |
| 3.1.1.h | Attack Surface | Ex01 |
| 3.1.1.i | Threat Modeling | Ex02 |
| 3.1.1.j | Risk Assessment | Ex02 |
| 3.1.1.k | Security Controls | Ex02 |
| 3.1.1.l | Security Policies | Ex02 |
| 3.1.1.m | Security Frameworks | Ex02 |
| 3.1.1.n | Compliance | Ex02 |
| 3.1.1.o | Security Metrics | Ex02 |

### Sous-module 3.1.2 - Mathematiques crypto (12 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.2.a | Arithmetique modulaire | Ex03 |
| 3.1.2.b | PGCD et Bezout | Ex03 |
| 3.1.2.c | Inverse modulaire | Ex03 |
| 3.1.2.d | Theoreme de Fermat | Ex03 |
| 3.1.2.e | Theoreme d'Euler | Ex03 |
| 3.1.2.f | Exponentiation modulaire | Ex03 |
| 3.1.2.g | Theoreme des restes chinois | Ex04 |
| 3.1.2.h | Nombres premiers | Ex04 |
| 3.1.2.i | Groupes cycliques | Ex05 |
| 3.1.2.j | Corps finis | Ex05 |
| 3.1.2.k | Courbes elliptiques | Ex05 |
| 3.1.2.l | Attaques mathematiques | Ex05 |

### Sous-module 3.1.3 - Chiffrement symetrique (15 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.3.a | Chiffrements historiques | Ex06 |
| 3.1.3.b | One-Time Pad | Ex06 |
| 3.1.3.c | Stream Ciphers | Ex07 |
| 3.1.3.d | Block Ciphers | Ex07 |
| 3.1.3.e | DES | Ex07 |
| 3.1.3.f | 3DES | Ex07 |
| 3.1.3.g | AES | Ex07 |
| 3.1.3.h | Mode ECB | Ex07 |
| 3.1.3.i | Mode CBC | Ex07 |
| 3.1.3.j | Mode CTR | Ex07 |
| 3.1.3.k | Mode GCM | Ex08 |
| 3.1.3.l | ChaCha20-Poly1305 | Ex08 |
| 3.1.3.m | Padding | Ex08 |
| 3.1.3.n | Key Derivation | Ex08 |
| 3.1.3.o | Implementation securisee | Ex08 |

### Sous-module 3.1.4 - Chiffrement asymetrique (16 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.4.a | Concepts asymetriques | Ex09 |
| 3.1.4.b | RSA generation | Ex09 |
| 3.1.4.c | RSA chiffrement | Ex09 |
| 3.1.4.d | RSA signatures | Ex09 |
| 3.1.4.e | RSA padding | Ex09 |
| 3.1.4.f | RSA attaques | Ex09 |
| 3.1.4.g | Diffie-Hellman | Ex10 |
| 3.1.4.h | DH attaques | Ex10 |
| 3.1.4.i | ElGamal | Ex10 |
| 3.1.4.j | DSA | Ex10 |
| 3.1.4.k | ECDH | Ex11 |
| 3.1.4.l | ECDSA | Ex11 |
| 3.1.4.m | Ed25519 | Ex11 |
| 3.1.4.n | Post-quantique | Ex11 |
| 3.1.4.o | Side-channel attacks | Ex11 |
| 3.1.4.p | Implementation securisee | Ex11 |

### Sous-module 3.1.5 - Hachage et MAC (14 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.5.a | Proprietes hash | Ex12 |
| 3.1.5.b | Merkle-Damgard | Ex12 |
| 3.1.5.c | MD5 | Ex12 |
| 3.1.5.d | SHA-1 | Ex12 |
| 3.1.5.e | SHA-2 | Ex12 |
| 3.1.5.f | SHA-3 | Ex12 |
| 3.1.5.g | BLAKE2/BLAKE3 | Ex12 |
| 3.1.5.h | HMAC | Ex13 |
| 3.1.5.i | Password Hashing | Ex13 |
| 3.1.5.j | bcrypt | Ex13 |
| 3.1.5.k | scrypt | Ex13 |
| 3.1.5.l | Argon2 | Ex13 |
| 3.1.5.m | Attaques hachage | Ex13 |
| 3.1.5.n | Merkle Trees | Ex13 |

### Sous-module 3.1.6 - PKI et certificats (11 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.6.a | X.509 | Ex14 |
| 3.1.6.b | CA | Ex14 |
| 3.1.6.c | CSR | Ex14 |
| 3.1.6.d | Revocation | Ex14 |
| 3.1.6.e | Certificate Transparency | Ex14 |
| 3.1.6.f | Let's Encrypt | Ex14 |
| 3.1.6.g | Types certificats | Ex15 |
| 3.1.6.h | Formats | Ex15 |
| 3.1.6.i | OpenSSL commandes | Ex15 |
| 3.1.6.j | Web of Trust | Ex15 |
| 3.1.6.k | Pinning | Ex15 |

### Sous-module 3.1.7 - Protocoles crypto (10 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.7.a | TLS 1.2 | Ex16 |
| 3.1.7.b | TLS 1.3 | Ex16 |
| 3.1.7.c | TLS attaques | Ex16 |
| 3.1.7.d | SSH Protocol v2 | Ex16 |
| 3.1.7.e | IPsec | Ex16 |
| 3.1.7.f | WireGuard | Ex16 |
| 3.1.7.g | Signal Protocol | Ex17 |
| 3.1.7.h | Kerberos | Ex17 |
| 3.1.7.i | mTLS | Ex17 |
| 3.1.7.j | DNSSEC | Ex17 |

### Sous-module 3.1.8 - Aleatoire et entropie (6 concepts)
| ID | Concept | Exercice(s) |
|----|---------|-------------|
| 3.1.8.a | TRNG vs PRNG | Ex18 |
| 3.1.8.b | Sources entropie | Ex18 |
| 3.1.8.c | CSPRNG | Ex18 |
| 3.1.8.d | Attaques RNG | Ex18 |
| 3.1.8.e | Tests statistiques | Ex18 |
| 3.1.8.f | Best practices | Ex18 |

---

## STATISTIQUES FINALES

| Metrique | Valeur |
|----------|--------|
| **Concepts totaux** | 99 |
| **Concepts couverts** | 99 (100%) |
| **Exercices concus** | 18 |
| **Score moyen** | 97.4/100 |
| **Score minimum** | 96/100 |
| **Score maximum** | 99/100 |
| **Tous >= 95/100** | Oui |

### Distribution des scores
- 99/100 : 3 exercices (Ex11, Ex17, Ex18)
- 98/100 : 5 exercices (Ex07, Ex08, Ex09, Ex12, Ex16)
- 97/100 : 5 exercices (Ex02, Ex03, Ex05, Ex06, Ex10)
- 96/100 : 5 exercices (Ex01, Ex04, Ex14, Ex15, Ex13)

---

## NOTES DE CONCEPTION

### Philosophie
1. **Integration**: Chaque exercice couvre 4-8 concepts lies pour une comprehension systemique
2. **Realisme**: Scenarios issus de situations professionnelles reelles
3. **Profondeur**: Pas de surface - chaque concept est teste en profondeur
4. **Attaques**: La comprehension des failles est aussi importante que l'implementation
5. **Historique**: Les echecs celebres (Debian OpenSSL, PS3, etc.) comme outils pedagogiques

### Points forts
- Couverture exhaustive des 99 concepts
- Scenarios engageants et varies (CTF, audit, IoT, fintech, gouvernement)
- Equilibre theorie/pratique
- Pieges pedagogiques intelligents
- Sortie JSON testable par moulinette

### Recommandations pour l'implementation
1. Commencer par Ex03 (fondations mathematiques)
2. Les exercices de chaque sous-module sont independants
3. Ex11 (post-quantique) et Ex17 (Signal) sont les plus avances
4. Ex18 (entropie) est souvent neglige mais crucial

---

*Document genere le 2026-01-03*
*Module 3.1 - Fondamentaux Cryptographiques*
*Phase 3 - Odyssey Cybersecurite*
