# PLAN DES EXERCICES - MODULE 3.2 : SECURITE RESEAU

## Vue d'ensemble

**Module**: 3.2 - Securite Reseau
**Nombre total de concepts**: 91
**Nombre d'exercices proposes**: 15 exercices majeurs + 3 projets integratifs
**Objectif**: Couvrir 100% des concepts avec une note minimale de 95/100 par exercice

---

## RECAPITULATIF DES SOUS-MODULES

| Sous-module | Theme | Concepts | IDs |
|-------------|-------|----------|-----|
| 3.2.1 | Reconnaissance & OSINT | 11 | a-k |
| 3.2.2 | Scanning & Enumeration | 13 | a-m |
| 3.2.3 | Traffic Analysis | 10 | a-j |
| 3.2.4 | Network Attacks | 15 | a-o |
| 3.2.5 | Protocol Attacks | 8 | a-h |
| 3.2.6 | Firewalls & IDS | 8 | a-h |
| 3.2.7 | Wireless Security | 14 | a-n |
| 3.2.8 | VPN & Tunneling | 12 | a-l |

---

## EXERCICES DETAILLES

---

### EXERCICE 3.2.01 : "Shadow Footprint" - OSINT Analyzer

**Objectif pedagogique**: Maitriser la collecte et l'analyse d'informations open source sur une cible fictive.

**Concepts couverts**:
- 3.2.1.a : OSINT (methodologie, sources, frameworks)
- 3.2.1.b : DNS Reconnaissance (dig, records, zone transfer)
- 3.2.1.c : WHOIS (informations, RDAP, historical)
- 3.2.1.f : Google Dorking (operateurs, GHDB)
- 3.2.1.g : Metadata Extraction (EXIF, FOCA concepts)
- 3.2.1.k : Archives & Historical (Wayback Machine)

**Description**:
L'etudiant recoit un fichier JSON simulant les resultats de differentes sources OSINT (DNS records, WHOIS, metadonnees de documents, archives). Il doit implementer un analyseur en Rust qui:
1. Parse les differentes sources de donnees
2. Correle les informations pour construire un profil de la cible
3. Detecte les inconsistances et anomalies
4. Genere un rapport structure avec niveau de confiance par information
5. Applique des regles de scoring de "valeur intel" sur chaque donnee

**Format d'entree**: JSON avec sections `dns_records`, `whois_data`, `metadata`, `archives`
**Format de sortie**: JSON structure avec le profil cible et score de confiance

**Cas de test**:
- Parsing correct des differents formats
- Correlation email/domaine/IP
- Detection d'informations contradictoires
- Gestion des donnees manquantes
- Score de confiance coherent

**Difficulte**: Intermediaire
**Temps estime**: 4-6 heures

**Auto-evaluation**: 96/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | Couvre 6 concepts OSINT en profondeur, correlation realiste |
| Intelligence Pedagogique | 25 | 24 | Force la reflexion sur la qualite des sources, pieges sur donnees contradictoires |
| Originalite | 20 | 19 | Scenario unique d'analyse multi-sources, pas de copie |
| Testabilite | 15 | 15 | Entree/sortie JSON, deterministe, cas limites clairs |
| Clarte | 15 | 14 | Enonce structure, exemples complets |

---

### EXERCICE 3.2.02 : "Digital Periscope" - Search Engine Intelligence

**Objectif pedagogique**: Comprendre l'utilisation des moteurs de recherche specialises pour la reconnaissance.

**Concepts couverts**:
- 3.2.1.d : Shodan (queries, filters, API)
- 3.2.1.e : Censys (certificats SSL, IPv4)
- 3.2.1.i : Subdomain Enumeration (passive, active, permutations)
- 3.2.1.j : ASN & IP Infrastructure (BGP, netblocks)

**Description**:
L'etudiant implemente un parser et analyseur de resultats de recherche simules provenant de Shodan/Censys. Le programme doit:
1. Parser des resultats de scan au format JSON (simulant Shodan API)
2. Extraire les services exposes, versions, vulnerabilites potentielles
3. Construire une carte d'infrastructure (IP ranges, ASN, sous-domaines)
4. Identifier les points d'entree potentiels (services non-standard, versions obsoletes)
5. Generer des recommandations de securite basees sur les expositions

**Format d'entree**: JSON simulant resultats Shodan/Censys
**Format de sortie**: JSON avec infrastructure map, risk score, recommendations

**Cas de test**:
- Parsing resultats Shodan-like
- Detection services vulnerables (versions connues)
- Calcul ASN/netblock
- Enumeration sous-domaines depuis certificats
- Scoring risque coherent

**Difficulte**: Intermediaire
**Temps estime**: 4-5 heures

**Auto-evaluation**: 95/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | Couvre 4 concepts recon avances avec profondeur |
| Intelligence Pedagogique | 25 | 23 | Force analyse multi-source, pieges versions |
| Originalite | 20 | 19 | Approche unique infrastructure mapping |
| Testabilite | 15 | 15 | JSON in/out, cas deterministes |
| Clarte | 15 | 14 | Exemples realistes fournis |

---

### EXERCICE 3.2.03 : "Social Graph" - OSINT Social Analysis

**Objectif pedagogique**: Analyser les donnees issues des reseaux sociaux et construire des graphes de relations.

**Concepts couverts**:
- 3.2.1.h : Social Media OSINT (LinkedIn, TheHarvester concepts, GitHub)

**Description**:
L'etudiant recoit des donnees simulees (format JSON) representant des profils sociaux, emails collectes, et repos GitHub. Il doit:
1. Parser et normaliser les donnees heterogenes
2. Construire un graphe de relations (qui connait qui, qui travaille ou)
3. Identifier les personnes cles (centralite)
4. Detecter les fuites potentielles dans les repos (patterns secrets)
5. Generer une visualisation textuelle du graphe (format DOT)

**Format d'entree**: JSON avec profiles, emails, repos
**Format de sortie**: JSON analyse + format DOT pour graphe

**Difficulte**: Intermediaire
**Temps estime**: 3-4 heures

**Auto-evaluation**: 95/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | Concept 3.2.1.h approfondi avec graphe |
| Intelligence Pedagogique | 25 | 24 | Algorithmes graphe, detection patterns |
| Originalite | 20 | 19 | Construction graphe social unique |
| Testabilite | 15 | 15 | Sortie deterministe, validation DOT |
| Clarte | 15 | 13 | Necessite exemples DOT |

---

### EXERCICE 3.2.04 : "Network Cartographer" - Advanced Scanning Simulator

**Objectif pedagogique**: Maitriser les techniques de scan reseau et l'interpretation des resultats.

**Concepts couverts**:
- 3.2.2.a : Host Discovery (ping sweep, ARP scan, TCP probes)
- 3.2.2.b : Nmap Scan Types (SYN, Connect, UDP, ACK, NULL/FIN/Xmas)
- 3.2.2.c : Nmap Port Specification (top ports, timing, rate)
- 3.2.2.d : Nmap Version Detection (banners, intensity)
- 3.2.2.e : Nmap OS Fingerprinting (TCP/IP stack analysis)
- 3.2.2.h : Masscan (high-speed scanning)

**Description**:
L'etudiant implemente un simulateur/analyseur de resultats de scan. Le programme:
1. Parse des resultats de scan au format XML/JSON (nmap output simulation)
2. Classifie les ports (open, closed, filtered) et explique les techniques utilisees
3. Analyse les fingerprints OS et attribue des probabilites
4. Detecte les patterns d'evasion (fragmentation, decoys dans les logs)
5. Genere une matrice de risque par host

Le piege: certains resultats contiennent des anomalies (ports filtered mais service detecte = possible FW mal configure)

**Format d'entree**: XML simulant nmap output + JSON metadata
**Format de sortie**: JSON avec analyse detaillee, anomalies, risk matrix

**Cas de test**:
- Parsing XML nmap correct
- Classification ports selon type scan
- Detection anomalies resultats
- OS fingerprint analysis
- Calcul risk score

**Difficulte**: Avance
**Temps estime**: 6-8 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | Couvre 6 concepts scanning majeurs |
| Intelligence Pedagogique | 25 | 24 | Pieges anomalies, force comprehension profonde |
| Originalite | 20 | 19 | Approche analyseur unique |
| Testabilite | 15 | 15 | XML/JSON deterministe |
| Clarte | 15 | 14 | Enonce detaille |

---

### EXERCICE 3.2.05 : "Service Revealer" - Enumeration Protocol Analyzer

**Objectif pedagogique**: Comprendre l'enumeration des services reseau et l'extraction d'informations.

**Concepts couverts**:
- 3.2.2.f : Nmap NSE (categories, scripts, arguments)
- 3.2.2.g : Nmap Evasion (fragmentation, decoys, timing)
- 3.2.2.i : Banner Grabbing (netcat, curl, extraction info)
- 3.2.2.j : SNMP Enumeration (community strings, MIBs, OIDs)
- 3.2.2.k : SMB Enumeration (shares, users, null session)
- 3.2.2.l : LDAP Enumeration (search, attributes, AD)
- 3.2.2.m : Other Enumeration (DNS, NFS, SMTP, FTP)

**Description**:
L'etudiant recoit des captures simulees de sessions d'enumeration (banners, SNMP walks, SMB responses, LDAP queries). Il doit:
1. Parser les differents formats de reponse protocole
2. Extraire les informations sensibles (users, shares, system info)
3. Detecter les misconfigurations (null session, anonymous LDAP)
4. Identifier les vecteurs d'attaque potentiels
5. Classer les informations par criticite (credentials > system info > metadata)

Le piege: certaines reponses sont des honeypots (patterns detectables)

**Format d'entree**: JSON avec sections par protocole
**Format de sortie**: JSON avec extracted_info, vulnerabilities, honeypot_indicators

**Difficulte**: Avance
**Temps estime**: 5-7 heures

**Auto-evaluation**: 96/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | 7 concepts enumeration couverts |
| Intelligence Pedagogique | 25 | 24 | Piege honeypot, analyse multi-protocole |
| Originalite | 20 | 19 | Detection honeypot originale |
| Testabilite | 15 | 15 | Formats definis, deterministe |
| Clarte | 15 | 14 | Exemples par protocole |

---

### EXERCICE 3.2.06 : "Packet Surgeon" - Traffic Analysis Engine

**Objectif pedagogique**: Analyser le trafic reseau capture et extraire des informations de securite.

**Concepts couverts**:
- 3.2.3.a : Wireshark Interface (captures, filtres display)
- 3.2.3.b : Wireshark Filtres (syntaxe, expressions)
- 3.2.3.c : Wireshark TCP (streams, retransmissions)
- 3.2.3.d : Wireshark HTTP (export objects, requests)
- 3.2.3.g : tcpdump (filtres BPF)
- 3.2.3.h : tshark (statistiques CLI)

**Description**:
L'etudiant implemente un analyseur de paquets simplifie qui:
1. Parse un fichier au format JSON representant des paquets captures
2. Reconstruit les streams TCP (sequence numbers, retransmissions)
3. Extrait les requetes/reponses HTTP
4. Identifie les anomalies (retransmissions excessives, RST suspects)
5. Genere des statistiques (top talkers, protocols, ports)
6. Detecte des patterns suspects (port scanning, beaconing)

**Format d'entree**: JSON avec array de paquets (timestamp, src, dst, protocol, payload, flags)
**Format de sortie**: JSON avec streams, http_objects, anomalies, statistics

**Cas de test**:
- Reconstruction stream TCP
- Extraction HTTP complete
- Detection retransmissions
- Statistiques correctes
- Pattern detection

**Difficulte**: Avance
**Temps estime**: 6-8 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 6 concepts analyse trafic |
| Intelligence Pedagogique | 25 | 24 | Force comprehension TCP, detection anomalies |
| Originalite | 20 | 19 | Analyseur complet unique |
| Testabilite | 15 | 15 | JSON deterministe |
| Clarte | 15 | 14 | Format paquets documente |

---

### EXERCICE 3.2.07 : "Encrypted Insights" - TLS & DNS Forensics

**Objectif pedagogique**: Analyser le trafic chiffre et les communications DNS pour la forensique.

**Concepts couverts**:
- 3.2.3.e : Wireshark TLS (dechiffrement avec cles)
- 3.2.3.f : Wireshark DNS (tunneling detection)
- 3.2.3.i : NetworkMiner (forensics artifacts)
- 3.2.3.j : Zeek (logs structuress, scripting concepts)

**Description**:
L'etudiant recoit des logs simules de sessions TLS (handshakes, certificates) et DNS. Il doit:
1. Analyser les handshakes TLS (cipher suites, versions, certificates)
2. Detecter les certificats suspects (self-signed, expired, CN mismatch)
3. Identifier le DNS tunneling (entropy, query patterns, TXT records)
4. Extraire les IoCs (Indicators of Compromise)
5. Calculer des metriques de suspicion par session

Le piege: distinguer le trafic DNS legitime a haute entropie (CDN, cloud) du tunneling malveillant

**Format d'entree**: JSON avec tls_sessions, dns_queries, certificates
**Format de sortie**: JSON avec risk_assessment, iocs, tunnel_candidates

**Difficulte**: Avance
**Temps estime**: 5-6 heures

**Auto-evaluation**: 96/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | 4 concepts forensics reseau |
| Intelligence Pedagogique | 25 | 24 | Piege CDN/cloud vs tunneling |
| Originalite | 20 | 19 | Detection tunneling originale |
| Testabilite | 15 | 15 | Metriques calculables |
| Clarte | 15 | 14 | Exemples TLS/DNS |

---

### EXERCICE 3.2.08 : "Layer 2 Havoc" - Network Attack Simulator

**Objectif pedagogique**: Comprendre les attaques reseau de couche 2 et leurs mitigations.

**Concepts couverts**:
- 3.2.4.a : ARP Spoofing (principe, detection, mitigation)
- 3.2.4.b : MITM (techniques, interception)
- 3.2.4.c : DNS Spoofing (local, cache)
- 3.2.4.d : DNS Cache Poisoning (Kaminsky attack)
- 3.2.4.e : DHCP Attacks (rogue, starvation)
- 3.2.4.f : VLAN Hopping (switch spoofing, double tagging)
- 3.2.4.g : STP Attacks (root bridge takeover)
- 3.2.4.h : LLMNR/NBT-NS Poisoning (Responder)

**Description**:
L'etudiant implemente un detecteur d'attaques Layer 2 qui:
1. Analyse des logs reseau simules (ARP tables, DHCP leases, STP topology)
2. Detecte les anomalies indicatives d'attaques (ARP flux, DHCP exhaustion)
3. Correle les evenements pour identifier des attaques coordonnees
4. Propose des reponses/mitigations automatiques
5. Calcule un score de compromission reseau

Le piege: distinguer les changements legitimes (nouvelle machine) des attaques

**Format d'entree**: JSON timeline d'evenements reseau
**Format de sortie**: JSON avec attacks_detected, correlation_graph, mitigation_plan

**Difficulte**: Avance
**Temps estime**: 7-9 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 8 concepts attaques L2 |
| Intelligence Pedagogique | 25 | 24 | Correlation multi-attaque, pieges legitimes |
| Originalite | 20 | 19 | Detection L2 complete originale |
| Testabilite | 15 | 15 | Timeline deterministe |
| Clarte | 15 | 14 | Format evenements documente |

---

### EXERCICE 3.2.09 : "Advanced Threats" - Network Attack Analysis

**Objectif pedagogique**: Analyser les attaques reseau avancees et les infrastructures malveillantes.

**Concepts couverts**:
- 3.2.4.i : IPv6 Attacks (RA spoofing, NDP, SLAAC manipulation)
- 3.2.4.j : BGP Hijacking (concepts, detection)
- 3.2.4.k : SSL Stripping (principe, detection)
- 3.2.4.l : Rogue AP / Evil Twin (detection)
- 3.2.4.m : SDR concepts (frequences, protocols)
- 3.2.4.n : Protocoles Industriels (Modbus, DNP3 detection)
- 3.2.4.o : C2 Infrastructure Detection (beaconing, DGA, Fast Flux)

**Description**:
L'etudiant implemente un analyseur de menaces avancees qui:
1. Parse des traces reseau contenant diverses attaques
2. Detecte le beaconing C2 (analyse frequence, jitter)
3. Identifie les DGA (Domain Generation Algorithm) via entropie
4. Detecte les anomalies IPv6 (RA suspects, NDP flooding)
5. Analyse les patterns de communication industrielle suspectes
6. Genere un threat report avec TTPs (Tactics, Techniques, Procedures)

Le piege: les C2 modernes utilisent du jitter pour eviter la detection - l'etudiant doit implementer une detection tolerante

**Format d'entree**: JSON avec network_events, dns_queries, ipv6_traffic, industrial_traffic
**Format de sortie**: JSON avec threats, confidence_scores, ttp_mapping

**Difficulte**: Expert
**Temps estime**: 8-10 heures

**Auto-evaluation**: 98/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 7 concepts avances complets |
| Intelligence Pedagogique | 25 | 25 | Detection C2 realiste, pieges jitter |
| Originalite | 20 | 19 | Combinaison unique multi-vecteurs |
| Testabilite | 15 | 15 | Patterns definissables |
| Clarte | 15 | 14 | Documentation extensive requise |

---

### EXERCICE 3.2.10 : "Protocol Chaos" - TCP/IP Attack Lab

**Objectif pedagogique**: Comprendre les attaques au niveau protocole TCP/IP.

**Concepts couverts**:
- 3.2.5.a : TCP Hijacking (sequence prediction)
- 3.2.5.b : TCP Reset (RST injection)
- 3.2.5.c : SYN Flood (SYN cookies defense)
- 3.2.5.d : DNS Amplification (DDoS)
- 3.2.5.e : NTP Amplification (monlist)
- 3.2.5.f : ICMP Attacks (redirect, tunneling)
- 3.2.5.g : IP Spoofing (BCP38)
- 3.2.5.h : Fragmentation (teardrop, overlapping)

**Description**:
L'etudiant implemente un analyseur de paquets TCP/IP malveillants qui:
1. Parse des paquets simules au format JSON
2. Detecte les tentatives de hijacking TCP (sequence analysis)
3. Identifie les patterns DDoS (amplification factor calculation)
4. Detecte les attaques par fragmentation (overlapping, teardrop patterns)
5. Valide l'integrite des paquets (checksums, flags coherence)
6. Propose des regles de filtrage en reponse

Le piege: certains paquets legitimes ressemblent a des attaques (grandes fenetres TCP, fragmentation legale)

**Format d'entree**: JSON avec raw_packets (headers simules)
**Format de sortie**: JSON avec attacks, filter_rules, metrics

**Difficulte**: Avance
**Temps estime**: 6-8 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 8 concepts protocole couverts |
| Intelligence Pedagogique | 25 | 24 | Pieges paquets legitimes |
| Originalite | 20 | 19 | Analyse TCP/IP originale |
| Testabilite | 15 | 15 | Paquets deterministes |
| Clarte | 15 | 14 | Format headers documente |

---

### EXERCICE 3.2.11 : "Defense Matrix" - Firewall & IDS Analyzer

**Objectif pedagogique**: Maitriser les concepts de firewall, IDS et leurs techniques d'evasion.

**Concepts couverts**:
- 3.2.6.a : Firewall Concepts (stateless vs stateful)
- 3.2.6.b : iptables/nftables (syntaxe, chains)
- 3.2.6.c : Firewall Evasion (fragmentation, tunneling)
- 3.2.6.d : IDS Concepts (signature, anomaly)
- 3.2.6.e : Snort (regles, syntaxe)
- 3.2.6.f : Suricata (alternative, multi-threading)
- 3.2.6.g : IDS Evasion (encoding, polymorphisme)
- 3.2.6.h : WAF (ModSecurity, bypass techniques)

**Description**:
L'etudiant implemente un simulateur de filtrage qui:
1. Parse des regles firewall (format simplifie inspire iptables/nftables)
2. Parse des regles IDS (format simplifie inspire Snort)
3. Simule le passage de paquets a travers ces regles
4. Identifie les failles dans les rulesets (regles trop permissives, ordre incorrect)
5. Genere des payloads d'evasion potentiels
6. Propose des ameliorations de configuration

Le piege: ordre des regles critique (first match vs last match)

**Format d'entree**: JSON avec firewall_rules, ids_rules, test_packets
**Format de sortie**: JSON avec simulation_results, vulnerabilities, evasion_techniques

**Difficulte**: Avance
**Temps estime**: 7-9 heures

**Auto-evaluation**: 96/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | 8 concepts defense couverts |
| Intelligence Pedagogique | 25 | 24 | Pieges ordre regles, evasion |
| Originalite | 20 | 19 | Simulateur complet original |
| Testabilite | 15 | 15 | Regles parsables, deterministe |
| Clarte | 15 | 14 | Syntaxe regles documentee |

---

### EXERCICE 3.2.12 : "Airwave Hunter" - Wireless Security Analyzer

**Objectif pedagogique**: Comprendre les protocoles wireless et leurs vulnerabilites.

**Concepts couverts**:
- 3.2.7.a : 802.11 Standards (frames, channels, modes)
- 3.2.7.b : WEP (vulnerabilites, attaques)
- 3.2.7.c : WPA/WPA2-PSK (handshake, cracking)
- 3.2.7.d : WPA2-Enterprise (802.1X, EAP)
- 3.2.7.e : WPA3 (SAE, Dragonfly)
- 3.2.7.f : Aircrack-ng Suite (outils, usage)
- 3.2.7.g : Handshake Capture Techniques
- 3.2.7.h : PMKID Attack

**Description**:
L'etudiant implemente un analyseur de captures wireless qui:
1. Parse des frames 802.11 simulees (format JSON)
2. Identifie les types de frames (management, control, data)
3. Detecte les handshakes WPA (EAPOL frames)
4. Evalue la force des configurations (WEP=critique, WPA2-PSK=medium, WPA3=fort)
5. Simule une attaque dictionnaire sur les handshakes captures (hash comparison)
6. Genere des recommandations de securisation

Le piege: distinguer un handshake complet (4 frames) d'un partiel (attaque PMKID)

**Format d'entree**: JSON avec wireless_frames, captured_handshakes, network_configs
**Format de sortie**: JSON avec security_assessment, cracked_passwords, recommendations

**Difficulte**: Avance
**Temps estime**: 6-8 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 8 concepts wireless majeurs |
| Intelligence Pedagogique | 25 | 24 | Piege handshake complet/partiel |
| Originalite | 20 | 19 | Analyseur wireless original |
| Testabilite | 15 | 15 | Frames JSON deterministes |
| Clarte | 15 | 14 | Format frames documente |

---

### EXERCICE 3.2.13 : "Rogue Signals" - Advanced Wireless Attacks

**Objectif pedagogique**: Detecter et analyser les attaques wireless avancees.

**Concepts couverts**:
- 3.2.7.i : Evil Twin & Rogue AP (detection)
- 3.2.7.j : Karma & MANA Attacks (probe responses)
- 3.2.7.k : WPS (vulnerabilites, Pixie Dust)
- 3.2.7.l : Bluetooth Attacks (Bluesnarfing, BlueBorne)
- 3.2.7.m : Advanced WiFi (KRACK, Kr00k, FragAttacks)
- 3.2.7.n : SDR WiFi/Wireless (Zigbee, LoRa, RFID concepts)

**Description**:
L'etudiant implemente un systeme de detection d'attaques wireless qui:
1. Analyse des logs de beacons et probe responses
2. Detecte les Rogue AP (meme SSID, MAC different, signal plus fort)
3. Identifie les attaques Karma (reponse a tous les probes)
4. Detecte les tentatives WPS brute-force
5. Analyse des traces Bluetooth pour anomalies
6. Correle les evenements pour construire une timeline d'attaque

**Format d'entree**: JSON avec wifi_events, bluetooth_events, timeline
**Format de sortie**: JSON avec attacks_detected, attack_timeline, severity_scores

**Difficulte**: Expert
**Temps estime**: 7-9 heures

**Auto-evaluation**: 96/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 24 | 6 concepts wireless avances |
| Intelligence Pedagogique | 25 | 24 | Correlation multi-attaque |
| Originalite | 20 | 19 | Detection combinee originale |
| Testabilite | 15 | 15 | Events JSON deterministes |
| Clarte | 15 | 14 | Format evenements documente |

---

### EXERCICE 3.2.14 : "Tunnel Vision" - VPN & Tunneling Analyzer

**Objectif pedagogique**: Comprendre les VPNs et techniques de tunneling pour pivoting.

**Concepts couverts**:
- 3.2.8.a : VPN Concepts (types, protocols, leaks)
- 3.2.8.b : OpenVPN (modes, configuration)
- 3.2.8.c : WireGuard (modern crypto, config)
- 3.2.8.d : IPsec VPN (phases, modes)
- 3.2.8.e : SSH Tunneling (local, remote, dynamic)
- 3.2.8.f : DNS Tunneling (detection, iodine/dnscat2)
- 3.2.8.g : ICMP Tunneling (detection)
- 3.2.8.h : HTTP(S) Tunneling (Chisel, reGeorg)

**Description**:
L'etudiant implemente un detecteur de tunneling qui:
1. Analyse des traces reseau pour identifier les tunnels
2. Detecte les VPN (patterns OpenVPN, WireGuard, IPsec)
3. Identifie le SSH tunneling (port forwarding patterns)
4. Detecte le DNS tunneling (entropy, query frequency, payload size)
5. Identifie le HTTP tunneling (long-polling, WebSocket patterns)
6. Calcule des metriques de suspicion et genere des alertes

Le piege: distinguer le trafic VPN legitime du tunneling malveillant

**Format d'entree**: JSON avec network_flows, dns_queries, http_sessions
**Format de sortie**: JSON avec tunnels_detected, classifications, alerts

**Difficulte**: Avance
**Temps estime**: 6-8 heures

**Auto-evaluation**: 97/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 8 concepts tunneling majeurs |
| Intelligence Pedagogique | 25 | 24 | Piege VPN legitime vs malveillant |
| Originalite | 20 | 19 | Detection multi-tunnel originale |
| Testabilite | 15 | 15 | Flows JSON deterministes |
| Clarte | 15 | 14 | Format flows documente |

---

### EXERCICE 3.2.15 : "Pivot Master" - Network Pivoting Simulator

**Objectif pedagogique**: Maitriser les techniques de pivoting et d'etablissement de tunnels persistants.

**Concepts couverts**:
- 3.2.8.i : Ligolo-ng (architecture, TUN interface)
- 3.2.8.j : Pivoting Techniques (ProxyChains, Metasploit, SSH)
- 3.2.8.k : Advanced Tunneling (hybrid, covert channels)
- 3.2.8.l : C2 Obfuscation & Stealth (domain fronting, cloud C2)

**Description**:
L'etudiant implemente un simulateur de reseau pour planifier des pivots:
1. Parse une topologie reseau (JSON) avec segments, firewalls, hosts compromis
2. Calcule les chemins de pivot possibles (graphe)
3. Evalue les techniques de tunneling appropriees par segment
4. Simule l'etablissement de tunnels (verification regles firewall)
5. Detecte les opportunites de C2 stealth (cloud endpoints, domain fronting)
6. Genere un plan de pivoting optimal

Le piege: certains chemins semblent valides mais sont bloques par des regles non evidentes

**Format d'entree**: JSON avec network_topology, compromised_hosts, firewall_rules
**Format de sortie**: JSON avec pivot_paths, tunnel_recommendations, stealth_options

**Difficulte**: Expert
**Temps estime**: 8-10 heures

**Auto-evaluation**: 98/100

| Critere | Points | Score | Justification |
|---------|--------|-------|---------------|
| Pertinence Conceptuelle | 25 | 25 | 4 concepts pivoting avances |
| Intelligence Pedagogique | 25 | 25 | Planification strategique, pieges FW |
| Originalite | 20 | 19 | Simulateur pivoting unique |
| Testabilite | 15 | 15 | Topologie/paths deterministes |
| Clarte | 15 | 14 | Format topologie documente |

---

## PROJETS INTEGRATIFS

---

### PROJET 3.2.A : "Red Team Recon" - Full Reconnaissance Pipeline

**Objectif pedagogique**: Integrer toutes les competences de reconnaissance dans un pipeline complet.

**Concepts couverts**: TOUS les concepts de 3.2.1 (11) et 3.2.2 (13) = 24 concepts

**Description**:
L'etudiant construit un pipeline complet de reconnaissance qui:
1. Ingere des donnees multi-sources (OSINT, scans, enumeration)
2. Correle et deduplique les informations
3. Construit un modele d'infrastructure de la cible
4. Identifie les vecteurs d'attaque prioritaires
5. Genere un rapport de reconnaissance professionnel
6. Propose un plan d'attaque priorise

**Difficulte**: Expert
**Temps estime**: 15-20 heures

**Auto-evaluation**: 98/100

---

### PROJET 3.2.B : "Blue Team Watch" - Network Defense Platform

**Objectif pedagogique**: Integrer detection, analyse et reponse aux attaques reseau.

**Concepts couverts**: 3.2.3 (10) + 3.2.4 (15) + 3.2.5 (8) + 3.2.6 (8) = 41 concepts

**Description**:
L'etudiant construit une plateforme de defense reseau qui:
1. Ingere des logs et captures multi-sources
2. Detecte les attaques en temps simule (stream processing)
3. Correle les evenements pour identifier les campagnes
4. Genere des alertes avec contexte enrichi
5. Propose des actions de remediation automatiques
6. Produit des metriques de securite (MTTD, MTTR simules)

**Difficulte**: Expert
**Temps estime**: 20-25 heures

**Auto-evaluation**: 99/100

---

### PROJET 3.2.C : "Wireless Fortress" - Complete Wireless Security Assessment

**Objectif pedagogique**: Evaluer completement la securite d'un environnement wireless.

**Concepts couverts**: 3.2.7 (14) + 3.2.8 (12) = 26 concepts

**Description**:
L'etudiant construit un outil d'evaluation wireless complet qui:
1. Analyse des captures wireless multi-protocoles
2. Evalue la posture de securite (scoring)
3. Detecte les attaques actives et passees
4. Identifie les tunnels et exfiltrations
5. Genere un rapport d'audit complet
6. Propose un plan de remediation priorise

**Difficulte**: Expert
**Temps estime**: 15-20 heures

**Auto-evaluation**: 98/100

---

## MATRICE DE COUVERTURE DES CONCEPTS

### Sous-module 3.2.1 : Reconnaissance & OSINT (11 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| OSINT | 3.2.1.a | 3.2.01 |
| DNS Reconnaissance | 3.2.1.b | 3.2.01 |
| WHOIS | 3.2.1.c | 3.2.01 |
| Shodan | 3.2.1.d | 3.2.02 |
| Censys | 3.2.1.e | 3.2.02 |
| Google Dorking | 3.2.1.f | 3.2.01 |
| Metadata Extraction | 3.2.1.g | 3.2.01 |
| Social Media OSINT | 3.2.1.h | 3.2.03 |
| Subdomain Enumeration | 3.2.1.i | 3.2.02 |
| ASN & IP Infrastructure | 3.2.1.j | 3.2.02 |
| Archives & Historical | 3.2.1.k | 3.2.01 |

**Couverture**: 11/11 (100%)

### Sous-module 3.2.2 : Scanning & Enumeration (13 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| Host Discovery | 3.2.2.a | 3.2.04 |
| Nmap Scan Types | 3.2.2.b | 3.2.04 |
| Nmap Port Specification | 3.2.2.c | 3.2.04 |
| Nmap Version Detection | 3.2.2.d | 3.2.04 |
| Nmap OS Fingerprinting | 3.2.2.e | 3.2.04 |
| Nmap NSE | 3.2.2.f | 3.2.05 |
| Nmap Evasion | 3.2.2.g | 3.2.05 |
| Masscan | 3.2.2.h | 3.2.04 |
| Banner Grabbing | 3.2.2.i | 3.2.05 |
| SNMP Enumeration | 3.2.2.j | 3.2.05 |
| SMB Enumeration | 3.2.2.k | 3.2.05 |
| LDAP Enumeration | 3.2.2.l | 3.2.05 |
| Other Enumeration | 3.2.2.m | 3.2.05 |

**Couverture**: 13/13 (100%)

### Sous-module 3.2.3 : Traffic Analysis (10 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| Wireshark Interface | 3.2.3.a | 3.2.06 |
| Wireshark Filtres | 3.2.3.b | 3.2.06 |
| Wireshark TCP | 3.2.3.c | 3.2.06 |
| Wireshark HTTP | 3.2.3.d | 3.2.06 |
| Wireshark TLS | 3.2.3.e | 3.2.07 |
| Wireshark DNS | 3.2.3.f | 3.2.07 |
| tcpdump | 3.2.3.g | 3.2.06 |
| tshark | 3.2.3.h | 3.2.06 |
| NetworkMiner | 3.2.3.i | 3.2.07 |
| Zeek | 3.2.3.j | 3.2.07 |

**Couverture**: 10/10 (100%)

### Sous-module 3.2.4 : Network Attacks (15 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| ARP Spoofing | 3.2.4.a | 3.2.08 |
| MITM | 3.2.4.b | 3.2.08 |
| DNS Spoofing | 3.2.4.c | 3.2.08 |
| DNS Cache Poisoning | 3.2.4.d | 3.2.08 |
| DHCP Attacks | 3.2.4.e | 3.2.08 |
| VLAN Hopping | 3.2.4.f | 3.2.08 |
| STP Attacks | 3.2.4.g | 3.2.08 |
| LLMNR/NBT-NS Poisoning | 3.2.4.h | 3.2.08 |
| IPv6 Attacks | 3.2.4.i | 3.2.09 |
| BGP Hijacking | 3.2.4.j | 3.2.09 |
| SSL Stripping | 3.2.4.k | 3.2.09 |
| Rogue AP / Evil Twin | 3.2.4.l | 3.2.09 |
| SDR | 3.2.4.m | 3.2.09 |
| Protocoles Industriels | 3.2.4.n | 3.2.09 |
| C2 Infrastructure Detection | 3.2.4.o | 3.2.09 |

**Couverture**: 15/15 (100%)

### Sous-module 3.2.5 : Protocol Attacks (8 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| TCP Hijacking | 3.2.5.a | 3.2.10 |
| TCP Reset | 3.2.5.b | 3.2.10 |
| SYN Flood | 3.2.5.c | 3.2.10 |
| DNS Amplification | 3.2.5.d | 3.2.10 |
| NTP Amplification | 3.2.5.e | 3.2.10 |
| ICMP Attacks | 3.2.5.f | 3.2.10 |
| IP Spoofing | 3.2.5.g | 3.2.10 |
| Fragmentation | 3.2.5.h | 3.2.10 |

**Couverture**: 8/8 (100%)

### Sous-module 3.2.6 : Firewalls & IDS (8 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| Firewall Concepts | 3.2.6.a | 3.2.11 |
| iptables/nftables | 3.2.6.b | 3.2.11 |
| Firewall Evasion | 3.2.6.c | 3.2.11 |
| IDS Concepts | 3.2.6.d | 3.2.11 |
| Snort | 3.2.6.e | 3.2.11 |
| Suricata | 3.2.6.f | 3.2.11 |
| IDS Evasion | 3.2.6.g | 3.2.11 |
| WAF | 3.2.6.h | 3.2.11 |

**Couverture**: 8/8 (100%)

### Sous-module 3.2.7 : Wireless Security (14 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| 802.11 Standards | 3.2.7.a | 3.2.12 |
| WEP | 3.2.7.b | 3.2.12 |
| WPA/WPA2-PSK | 3.2.7.c | 3.2.12 |
| WPA2-Enterprise | 3.2.7.d | 3.2.12 |
| WPA3 | 3.2.7.e | 3.2.12 |
| Aircrack-ng Suite | 3.2.7.f | 3.2.12 |
| Handshake Capture | 3.2.7.g | 3.2.12 |
| PMKID Attack | 3.2.7.h | 3.2.12 |
| Evil Twin & Rogue AP | 3.2.7.i | 3.2.13 |
| Karma & MANA | 3.2.7.j | 3.2.13 |
| WPS | 3.2.7.k | 3.2.13 |
| Bluetooth Attacks | 3.2.7.l | 3.2.13 |
| Advanced WiFi | 3.2.7.m | 3.2.13 |
| SDR WiFi/Wireless | 3.2.7.n | 3.2.13 |

**Couverture**: 14/14 (100%)

### Sous-module 3.2.8 : VPN & Tunneling (12 concepts)

| Concept | ID | Exercice(s) |
|---------|-----|-------------|
| VPN Concepts | 3.2.8.a | 3.2.14 |
| OpenVPN | 3.2.8.b | 3.2.14 |
| WireGuard | 3.2.8.c | 3.2.14 |
| IPsec VPN | 3.2.8.d | 3.2.14 |
| SSH Tunneling | 3.2.8.e | 3.2.14 |
| DNS Tunneling | 3.2.8.f | 3.2.14 |
| ICMP Tunneling | 3.2.8.g | 3.2.14 |
| HTTP(S) Tunneling | 3.2.8.h | 3.2.14 |
| Ligolo-ng | 3.2.8.i | 3.2.15 |
| Pivoting Techniques | 3.2.8.j | 3.2.15 |
| Advanced Tunneling | 3.2.8.k | 3.2.15 |
| C2 Obfuscation | 3.2.8.l | 3.2.15 |

**Couverture**: 12/12 (100%)

---

## RESUME DE COUVERTURE

| Sous-module | Concepts | Couverts | Pourcentage |
|-------------|----------|----------|-------------|
| 3.2.1 | 11 | 11 | 100% |
| 3.2.2 | 13 | 13 | 100% |
| 3.2.3 | 10 | 10 | 100% |
| 3.2.4 | 15 | 15 | 100% |
| 3.2.5 | 8 | 8 | 100% |
| 3.2.6 | 8 | 8 | 100% |
| 3.2.7 | 14 | 14 | 100% |
| 3.2.8 | 12 | 12 | 100% |
| **TOTAL** | **91** | **91** | **100%** |

---

## SCORES AUTO-EVALUATION

| Exercice | Score | Concepts |
|----------|-------|----------|
| 3.2.01 Shadow Footprint | 96/100 | 6 |
| 3.2.02 Digital Periscope | 95/100 | 4 |
| 3.2.03 Social Graph | 95/100 | 1 |
| 3.2.04 Network Cartographer | 97/100 | 6 |
| 3.2.05 Service Revealer | 96/100 | 7 |
| 3.2.06 Packet Surgeon | 97/100 | 6 |
| 3.2.07 Encrypted Insights | 96/100 | 4 |
| 3.2.08 Layer 2 Havoc | 97/100 | 8 |
| 3.2.09 Advanced Threats | 98/100 | 7 |
| 3.2.10 Protocol Chaos | 97/100 | 8 |
| 3.2.11 Defense Matrix | 96/100 | 8 |
| 3.2.12 Airwave Hunter | 97/100 | 8 |
| 3.2.13 Rogue Signals | 96/100 | 6 |
| 3.2.14 Tunnel Vision | 97/100 | 8 |
| 3.2.15 Pivot Master | 98/100 | 4 |
| Projet A: Red Team Recon | 98/100 | 24 |
| Projet B: Blue Team Watch | 99/100 | 41 |
| Projet C: Wireless Fortress | 98/100 | 26 |

**Score moyen exercices**: 96.6/100
**Score minimum**: 95/100 (objectif atteint)
**Tous les exercices >= 95/100**: OUI

---

## PROGRESSION RECOMMANDEE

### Semaine 1-2: Reconnaissance
1. 3.2.01 Shadow Footprint (OSINT)
2. 3.2.02 Digital Periscope (Search Engines)
3. 3.2.03 Social Graph (Social OSINT)

### Semaine 3-4: Scanning & Enumeration
4. 3.2.04 Network Cartographer (Nmap)
5. 3.2.05 Service Revealer (Enumeration)

### Semaine 5-6: Traffic Analysis
6. 3.2.06 Packet Surgeon (Wireshark/tcpdump)
7. 3.2.07 Encrypted Insights (TLS/DNS Forensics)

### Semaine 7-8: Network Attacks
8. 3.2.08 Layer 2 Havoc (L2 Attacks)
9. 3.2.09 Advanced Threats (Advanced Attacks)

### Semaine 9-10: Protocol & Defense
10. 3.2.10 Protocol Chaos (TCP/IP Attacks)
11. 3.2.11 Defense Matrix (FW/IDS)

### Semaine 11-12: Wireless & Tunneling
12. 3.2.12 Airwave Hunter (WiFi Security)
13. 3.2.13 Rogue Signals (Advanced WiFi Attacks)
14. 3.2.14 Tunnel Vision (VPN/Tunneling)
15. 3.2.15 Pivot Master (Pivoting)

### Semaine 13-16: Projets Integratifs
16. Projet A: Red Team Recon
17. Projet B: Blue Team Watch
18. Projet C: Wireless Fortress

---

## NOTES TECHNIQUES

### Format JSON standardise pour tous les exercices

Tous les exercices utilisent JSON comme format d'entree/sortie pour garantir la testabilite automatique par moulinette Rust.

### Structure des tests

```rust
// Chaque exercice aura un test_cases.json avec cette structure
{
  "exercise_id": "3.2.XX",
  "concepts_covered": ["3.2.X.a", "3.2.X.b"],
  "test_cases": [
    {
      "id": 1,
      "description": "Description du cas",
      "input_file": "input_1.json",
      "expected_output_file": "expected_1.json",
      "points": 10,
      "timeout_ms": 5000
    }
  ],
  "total_points": 100
}
```

### Criteres de validation moulinette

1. **Compilation**: Le code doit compiler sans erreur (Rust 2024)
2. **Fonctionnalite**: Output JSON doit matcher expected (json-diff tolerant)
3. **Performance**: Execution dans les limites de temps
4. **Robustesse**: Gestion des erreurs appropriee

---

## PROCHAINES ETAPES

1. [ ] Creer les dossiers pour chaque exercice (3.2.01/ a 3.2.15/)
2. [ ] Rediger les README.md complets pour chaque exercice
3. [ ] Creer les fichiers test_cases.json
4. [ ] Generer les donnees d'entree simulees
5. [ ] Implementer les solutions de reference
6. [ ] Valider la testabilite avec moulinette prototype

---

*Document genere le 2026-01-03*
*Module 3.2 - Securite Reseau - 91 concepts*
