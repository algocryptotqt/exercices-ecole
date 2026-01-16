# Module 3.6 - Malware Analysis

## Exercices disponibles

### 3.6.1-a : specimen_classifier ✅ COMPLET

**Status :** Généré et validé
**Fichier :** `3.6.1-a-specimen_classifier.md`
**Lignes :** 2785
**Score Qualité :** 96/100

**Description :**
Exercice de classification de malware selon leur taxonomie (Virus, Worm, Trojan, Ransomware, Rootkit, Bootkit). L'étudiant implémente un classificateur en Python qui analyse les caractéristiques comportementales d'un binaire suspect et retourne sa classification complète avec niveau de confiance et de risque.

**Concepts couverts :**
- 3.6.1.a: Types - Virus (self-replicating, file infectors)
- 3.6.1.b: Types - Worms (network propagation)
- 3.6.1.c: Types - Trojans (RATs, backdoors)
- 3.6.1.d: Types - Ransomware (encryption, lockers)
- 3.6.1.e: Types - Rootkits (userland, kernel)
- 3.6.1.f: Types - Bootkits (MBR, UEFI)

**Caractéristiques :**
- **Langage :** Python 3.14
- **Difficulté :** 7/10 (Phase 3)
- **Durée estimée :** 45 min (base) + 20 min (bonus)
- **XP Base :** 150
- **Bonus :** 🔥 AVANCÉ (×3 XP) - Détection APT et mapping MITRE ATT&CK
- **Référence culture :** Mr. Robot (Elliot classifiant malwares)
- **MEME :** "I am Mr. Robot" + 5 autres memes pédagogiques

**Sections complètes :**
1. ✅ Thinking (analyse conceptuelle)
2. ✅ Prototype & Consigne
3. ✅ Le Saviez-Vous + Dans la Vraie Vie
4. ✅ Exemple d'utilisation bash
5. ✅ Zone correction (solution + 5 mutants)
6. ✅ Comprendre (cours complet 200+ lignes)
7. ✅ Pièges — Récapitulatif
8. ✅ QCM (10 questions)
9. ✅ Récapitulatif + Deployment Pack

**Tests validés :**
- ✅ 8 tests de base (virus, worm, trojan, ransomware, rootkit, bootkit, hybride, edge cases)
- ✅ 5 mutants (boundary, safety, resource, logic, return)
- ✅ Solution de référence fonctionnelle
- ✅ Alternative (approche IF-ELIF)
- ✅ Solution bonus complète (APT + MITRE)

**Visualisations :**
- ✅ Architecture de classification (ASCII art)
- ✅ Matrice de scoring
- ✅ Timeline de propagation worm vs virus
- ✅ Diagramme Mermaid (logique de sécurité)
- ✅ Boot sequence hijacking

**Pédagogie :**
- ✅ LDA (Langage de Description d'Algorithmes) en MAJUSCULES
- ✅ Style académique universitaire français
- ✅ Logic Flow (Structured English)
- ✅ Trace d'exécution complète (26 étapes)
- ✅ 6 mnémotechniques avec memes
- ✅ 4 cas d'usage pratiques (SOC, Threat Intel, Playbook, Reporting)

**Conformité HACKBRAIN v5.5.2 :**
- ✅ Section 0 : Thinking obligatoire AVANT contenu
- ✅ En-tête strict (un champ par ligne)
- ✅ Système de TIERS (Tiers 1 : Concept isolé)
- ✅ 6 paliers bonus (🔥 AVANCÉ)
- ✅ Session bash minimaliste ($ uniquement)
- ✅ MEME obligatoire (Mr. Robot)
- ✅ spec.json ENGINE v22.1
- ✅ Neutralité (pas de mention de cible)
- ✅ Normes avec explications pédagogiques

**Applications métiers :**
- Malware Analyst (analyse approfondie)
- SOC Analyst L2-L3 (triage et réponse)
- Threat Intelligence Analyst (attribution APT)
- Incident Responder (gestion de crises)
- Security Engineer (automatisation détection)

**Ressources complémentaires suggérées :**
- MITRE ATT&CK : https://attack.mitre.org/
- VirusTotal : https://www.virustotal.com/
- Hybrid Analysis : https://www.hybrid-analysis.com/
- "Practical Malware Analysis" (Sikorski, Honig)
- GREM Certification (GIAC Reverse Engineering Malware)

---

## Structure du module 3.6

```
3.6 — Malware Analysis
│
├── 3.6.1 — Malware Fundamentals
│   ├── 3.6.1-a : specimen_classifier ✅
│   ├── 3.6.1-b : static_analyzer (TODO)
│   ├── 3.6.1-c : sandbox_runner (TODO)
│   └── ...
│
├── 3.6.2 — Behavioral Analysis (TODO)
├── 3.6.3 — Signature Creation (TODO)
└── 3.6.4 — Memory Forensics (TODO)
```

---

## Commandes utiles

### Tester l'exercice
```bash
cd /home/many/ecoleexos/phase3/exercices/module_3.6
python3 specimen_classifier.py < tests/test_samples.json
```

### Valider le spec.json
```bash
python3 hackbrain_engine_v22.py --validate-spec spec.json
```

### Tester la solution de référence
```bash
python3 hackbrain_engine_v22.py -s spec.json -f references/ref_specimen_classifier.py
```

### Tester les mutants
```bash
python3 hackbrain_mutation_tester.py -r references/ref_specimen_classifier.py -s spec.json --validate
```

---

## Statistiques

- **Exercices générés :** 1/15+
- **Lignes de code (total) :** 2785
- **Lignes de cours :** ~1200 (Section 5)
- **Questions QCM :** 10
- **Mutants :** 5
- **Memes pédagogiques :** 6
- **Cas d'usage réels :** 4
- **Diagrammes :** 5 (ASCII + Mermaid)

---

*Généré le 2026-01-15 par HACKBRAIN v5.5.2*
*Compatible ENGINE v22.1 + Mutation Tester*
