# 📋 HACKBRAIN GRADER v3.0 — SYSTÈME D'ÉVALUATION EXHAUSTIF ULTIME

> **Version :** 3.0.0 — STATE OF THE ART FINAL
> **Compatible :** HACKBRAIN Prompt v5.5.2 + ENGINE v22.1 + Mutation Tester
> **Auteur :** The Hackbrain Company
> **Philosophie :** L'excellence pédagogique ne se négocie pas — pas de raccourcis

---

## 🎯 ÉNONCÉ DE MISSION HACKBRAIN

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   CRÉER DES EXERCICES QUI RENDENT LA RÉUSSITE PAR HASARD IMPOSSIBLE         │
│                                                                             │
│   ✅ Un exercice réussi = concept COMPRIS                                   │
│   ✅ Un exercice échoué = feedback PRÉCIS sur ce qui manque                 │
│   ❌ Un exercice copier-collable = ÉCHEC de conception                      │
│   ❌ Un testeur qui valide du code buggé = ÉCHEC du testeur                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Vérifications Anti-Hasard (à valider AVANT notation)

| Critère Anti-Hasard | OK |
|---------------------|-----|
| L'exercice ne peut PAS être résolu par copier-coller d'internet | □ |
| Les tests détectent TOUTES les solutions buggées (mutants) | □ |
| Un étudiant qui réussit a FORCÉMENT compris le concept | □ |
| Le feedback d'échec indique PRÉCISÉMENT ce qui manque | □ |

---

## 🏆 CRITÈRES DE QUALITÉ PREMIUM

> Ce grader vérifie que l'exercice est de qualité PREMIUM, pas juste "ok" ou "pas mal".

| Critère Premium | Description | Section |
|-----------------|-------------|---------|
| **Autonomie étudiante** | Sections 1-3 suffisantes pour faire l'exercice SEUL | D |
| **Analogies recherchées** | Pas foireuses, avec un SENS LOGIQUE | G |
| **Double énoncé** | Fun (2.4.1) + Académique (2.4.2) | G |
| **Consignes exhaustives** | Autant d'explications que nécessaire (surtout projets) | D |
| **Format universel** | Testable par TOUT LE MONDE, pas juste une IA | D.1 |
| **Pas de commentaires obligatoires** | Liberté de l'étudiant | D.1 |
| **Moulinette complète** | TOUT le code fourni et fonctionnel | I |
| **Mutants concrets** | CODE COMPLET, pas juste description | I.4 |

---

## 🎯 SCORE GLOBAL : /100

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   NOTE FINALE : ___/100                                                     │
│                                                                             │
│   VERDICT :                                                                 │
│   □ ✅ PUBLICATION AUTORISÉE (100/100 UNIQUEMENT)                           │
│   □ ❌ REJET — CORRIGER ET RESOUMETTRE (<100/100)                           │
│                                                                             │
│   ⚠️ RÈGLE ABSOLUE : Score <100 = NON PUBLIABLE                             │
│                                                                             │
│   L'EXCELLENCE N'A PAS DE RACCOURCIS.                                       │
│   99/100 = ÉCHEC. SEUL 100/100 EST ACCEPTABLE.                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 RÉPARTITION DES POINTS (100 points)

| Section | Points | Description |
|---------|--------|-------------|
| **A. Phase de Réflexion (Thinking)** | 8 | Bloc thinking + checklist A-G complète |
| **B. En-tête Obligatoire** | 8 | 12 champs format strict |
| **C. Structure des 9 Sections** | 6 | Présence et ordre strict |
| **D. Section 1 : Prototype & Consigne** | 10 | Autonomie étudiante |
| **E. Section 2 : Le Saviez-Vous + Vraie Vie** | 4 | Contexte professionnel |
| **F. Section 3 : Exemple Bash + Bonus** | 8 | Format minimaliste + bonus complet |
| **G. Analogies : Double Énoncé 2.4** | 12 | Fun (2.4.1) + Académique (2.4.2) |
| **H. Section 5 : Cours Complet** | 12 | LDA, Logic Flow, ASCII, Normes, Traces |
| **I. Section 4 : Zone Correction** | 16 | 10 sous-sections + spec.json + mutants |
| **J. Section 9 : Deployment Pack** | 6 | JSON complet + cohérence |
| **K. Cohérence Globale & Règles** | 10 | Phase, Tiers, Anti-Wrapper, Originalité |
| **TOTAL** | **100** | |

---

# SECTION A : PHASE DE RÉFLEXION — THINKING (8 points)

> **RÈGLE ABSOLUE :** Pas de contenu sans thinking préalable.
> Si l'output commence par "# Exercice" SANS bloc `<thinking>` → ÉCHEC IMMÉDIAT.

## A.1 — Présence du Bloc Thinking (2 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| Bloc `<thinking>` présent AVANT tout contenu | □ | /0.5 |
| Bloc `</thinking>` fermé correctement | □ | /0.5 |
| Aucun contenu d'exercice avant le thinking | □ | /0.5 |
| Thinking contient une vraie analyse, pas du texte générique | □ | /0.5 |

**Score A.1 : ___/2**

---

## A.2 — Checklist de Réflexion Complète A-G (6 points)

### A. Analyse du Concept (0.8 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Concept nommé explicitement | □ | /0.2 |
| Phase demandée identifiée | □ | /0.2 |
| Adapté à la phase ? (OUI/NON + justification) | □ | /0.2 |
| Enseignable en un seul exercice ? (sinon découper) | □ | /0.2 |

### B. Combo Base + Bonus (1 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Exercice de base décrit (UN concept clair) | □ | /0.2 |
| Bonus = VARIANTE (pas nouvel exercice) | □ | /0.2 |
| Bonus ajoute une dimension (complexité, cas) | □ | /0.2 |
| Progression base → bonus logique | □ | /0.2 |
| Palier bonus identifié (⚡🔥💀🧠☠️🔮) | □ | /0.2 |

### C. Prérequis & Difficulté (1 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Prérequis VRAIMENT nécessaires listés | □ | /0.2 |
| Prérequis couverts par exercices précédents ? | □ | /0.2 |
| Difficulté correspond à la phase ? | □ | /0.2 |
| Débutant de cette phase peut le faire ? | □ | /0.2 |
| Difficulté estimée (N/10) explicite | □ | /0.2 |

### D. Cohérence Pédagogique (0.8 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Enseigne le FOND, pas juste la FORME | □ | /0.2 |
| Étudiant comprendra POURQUOI il fait ça | □ | /0.2 |
| Exercice FUN ou au moins INTÉRESSANT | □ | /0.2 |
| MEME/référence culture pop identifié | □ | /0.2 |

### E. Vérification Anti-Hérésie (0.8 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Complexité temps/espace cohérente avec phase | □ | /0.2 |
| Exercice ne demande PAS un wrapper vide | □ | /0.2 |
| AU MOINS une décision (if/else/boucle) requise | □ | /0.2 |
| Contexte ancré dans le réel ou culture pop | □ | /0.2 |

### F. Scénarios d'Échec (1.2 points)

| Critère | Présent | Concret | Points |
|---------|---------|---------|--------|
| Mutant A (Boundary) décrit avec CODE | □ | □ | /0.24 |
| Mutant B (Safety) décrit avec CODE | □ | □ | /0.24 |
| Mutant C (Resource) décrit avec CODE | □ | □ | /0.24 |
| Mutant D (Logic) décrit avec CODE | □ | □ | /0.24 |
| Mutant E (Return) décrit avec CODE | □ | □ | /0.24 |

> **ATTENTION :** "tu dois mettre les vrais mutants pas des idées approximatives on veut du concret"

### G. Validation Finale (0.4 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Verdict explicite (VALIDE/À MODIFIER/REJETER) | □ | /0.2 |
| Si "À modifier" : changements listés | □ | /0.2 |

**Score A.2 : ___/6**

**SCORE TOTAL SECTION A : ___/8**

---

# SECTION B : EN-TÊTE OBLIGATOIRE (8 points)

> Format strict — UN CHAMP PAR LIGNE

## B.1 — Les 12 Champs Obligatoires

| Champ | Présent | Format Correct | Points |
|-------|---------|----------------|--------|
| `# Exercice [X.X.X-y] : [nom_fonction]` | □ | □ | /0.7 |
| `**Module :** X.X.X — Nom du Module` | □ | □ | /0.6 |
| `**Concept :** [lettre] — Nom du Concept` | □ | □ | /0.6 |
| `**Difficulté :** [★★★...] ([N]/10)` | □ | □ | /0.7 |
| `**Type :** (9 types valides)` | □ | □ | /0.7 |
| `**Tiers :** 1\|2\|3 — Description` | □ | □ | /0.7 |
| `**Langage :** + VERSION OBLIGATOIRE` | □ | □ | /0.7 |
| `**Prérequis :** Liste ou "Aucun"` | □ | □ | /0.6 |
| `**Domaines :** Codes valides (21 codes)` | □ | □ | /0.6 |
| `**Durée estimée :** [N] min` | □ | □ | /0.6 |
| `**XP Base :** [N]` | □ | □ | /0.5 |
| `**Complexité :** T[N] O(?) × S[N] O(?)` | □ | □ | /0.6 |

**Score B.1 : ___/8**

### Vérifications de Cohérence Obligatoires

#### Système de Difficulté (Étoiles)

| Niveau | Affichage EXACT Attendu |
|--------|-------------------------|
| 1/10 | ★☆☆☆☆☆☆☆☆☆ |
| 2/10 | ★★☆☆☆☆☆☆☆☆ |
| 3/10 | ★★★☆☆☆☆☆☆☆ |
| 4/10 | ★★★★☆☆☆☆☆☆ |
| 5/10 | ★★★★★☆☆☆☆☆ |
| 6/10 | ★★★★★★☆☆☆☆ |
| 7/10 | ★★★★★★★☆☆☆ |
| 8/10 | ★★★★★★★★☆☆ |
| 9/10 | ★★★★★★★★★☆ |
| 10/10 | ★★★★★★★★★★ |
| 11-15/10 | 🧠 |
| 16-20/10 | 🧠🧠 |
| 21-25/10 | ☠️ |
| 26-30/10 | ☠️☠️ |
| 31-35/10 | 🔮 |
| 36-40/10 | 🔮🔮 |

#### 9 Types d'Exercices Valides

| Code | Nom | Description |
|------|-----|-------------|
| `qcm` | QCM Pur | Questions théoriques, 10 réponses (A-J) chacune |
| `code` | Code Pur | Fonction à implémenter |
| `cours_qcm` | Cours + QCM | Théorie puis vérification par QCM |
| `cours_code` | Cours + Code | Explication puis implémentation |
| `complet` | Cours + QCM + Code | Package complet |
| `pratique` | Pratique Pur | Exercice de pratique |
| `cours_qcm_pratique` | Cours + QCM + Pratique | Théorie puis QCM et pratique |
| `cours_pratique_code` | Cours + Code + Pratique | Explication puis implémentation et pratique |
| `complet_2` | Package complet 2 | Cours + QCM + Code + Pratique |

#### 21 Codes de Domaines Valides

| Catégorie | Codes |
|-----------|-------|
| **MATHS** | MD, AL, Calcul, Probas |
| **PHYSIQUE** | Méca, Optique, Ondes, Thermo |
| **HARDWARE** | CPU, ASM, Électro |
| **THÉORIE INFO** | Encodage, Compression, Crypto |
| **SYSTÈME** | FS, Mem, Process, Net |
| **ALGO** | Tri, Struct, DP |

#### Versions de Langage Obligatoires

| Langage | Version Obligatoire |
|---------|---------------------|
| C | C17 |
| Python | Python 3.14 |
| Rust | Rust Edition 2024 |

**SCORE TOTAL SECTION B : ___/8**

---

# SECTION C : STRUCTURE DES 9 SECTIONS (6 points)

## C.1 — Présence et Ordre Strict

| Section | Emoji | Titre | Présente | Ordre | Points |
|---------|-------|-------|----------|-------|--------|
| 1 | 📐 | Prototype & Consigne | □ | □ | /0.7 |
| 2 | 💡 | Le Saviez-Vous ? + 2.5 Dans la Vraie Vie | □ | □ | /0.6 |
| 3 | 🖥️ | Exemple d'Utilisation | □ | □ | /0.7 |
| 4 | ✅❌ | Zone Correction (10 sous-sections) | □ | □ | /0.8 |
| 5 | 🧠 | Comprendre (Cours Complet) | □ | □ | /0.7 |
| 6 | ⚠️ | Pièges — Récapitulatif | □ | □ | /0.5 |
| 7 | 📝 | QCM (si type le requiert) | □ | □ | /0.5 |
| 8 | 📊 | Récapitulatif | □ | □ | /0.5 |
| 9 | 📦 | Deployment Pack | □ | □ | /1.0 |

**Score C.1 : ___/6**

---

## C.2 — Détail Sections 6, 7, 8 (Points inclus dans C.1)

### Section 6 : ⚠️ Pièges — Récapitulatif

| Critère | Présent |
|---------|---------|
| Liste des pièges courants du concept | □ |
| Cohérence avec Section 5.4 | □ |
| Format clair (bullet points ou tableau) | □ |

### Section 7 : 📝 QCM (si type le requiert)

| Critère | Présent |
|---------|---------|
| QCM présent SI type = qcm, cours_qcm, complet, cours_qcm_pratique, complet_2 | □ |
| Chaque question a EXACTEMENT 10 réponses (A-J) | □ |
| Une seule bonne réponse par question | □ |
| Questions testent la COMPRÉHENSION, pas la mémorisation | □ |
| Réponses suffisamment différentes (pas de pièges mesquins) | □ |

### Section 8 : 📊 Récapitulatif

| Critère | Présent |
|---------|---------|
| Résumé des points clés de l'exercice | □ |
| Ce qu'il faut retenir | □ |
| Liens vers exercices suivants (si applicable) | □ |

**SCORE TOTAL SECTION C : ___/6**

---

# SECTION D : SECTION 1 — PROTOTYPE & CONSIGNE (10 points)

> **PRINCIPE FONDAMENTAL :**
> L'étudiant qui n'a JAMAIS fait l'exercice doit pouvoir le réaliser
> en lisant UNIQUEMENT les sections 1 à 3. TOUT doit être explicite.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   TEST D'AUTONOMIE ÉTUDIANTE                                                │
│                                                                             │
│   Imagine un étudiant qui :                                                 │
│   • N'a JAMAIS vu cet exercice                                             │
│   • N'a accès qu'aux sections 1, 2, 3                                      │
│   • Ne peut PAS te poser de questions                                      │
│                                                                             │
│   Question : Peut-il réaliser l'exercice à 100% ?                          │
│   → Si NON : Les consignes sont INSUFFISANTES → ÉCHEC                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Distinction Exercice Simple vs Projet (Tiers 3 / Synthèse)

| Type | Longueur Consigne | Niveau Détail | Architecture |
|------|-------------------|---------------|--------------|
| **Exercice simple** (Tiers 1) | Courte (1-2 paragraphes) | Basique | Non requise |
| **Exercice composé** (Tiers 2) | Moyenne (3-5 paragraphes) | Intermédiaire | Optionnelle |
| **Projet / Synthèse** (Tiers 3) | **AUSSI LONGUE QUE NÉCESSAIRE** | **EXHAUSTIF** | **OBLIGATOIRE** |

> **RÈGLE PROJET :** Si l'exercice ressemble plus à un PROJET qu'à un exercice,
> il faut AUTANT d'explications que nécessaire. On veut du PREMIUM, pas du bancal.

## D.1 — Section 1.1 : Obligations (3 points)

| Critère | Présent | Clair | Points |
|---------|---------|-------|--------|
| Nom du fichier à rendre explicite | □ | □ | /0.5 |
| Fonctions autorisées listées | □ | □ | /0.5 |
| Fonctions interdites listées | □ | □ | /0.5 |
| Cohérence avec `norm.allowed_functions` | □ | □ | /0.5 |
| Cohérence avec `norm.forbidden_functions` | □ | □ | /0.5 |
| **PAS de demande de commentaires obligatoires** | □ | □ | /0.5 |

### Règle Format de Réponse Universel

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   FORMAT DE RÉPONSE = TESTABLE PAR TOUT LE MONDE, PAS JUSTE UNE IA          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ✅ CE QU'ON PEUT DEMANDER :                                               │
│   • Fonction qui retourne une valeur précise                               │
│   • Code qui compile avec gcc -Wall -Wextra -Werror                        │
│   • QCM avec réponses A-J                                                  │
│   • Sortie stdout vérifiable                                               │
│                                                                             │
│   ❌ CE QU'ON NE PEUT PAS DEMANDER :                                        │
│   • "Explique ton raisonnement" (subjectif)                                │
│   • "Commente ton code" (liberté de l'étudiant)                            │
│   • Formats que seule une IA peut évaluer                                  │
│   • Réponses ouvertes non vérifiables automatiquement                      │
│                                                                             │
│   La moulinette est un SCRIPT, pas une IA.                                 │
│   Tout doit être vérifiable AUTOMATIQUEMENT.                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Score D.1 : ___/3**

---

## D.2 — Section 1.2 : Consigne (5 points)

| Critère | Présent | Clair | Points |
|---------|---------|-------|--------|
| **🎮 Contexte fun** (référence culture pop) | □ | □ | /0.5 |
| Description engageante du problème | □ | □ | /0.5 |
| **"Ta mission :"** clairement énoncée | □ | □ | /0.5 |
| **Entrée :** TOUS paramètres (type + rôle + contraintes) | □ | □ | /0.6 |
| **Sortie :** TOUTES valeurs de retour documentées | □ | □ | /0.6 |
| **Contraintes :** en français SIMPLE | □ | □ | /0.5 |
| **Exemples :** tableau Appel/Retour/Explication | □ | □ | /0.6 |
| Exemples couvrent : normal + edge + erreur (min 3) | □ | □ | /0.4 |
| Langage accessible (pas de jargon non expliqué) | □ | □ | /0.4 |
| Consigne AUSSI LONGUE QUE NÉCESSAIRE | □ | □ | /0.4 |

### Critères Supplémentaires pour PROJETS (Tiers 3 / Synthèse)

> Si l'exercice est un Tiers 3 ou ressemble à un projet, ces critères sont OBLIGATOIRES :

| Critère Projet | Présent | Points (inclus dans D.2) |
|----------------|---------|--------------------------|
| Architecture globale expliquée | □ | — |
| Ordre de développement suggéré | □ | — |
| Dépendances entre fonctions clarifiées | □ | — |
| Exemples d'utilisation du projet final | □ | — |
| Critères de succès explicites | □ | — |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   RÈGLE PROJET / TIERS 3                                                    │
│                                                                             │
│   Si l'exercice est complexe (Tiers 3, synthèse, mini-projet) :            │
│                                                                             │
│   → La consigne doit être EXHAUSTIVE                                       │
│   → On préfère TROP d'explications que PAS ASSEZ                           │
│   → L'étudiant ne doit JAMAIS être perdu                                   │
│   → On veut du PREMIUM, pas du bancal                                      │
│                                                                             │
│   "Autant d'explications que nécessaire" = parfois 2-3 pages               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Score D.2 : ___/5**

---

## D.3 — Section 1.3 : Prototype (2 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| Prototype complet et syntaxiquement correct | □ | /0.5 |
| Types de paramètres explicites | □ | /0.5 |
| Type de retour explicite | □ | /0.5 |
| Cohérence avec `function.prototype` (spec.json) | □ | /0.5 |

**Score D.3 : ___/2**

**SCORE TOTAL SECTION D : ___/10**

---

# SECTION E : SECTION 2 — LE SAVIEZ-VOUS + DANS LA VRAIE VIE (4 points)

## E.1 — Section 2 : Le Saviez-Vous ? (2 points)

| Critère | Présent | Points |
|---------|---------|--------|
| Section présente | □ | /0.5 |
| Information intéressante et pertinente | □ | /0.5 |
| Lien avec le concept enseigné | □ | /0.5 |
| Ajoute de la valeur pédagogique | □ | /0.5 |

**Score E.1 : ___/2**

---

## E.2 — Section 2.5 : Dans la Vraie Vie (2 points)

| Critère | Présent | Points |
|---------|---------|--------|
| Section 2.5 présente | □ | /0.5 |
| Analyse du Domaine de l'exercice | □ | /0.5 |
| Métier concret mentionné (DevOps, Data Scientist, etc.) | □ | /0.5 |
| Cas d'usage PRÉCIS expliqué | □ | /0.5 |

**Score E.2 : ___/2**

**SCORE TOTAL SECTION E : ___/4**

---

# SECTION F : SECTION 3 — EXEMPLE BASH + BONUS (8 points)

## F.1 — Section 3.0 : Session Bash MINIMALISTE (4 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| Commence par `$ ls` avec fichiers attendus | □ | /0.4 |
| `$ gcc -Wall -Wextra -Werror` présent | □ | /0.4 |
| Fichiers compilés cohérents avec Section 1.1 | □ | /0.4 |
| `$ ./test` avec sorties visibles | □ | /0.4 |
| Sorties claires (OK/KO, pas de verbosité) | □ | /0.4 |
| **PAS de `$ cat`** du fichier source | □ | /0.4 |
| **PAS de prototype** visible | □ | /0.4 |
| **PAS de commentaires** "// Ton code ici" | □ | /0.4 |
| **PAS de notes** "le main sera fourni" | □ | /0.4 |
| **PAS de noms d'utilisateurs** (music@, user@) | □ | /0.4 |

**Score F.1 : ___/4**

---

## F.2 — Section 3.1 : BONUS Complet (4 points)

### F.2.1 — En-tête Bonus (1.5 points)

| Critère | Présent | Correct | Points |
|---------|---------|---------|--------|
| Palier bonus (⚡🔥💀🧠☠️🔮) | □ | □ | /0.25 |
| **Difficulté Bonus :** [★] ou emoji | □ | □ | /0.25 |
| **Récompense :** XP ×[multiplicateur] | □ | □ | /0.25 |
| **Time Complexity attendue :** O(?) | □ | □ | /0.25 |
| **Space Complexity attendue :** O(?) | □ | □ | /0.25 |
| **Domaines Bonus :** si nouveaux | □ | □ | /0.25 |

### F.2.2 — Section 3.1.1 : Consigne Bonus (1.5 points)

| Critère | Présent | Points |
|---------|---------|--------|
| Contexte fun qui ÉTEND l'exercice de base | □ | /0.25 |
| **"Ta mission :"** pour le bonus | □ | /0.25 |
| **Entrée/Sortie** du bonus décrites | □ | /0.25 |
| **Contraintes** en encadré mathématique | □ | /0.25 |
| **Exemples** spécifiques au bonus | □ | /0.25 |
| Prototype bonus (3.1.2) | □ | /0.25 |

### F.2.3 — Section 3.1.3 : Ce qui Change (1 point)

| Critère | Présent | Points |
|---------|---------|--------|
| Tableau comparatif Base vs Bonus | □ | /0.25 |
| Ligne "Paramètres" comparée | □ | /0.25 |
| Ligne "Complexité" comparée | □ | /0.25 |
| Ligne "Edge cases" comparée | □ | /0.25 |

**Score F.2 : ___/4**

### Table des Paliers Bonus (Vérification)

| Palier | Icône | Multiplicateur | Difficulté Base | Exemples de Défis |
|--------|-------|----------------|-----------------|-------------------|
| STANDARD | ⚡ | ×2 | 1-5/10 | One-liner, récursif pur, sans variable temporaire |
| AVANCÉ | 🔥 | ×3 | 6-7/10 | Sans malloc intermédiaire, bitwise only, tail recursion |
| EXPERT | 💀 | ×4 | 8-10/10 | O(1) au lieu de O(n), zero-copy, lock-free |
| GÉNIE | 🧠 | ×6 | 11-20/10 | Algorithme non-documenté, preuve formelle requise |
| IMPOSSIBLE | ☠️ | ×10 | 21-30/10 | Battre complexité théorique, solution inédite |
| WIZARD | 🔮 | ×20 | 31-40/10 | Contribution majeure, digne de publication |

**SCORE TOTAL SECTION F : ___/8**

---

# SECTION G : ANALOGIES — DOUBLE ÉNONCÉ 2.4 (12 points)

> **DOUBLE EXIGENCE OBLIGATOIRE :**
> 1. Section 2.4.1 : Analogie FUN et INTELLIGENTE (pas foireuse)
> 2. Section 2.4.2 : Énoncé ACADÉMIQUE équivalent (style Académie Française)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   QUALITÉ PREMIUM DES ANALOGIES                                             │
│                                                                             │
│   On veut des analogies RECHERCHÉES, pas la première idée venue.           │
│                                                                             │
│   ❌ ANALOGIES FOIREUSES (ÉCHEC) :                                          │
│   • "C'est comme un truc qui fait un machin" (vague)                       │
│   • Analogie qui n'explique RIEN du concept                                │
│   • Référence obscure SANS explication                                     │
│   • Cliché répété 1000 fois (Mario qui saute = if/else)                    │
│                                                                             │
│   ✅ ANALOGIES PREMIUM (SUCCÈS) :                                           │
│   • Le parallèle est ÉVIDENT et aide à COMPRENDRE                          │
│   • La référence est ORIGINALE ou utilisée de façon NOUVELLE               │
│   • L'étudiant se souviendra du concept GRÂCE à l'analogie                 │
│   • Preuve de RECHERCHE (pas juste la première idée)                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## G.1 — Section 2.4.1 : Analogie Fun (7 points)

### G.1.1 — Pertinence Logique (4 points)

| Critère | Note /5 | ×0.2 | Points |
|---------|---------|------|--------|
| L'analogie explique VRAIMENT le concept | /5 | | /1 |
| Lien analogie ↔ code ÉVIDENT | /5 | | /1 |
| Aide à MÉMORISER le concept | /5 | | /1 |
| Pas FORCÉE ou artificielle | /5 | | /1 |

### G.1.2 — Originalité & Recherche (3 points)

| Critère | Note /5 | ×0.15 | Points |
|---------|---------|-------|--------|
| Référence non-cliché | /5 | | /0.75 |
| Source variée (anime/film/meme/jeu/niche) | /5 | | /0.75 |
| Référence ADAPTÉE (pas générique) | /5 | | /0.75 |
| Preuve de RECHERCHE (pas première idée) | /5 | | /0.75 |

**Score G.1 : ___/7**

### Échelle de Pertinence des Analogies

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5/5 — GÉNIE : L'analogie EST le concept. Impossible de l'oublier.          │
│       Le parallèle fonctionne sur PLUSIEURS niveaux.                       │
│       Exemples : "Schrödinger's pointer", "Hasta la vista, baby"           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4/5 — EXCELLENT : Lien fort et immédiat, aide réellement.                  │
│       Exemples : "You shall not pass", "Luffy vérifie son chapeau"         │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3/5 — CORRECT : Le lien existe mais demande explication.                   │
│       Acceptable mais pas mémorable. → RÉVISION RECOMMANDÉE                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2/5 — FAIBLE : Lien ténu, n'aide pas vraiment.                             │
│       → ÉCHEC — Note < 100/100                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1/5 — RATÉ : Analogie forcée, contre-productive.                           │
│       → ÉCHEC IMMÉDIAT                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 0/5 — ABSENT : Pas d'analogie.                                             │
│       → ÉCHEC IMMÉDIAT                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Sources d'Inspiration Autorisées (du plus connu au NICHE)

| Source | Exemples |
|--------|----------|
| **Culture Internet** | Memes, running gags, références virales |
| **Mangas/Anime** | One Piece, Naruto, JoJo, mais aussi NICHE (Steins;Gate, etc.) |
| **Films/Séries** | Terminator, Matrix, mais aussi films obscurs si pertinents |
| **Jeux vidéo** | Zelda, Dark Souls, mais aussi jeux indés |
| **Culture geek** | D&D, comics, SF classique |
| **NICHE autorisée** | Si l'analogie est PARFAITE, le moins connu est OK |

> **RÈGLE :** Le plus important est le FOND (l'analogie est-elle parfaite ?) pas la FORME (est-ce connu ?)

### Règle des Tests 100% Déterministes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   ⚠️ AUCUNE IA DANS LE TESTEUR — TESTS 100% DÉTERMINISTES                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ❌ INTERDIT dans les exercices :                                          │
│   • "Explique pourquoi..." (non vérifiable automatiquement)                │
│   • "Décris en tes mots..." (subjectif)                                    │
│   • Toute réponse ouverte                                                  │
│                                                                             │
│   ✅ AUTORISÉ :                                                             │
│   • Code avec entrée/sortie déterministe                                   │
│   • QCM avec réponses fixes (A-J)                                          │
│   • Valeurs de retour vérifiables                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## G.2 — Section 2.4.2 : Énoncé Académique (4 points)

| Critère | Présent | Correct | Points |
|---------|---------|---------|--------|
| Section 2.4.2 PRÉSENTE (obligatoire) | □ | □ | /1 |
| Vocabulaire académique (français soutenu) | □ | □ | /1 |
| Définition formelle du concept | □ | □ | /1 |
| ÉQUIVALENT à l'analogie fun (même concept) | □ | □ | /0.5 |
| Pas de ton familier ou humoristique | □ | □ | /0.5 |

**Score G.2 : ___/4**

---

## G.3 — Auto-Évaluation de l'Analogie (1 point)

> Le prompt demande : "tu dois juger est-ce que l'exercice ainsi créé est-il con ou intelligent ou mid ou ok, le tout sur une notation de 0 à 100, et donc si la note ne dépasse pas 95 recommencer"

| Critère | Présent | Points |
|---------|---------|--------|
| Auto-évaluation explicite (note /100) | □ | /0.5 |
| Justification de la note | □ | /0.5 |

**Score G.3 : ___/1**

**SCORE TOTAL SECTION G : ___/12**

---

# SECTION H : SECTION 5 — COURS COMPLET (12 points)

> **RAPPEL :** La Section 5 est un VRAI COURS COMPLET, pas un résumé.

## H.1 — Sous-sections Obligatoires (8 points)

| Sous-section | Présente | Complète | Points |
|--------------|----------|----------|--------|
| **5.1** Ce que cet exercice enseigne | □ | □ | /0.6 |
| **5.2** LDA — Traduction littérale (MAJUSCULES) | □ | □ | /1 |
| **5.2.2** Logic Flow (Structured English) | □ | □ | /0.6 |
| **5.2.3** Représentation algorithmique | □ | □ | /0.5 |
| **5.2.3.1** Logique de Garde (Fail Fast) | □ | □ | /0.5 |
| **5.3** Visualisation ASCII (adaptée au domaine) | □ | □ | /0.8 |
| **5.4** Les pièges en détail | □ | □ | /0.6 |
| **5.5** Cours Complet (VRAI cours, pas résumé) | □ | □ | /1 |
| **5.6** Normes avec explications pédagogiques | □ | □ | /0.6 |
| **5.7** Simulation avec trace d'exécution | □ | □ | /0.6 |
| **5.8** Mnémotechniques (MEME obligatoire) | □ | □ | /0.6 |
| **5.9** Applications pratiques | □ | □ | /0.6 |

**Score H.1 : ___/8**

---

## H.2 — Qualité du LDA Section 5.2 (1.5 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| Tout en MAJUSCULES | □ | /0.3 |
| Traduction LITTÉRALE (pas interprétation) | □ | /0.3 |
| Utilise la table de traduction officielle | □ | /0.3 |
| Structure DÉBUT/FIN FONCTION | □ | /0.3 |
| Indentation correcte | □ | /0.3 |

**Score H.2 : ___/1.5**

### Table de Traduction LDA Complète (Référence)

| Code C | Traduction LDA (MAJUSCULES) |
|--------|-------------------------------|
| `int func(char *str)` | FONCTION func QUI RETOURNE UN ENTIER ET PREND EN PARAMÈTRE str QUI EST UN POINTEUR VERS UN CARACTÈRE |
| `{` (début fonction) | DÉBUT FONCTION |
| `}` (fin fonction) | FIN FONCTION |
| `int i;` | DÉCLARER i COMME ENTIER |
| `char c;` | DÉCLARER c COMME CARACTÈRE |
| `int *ptr;` | DÉCLARER ptr COMME POINTEUR VERS UN ENTIER |
| `FILE *fp;` | DÉCLARER fp COMME POINTEUR VERS UNE STRUCTURE FICHIER |
| `i = 0;` | AFFECTER 0 À i |
| `i = j + 1;` | AFFECTER j PLUS 1 À i |
| `i++;` | INCRÉMENTER i DE 1 |
| `i--;` | DÉCRÉMENTER i DE 1 |
| `while (condition)` | TANT QUE condition FAIRE |
| `}` (fin while) | FIN TANT QUE |
| `if (condition)` | SI condition ALORS |
| `else if (condition)` | SINON SI condition ALORS |
| `else` | SINON |
| `}` (fin if) | FIN SI |
| `for (i = 0; i < n; i++)` | POUR i ALLANT DE 0 À n MOINS 1 FAIRE |
| `}` (fin for) | FIN POUR |
| `return (i);` | RETOURNER LA VALEUR DE i |
| `str[i]` | LE CARACTÈRE À LA POSITION i DANS str |
| `tab[i]` | L'ÉLÉMENT À LA POSITION i DANS tab |
| `'\0'` | LE CARACTÈRE NUL |
| `NULL` | NUL |
| `ptr->field` | LE CHAMP field DE ptr |
| `malloc(sizeof(type))` | ALLOUER LA MÉMOIRE DE LA TAILLE D'UN type |
| `free(ptr)` | LIBÉRER LA MÉMOIRE POINTÉE PAR ptr |
| `fopen(f, "r")` | OUVRIR LE FICHIER f EN MODE LECTURE |
| `fclose(fp)` | FERMER LE FICHIER fp |
| `!=` | EST DIFFÉRENT DE |
| `==` | EST ÉGAL À |
| `<` | EST INFÉRIEUR À |
| `<=` | EST INFÉRIEUR OU ÉGAL À |
| `>` | EST SUPÉRIEUR À |
| `>=` | EST SUPÉRIEUR OU ÉGAL À |
| `&&` | ET |
| `\|\|` | OU |
| `!` | NON / N'EST PAS |
| `+` | PLUS |
| `-` | MOINS |
| `*` | MULTIPLIÉ PAR |
| `/` | DIVISÉ PAR |
| `%` | MODULO |

---

## H.3 — Visualisation ASCII Section 5.3 (1 point)

> Les schémas ASCII s'adaptent au DOMAINE de l'exercice.

| Domaine | Type de Visualisation Attendu | Utilisé si applicable |
|---------|-------------------------------|----------------------|
| Mem | Stack/Heap, pointeurs | □ |
| Struct (strings) | Tableau avec positions et '\0' | □ |
| Struct (listes) | Liste chaînée avec flèches | □ |
| Struct (arbres) | Arbre binaire | □ |
| FS | Système d'exploitation / Kernel / Disque | □ |
| Net | Client/Server ou couches réseau | □ |
| CPU/ASM | User Space / Kernel Space | □ |
| Encodage | Représentation bits | □ |
| Algo | Flux d'exécution (flowchart) | □ |

| Critère | Conforme | Points |
|---------|----------|--------|
| Visualisation ADAPTÉE au domaine | □ | /0.5 |
| Schéma clair et lisible | □ | /0.5 |

**Score H.3 : ___/1**

---

## H.4 — Normes Section 5.6 — Format Obligatoire (1 point)

> Format d'explication des normes : ❌ HORS NORME / ✅ CONFORME / 📖 POURQUOI

| Critère | Conforme | Points |
|---------|----------|--------|
| Format ❌ HORS NORME présent | □ | /0.25 |
| Format ✅ CONFORME présent | □ | /0.25 |
| Format 📖 POURQUOI présent | □ | /0.25 |
| Explications pédagogiques | □ | /0.25 |

**Score H.4 : ___/1**

---

## H.5 — Diagramme Mermaid (si complexe) (0.5 point)

| Critère | Applicable | Présent | Points |
|---------|------------|---------|--------|
| Exercice complexe nécessitant visualisation | □ | — | — |
| Diagramme Mermaid fourni | — | □ | /0.25 |
| Diagramme syntaxiquement correct | — | □ | /0.25 |

**Score H.5 : ___/0.5** (ou N/A)

**SCORE TOTAL SECTION H : ___/12**

---

# SECTION I : SECTION 4 — ZONE CORRECTION (16 points)

> **PRINCIPE FONDAMENTAL :**
> La moulinette teste AUTOMATIQUEMENT sans intervention humaine.
> TOUT le code doit être fourni, COMPLET, et FONCTIONNEL.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   LA MOULINETTE A BESOIN DE TOUT LE CODE                                    │
│                                                                             │
│   La moulinette est un SCRIPT AUTOMATIQUE qui :                            │
│   • Compile le code étudiant avec gcc                                      │
│   • Compare la sortie avec la solution de référence                        │
│   • Teste tous les edge cases                                              │
│   • Vérifie que les mutants sont détectés                                  │
│                                                                             │
│   Pour fonctionner, elle a besoin de :                                     │
│   ✅ Solution de référence COMPLÈTE (pas un extrait)                       │
│   ✅ main.c de test FONCTIONNEL                                            │
│   ✅ Tous les edge_cases avec args et expected                             │
│   ✅ 5 mutants avec CODE COMPLET (pas juste description)                   │
│   ✅ spec.json PARSABLE sans erreur                                        │
│                                                                             │
│   ❌ Si un seul élément manque → La moulinette ne fonctionne pas → ÉCHEC   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## I.1 — Les 10 Sous-sections Obligatoires (6 points)

| Sous-section | Présente | Complète | Points |
|--------------|----------|----------|--------|
| **4.1** Moulinette (tableau des tests) | □ | □ | /0.6 |
| **4.2** main.c de test | □ | □ | /0.6 |
| **4.3** Solution de référence | □ | □ | /0.6 |
| **4.4** Solutions alternatives acceptées | □ | □ | /0.6 |
| **4.5** Solutions refusées (avec explications) | □ | □ | /0.6 |
| **4.6** Solution bonus de référence (COMPLÈTE) | □ | □ | /0.6 |
| **4.7** Solutions alternatives bonus (COMPLÈTES) | □ | □ | /0.6 |
| **4.8** Solutions refusées bonus (COMPLÈTES) | □ | □ | /0.6 |
| **4.9** spec.json (ENGINE v22.1) | □ | □ | /0.6 |
| **4.10** Solutions Mutantes (minimum 5) | □ | □ | /0.6 |

**Score I.1 : ___/6**

---

## I.2 — Solution de Référence Section 4.3 (2 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| Code COMPLET et FONCTIONNEL | □ | /0.25 |
| Préfixe `ref_` sur le nom de fonction | □ | /0.25 |
| Code sur UNE ligne dans spec.json (pas de \n) | □ | /0.25 |
| Guillemets échappés (\" pas ") | □ | /0.25 |
| PAS de commentaires multi-lignes | □ | /0.25 |
| PAS d'includes dans le JSON | □ | /0.25 |
| Tous les edge cases gérés | □ | /0.25 |
| Pas de wrapper vide (au moins 1 if/else) | □ | /0.25 |

**Score I.2 : ___/2**

---

## I.3 — spec.json Complet Section 4.9 (4 points)

### Champs OBLIGATOIRES

| Champ | Présent | Valide | Points |
|-------|---------|--------|--------|
| `name` | □ | □ | /0.15 |
| `language` | □ | □ | /0.15 |
| `type` | □ | □ | /0.15 |
| `tier` + `tier_info` | □ | □ | /0.15 |
| `tags` (array) | □ | □ | /0.15 |
| `passing_score` (70) | □ | □ | /0.15 |
| `function.name` | □ | □ | /0.15 |
| `function.prototype` | □ | □ | /0.15 |
| `function.return_type` | □ | □ | /0.15 |
| `function.parameters` (array) | □ | □ | /0.15 |
| `driver.reference` (préfixe ref_) | □ | □ | /0.2 |
| `driver.edge_cases` (≥5) | □ | □ | /0.2 |

### Format edge_case Obligatoire

```json
{
  "name": "null_input",
  "args": [null],
  "expected": 0,
  "is_trap": true,
  "trap_explanation": "param est NULL, doit retourner 0"
}
```

| Champ edge_case | Obligatoire |
|-----------------|-------------|
| `name` (unique) | ✅ |
| `args` (array) | ✅ |
| `expected` | ✅ |
| `is_trap` | ✅ si trap |
| `trap_explanation` | ✅ si is_trap=true |
| `driver.fuzzing.enabled` | □ | □ | /0.15 |
| `driver.fuzzing.iterations` | □ | □ | /0.1 |
| `driver.fuzzing.generators` | □ | □ | /0.15 |
| `norm.allowed_functions` | □ | □ | /0.15 |
| `norm.forbidden_functions` | □ | □ | /0.15 |
| `norm.check_security` | □ | □ | /0.1 |
| `norm.check_memory` | □ | □ | /0.1 |
| `norm.blocking` | □ | □ | /0.1 |
| JSON parsable sans erreur | □ | □ | /0.4 |

**Score I.3 : ___/4**

### Types de Fuzzing Generators Valides

| Type | Description | Paramètres |
|------|-------------|------------|
| `int` | Entier | `min`, `max` |
| `float` | Flottant | `min`, `max` |
| `string` | Chaîne | `min_len`, `max_len`, `charset` |
| `array_int` | Tableau d'entiers | `min_len`, `max_len`, `min_val`, `max_val` |
| `array_float` | Tableau de flottants | `min_len`, `max_len`, `min_val`, `max_val` |
| `array_string` | Tableau de chaînes | `min_len`, `max_len` |
| `matrix_int` | Matrice | `min_rows`, `max_rows`, `min_cols`, `max_cols` |
| `bool` | Booléen | — |
| `char` | Caractère | `charset` |

### Charsets Valides

| Charset | Description |
|---------|-------------|
| `printable` | Caractères imprimables ASCII (32-126) |
| `ascii` | Tous les caractères ASCII (0-127) |
| `alphanumeric` | a-z, A-Z, 0-9 |
| `custom` | Requiert `custom_chars` |

---

## I.4 — Solutions Mutantes Section 4.10 (4 points)

| Mutant | Catégorie | Présent | Code COMPLET | Explication | Points |
|--------|-----------|---------|--------------|-------------|--------|
| A | Boundary (< vs <=) | □ | □ | □ | /0.8 |
| B | Safety (oubli NULL) | □ | □ | □ | /0.8 |
| C | Resource (fuite) | □ | □ | □ | /0.8 |
| D | Logic (inversée) | □ | □ | □ | /0.8 |
| E | Return (mauvaise valeur) | □ | □ | □ | /0.8 |

**Score I.4 : ___/4**

### Edge Cases OBLIGATOIRES par Type de Paramètre

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ POINTEUR/CHAÎNE :              │ ENTIER :                                   │
│ □ NULL                         │ □ 0                                        │
│ □ Chaîne vide ""               │ □ 1                                        │
│ □ Un seul caractère "a"        │ □ -1                                       │
│ □ Chaîne très longue           │ □ INT_MAX / INT_MIN                        │
├────────────────────────────────┼────────────────────────────────────────────┤
│ FICHIER :                      │ TABLEAU :                                  │
│ □ Fichier inexistant           │ □ Tableau NULL                             │
│ □ Chemin NULL                  │ □ Tableau vide (size 0)                    │
│ □ Fichier vide                 │ □ Un seul élément                          │
│ □ Sans permission              │ □ Éléments identiques                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Format OBLIGATOIRE des Mutants

```c
/* Mutant A (Boundary) : Description précise du bug */
int nom_fonction(const char *param)
{
    // CODE COMPLET — TOUT LE CODE, PAS UN EXTRAIT
    // Doit compiler seul
}
// Pourquoi c'est faux : [explication technique]
// Ce qui était pensé : [misconception de l'étudiant]
```

**SCORE TOTAL SECTION I : ___/16**

---

# SECTION J : SECTION 9 — DEPLOYMENT PACK (6 points)

## J.1 — JSON Deployment Pack Complet

| Champ | Présent | Valide | Points |
|-------|---------|--------|--------|
| `deploy.hackbrain_version` ("5.5.2") | □ | □ | /0.2 |
| `deploy.engine_version` ("v22.1") | □ | □ | /0.2 |
| `deploy.exercise_slug` | □ | □ | /0.2 |
| `deploy.generated_at` (YYYY-MM-DD HH:MM:SS) | □ | □ | /0.2 |
| `metadata.exercise_id` | □ | □ | /0.15 |
| `metadata.exercise_name` | □ | □ | /0.15 |
| `metadata.module` + `module_name` | □ | □ | /0.15 |
| `metadata.concept` + `concept_name` | □ | □ | /0.15 |
| `metadata.type` | □ | □ | /0.15 |
| `metadata.tier` + `tier_info` | □ | □ | /0.15 |
| `metadata.phase` | □ | □ | /0.15 |
| `metadata.difficulty` + `difficulty_stars` | □ | □ | /0.15 |
| `metadata.language` | □ | □ | /0.15 |
| `metadata.duration_minutes` | □ | □ | /0.15 |
| `metadata.xp_base` | □ | □ | /0.15 |
| `metadata.xp_bonus_multiplier` | □ | □ | /0.15 |
| `metadata.bonus_tier` + `bonus_icon` | □ | □ | /0.15 |
| `metadata.complexity_time` + `complexity_space` | □ | □ | /0.15 |
| `metadata.prerequisites` | □ | □ | /0.15 |
| `metadata.domains` + `domains_bonus` | □ | □ | /0.15 |
| `metadata.tags` | □ | □ | /0.15 |
| `metadata.meme_reference` | □ | □ | /0.2 |
| `files` (chemins des fichiers) | □ | □ | /0.3 |

**Score J.1 : ___/4**

---

## J.2 — Section Files du Deployment Pack (2 points)

| Fichier | Présent | Points |
|---------|---------|--------|
| `spec.json` | □ | /0.3 |
| `references/ref_solution.c` | □ | /0.3 |
| `references/ref_solution_bonus.c` | □ | /0.3 |
| `alternatives/alt_1.c` (au moins 1) | □ | /0.3 |
| `mutants/mutant_a_boundary.c` | □ | /0.2 |
| `mutants/mutant_b_safety.c` | □ | /0.2 |
| `mutants/mutant_c_resource.c` | □ | /0.2 |
| `mutants/mutant_d_logic.c` | □ | /0.1 |
| `mutants/mutant_e_return.c` | □ | /0.1 |

**Score J.2 : ___/2**

**SCORE TOTAL SECTION J : ___/6**

---

# SECTION K : COHÉRENCE GLOBALE & RÈGLES (10 points)

## K.1 — Cohérence Phase/Difficulté (3 points)

### Critères par Phase

| Phase | Difficulté | Lignes Logique | Durée | Complexité Max | Vérifications | Ton |
|-------|------------|----------------|-------|----------------|---------------|-----|
| **0** | 1-3/10 | 1-5 | 10-20 min | O(n) | 1 min (NULL) | Ultra-pédagogique, encourageant, FUN |
| **1** | 3-5/10 | 5-20 | 20-40 min | O(n log n) | 2-3 (NULL, 0, limites) | — |
| **2** | 4-6/10 | 10-50 | 30-60 min | Toute | Tous edge cases | — |
| **3-4** | 7-9/10 | 50-200 | 60-120 min | Toute | Exhaustifs + adversariaux | — |
| **5+** | 8-10+/10 | 100-500+ | 2-8h | Toute | — | — |

| Critère | Conforme | Points |
|---------|----------|--------|
| Difficulté cohérente avec Phase | □ | /0.5 |
| Lignes de logique cohérentes | □ | /0.5 |
| Durée estimée réaliste | □ | /0.5 |
| Complexité temps/espace cohérente | □ | /0.5 |
| Nombre de vérifications cohérent | □ | /0.5 |
| Ton adapté (Phase 0 = encourageant) | □ | /0.5 |

**Score K.1 : ___/3**

---

## K.2 — Cohérence Tiers/Difficulté (2 points)

| Tiers | Règle | Conforme | Points |
|-------|-------|----------|--------|
| TIERS 1 | 1 concept = 1 exercice | □ | /0.4 |
| TIERS 1 | Prérequis = modules PRÉCÉDENTS seulement | □ | /0.4 |
| TIERS 2 | Difficulté = Max(concepts T1) + 1 | □ | /0.4 |
| TIERS 2 | Combine 2-3 concepts DÉJÀ VUS en T1 | □ | /0.4 |
| TIERS 3 | Difficulté = Max(T2) + 2 | □ | /0.4 |

### Ordre de Génération OBLIGATOIRE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   TOUJOURS GÉNÉRER DANS CET ORDRE :                                         │
│                                                                             │
│   1. TOUS les Tiers 1 d'abord (a, b, c, d, e, f...)                         │
│   2. PUIS les Tiers 2 (mix1, mix2, mix3...)                                 │
│   3. ENFIN le(s) Tiers 3 (synth)                                            │
│                                                                             │
│   ⚠️ Un Tiers 2 ne peut PAS être généré si ses Tiers 1 n'existent pas       │
│   ⚠️ Un Tiers 3 ne peut PAS être généré si les Tiers 2 n'existent pas       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Score K.2 : ___/2**

---

## K.3 — Règle Anti-Wrapper (2 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| AU MOINS une décision (if/else) | □ | /0.5 |
| AU MOINS une gestion d'erreur | □ | /0.5 |
| Pas un simple `return fonction_standard()` | □ | /0.5 |
| L'exercice fait RÉFLÉCHIR | □ | /0.5 |

**Score K.3 : ___/2**

### Exemples de Wrappers INTERDITS

```c
// ❌ ÉCHEC : Wrapper vide
return fopen(filename, "r");
return strlen(str);
return a + b;
```

---

## K.4 — Originalité & Neutralité (3 points)

| Critère | Conforme | Points |
|---------|----------|--------|
| **Pas de préfixe `ft_`** (École 42) | □ | /0.5 |
| Nom de fonction ORIGINAL et DESCRIPTIF | □ | /0.5 |
| Nom de fonction FUN si approprié | □ | /0.5 |
| Contexte ancré culture pop/réel | □ | /0.5 |
| **Pas de mention de la cible** ("étudiants", "seniors") | □ | /0.5 |
| Pas de copie conventions autres écoles | □ | /0.5 |

**Score K.4 : ___/3**

**SCORE TOTAL SECTION K : ___/10**

---

# 📊 RÉCAPITULATIF FINAL

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GRILLE DE NOTATION FINALE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Section A — Thinking :                        ___/8                       │
│   Section B — En-tête :                         ___/8                       │
│   Section C — Structure 9 Sections :            ___/6                       │
│   Section D — Section 1 Consigne :              ___/10                      │
│   Section E — Section 2 Saviez-Vous :           ___/4                       │
│   Section F — Section 3 Bash + Bonus :          ___/8                       │
│   Section G — Analogies Double Énoncé :         ___/12                      │
│   Section H — Section 5 Cours Complet :         ___/12                      │
│   Section I — Section 4 Zone Correction :       ___/16                      │
│   Section J — Section 9 Deployment Pack :       ___/6                       │
│   Section K — Cohérence & Règles :              ___/10                      │
│                                                                             │
│   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│                                                                             │
│   SCORE TOTAL :                                 ___/100                     │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   VERDICT FINAL :                                                           │
│                                                                             │
│   □ ✅ PUBLICATION AUTORISÉE          (100/100 UNIQUEMENT)                  │
│   □ ❌ REJET — CORRIGER ET RESOUMETTRE (<100/100)                           │
│                                                                             │
│   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│                                                                             │
│   L'EXCELLENCE N'A PAS DE RACCOURCIS.                                       │
│   99/100 = ÉCHEC. SEUL 100/100 EST ACCEPTABLE.                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# ⚠️ CONDITIONS D'ÉCHEC AUTOMATIQUE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ÉCHECS AUTOMATIQUES                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ THINKING (Section A) :                                                      │
│ □ Pas de bloc <thinking> avant le contenu                                  │
│ □ Checklist A-G incomplète                                                 │
│ □ Mutants décrits sans code concret                                        │
│ □ Verdict absent                                                           │
│                                                                             │
│ EN-TÊTE (Section B) :                                                       │
│ □ Version du langage absente (C au lieu de C17)                            │
│ □ Format ID incorrect (0.1.27a au lieu de 0.1.27-a)                        │
│ □ Type d'exercice non reconnu                                              │
│ □ Étoiles incohérentes avec difficulté                                     │
│                                                                             │
│ CONSIGNES (Section D) :                                                     │
│ □ Sections 1-3 insuffisantes pour autonomie                                │
│ □ Demande de commentaires dans le code                                     │
│ □ Format de réponse non testable automatiquement                           │
│ □ Section 3 bash non minimaliste (cat, prototype visible)                  │
│                                                                             │
│ ANALOGIES (Section G) :                                                     │
│ □ Section 2.4.1 (fun) absente                                              │
│ □ Section 2.4.2 (académique) absente                                       │
│ □ Note analogie < 3/5 (forcée ou absente)                                  │
│ □ Analogie n'a pas de sens ou pas recherchée                               │
│                                                                             │
│ COURS (Section H) :                                                         │
│ □ Section 5 est un résumé, pas un cours                                    │
│ □ LDA pas en MAJUSCULES                                                    │
│ □ Visualisation ASCII absente ou inadaptée au domaine                      │
│                                                                             │
│ CORRECTION (Section I) :                                                    │
│ □ JSON spec.json non parsable                                              │
│ □ Moins de 5 mutants                                                       │
│ □ Mutants sans code COMPLET                                                │
│ □ Une des 10 sous-sections absente                                         │
│ □ Solution reference sans préfixe ref_                                     │
│ □ passing_score absent                                                     │
│ □ Fuzzing section absente                                                  │
│                                                                             │
│ COHÉRENCE (Section K) :                                                     │
│ □ Préfixe ft_ détecté                                                      │
│ □ Wrapper sans logique                                                     │
│ □ Difficulté incohérente avec la Phase                                     │
│ □ QCM sans 10 réponses (A-J) par question                                  │
│ □ Mention de "étudiants" ou "seniors" dans le texte                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 📝 NOTES DU CORRECTEUR

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ POINTS FORTS :                                                              │
│                                                                             │
│                                                                             │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ POINTS À CORRIGER POUR ATTEINDRE 100/100 :                                  │
│                                                                             │
│                                                                             │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ DÉTAIL DES POINTS PERDUS :                                                  │
│                                                                             │
│                                                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# ANNEXE A : CHECKLIST RAPIDE AVANT SOUMISSION

```
THINKING :
□ Bloc <thinking> présent AVANT tout contenu
□ Checklist complète A-G
□ 5 mutants avec CODE concret (pas approximatif)
□ Verdict explicite (VALIDE/À MODIFIER/REJETER)

EN-TÊTE :
□ 12 champs présents
□ Version du langage explicite (C17, Python 3.14, Rust Edition 2024)
□ Étoiles EXACTES pour le niveau de difficulté
□ Type parmi les 9 valides
□ Domaines parmi les 21 valides

SECTIONS 1-3 (Autonomie Étudiante) :
□ Fichier à rendre nommé
□ Fonctions autorisées/interdites listées
□ Consigne complète (entrée/sortie/contraintes/exemples)
□ Consigne AUSSI LONGUE QUE NÉCESSAIRE
□ Prototype cohérent avec spec.json
□ Section bash MINIMALISTE (pas de cat, pas de prototype, pas de user@)

BONUS :
□ Palier identifié (⚡🔥💀🧠☠️🔮)
□ Multiplicateur XP correct
□ Complexité temps/espace attendue
□ Tableau "Ce qui change" Base vs Bonus
□ Contraintes en encadré mathématique

ANALOGIES :
□ Section 2.4.1 fun présente (note ≥4/5)
□ Section 2.4.2 académique présente
□ Analogie INTELLIGENTE et RECHERCHÉE
□ Pas de cliché (Mario, Minecraft générique)
□ Auto-évaluation /100 (doit être ≥95)

SECTION 5 COURS :
□ 12 sous-sections présentes (5.1 à 5.9 + 5.2.2, 5.2.3, 5.2.3.1)
□ LDA en MAJUSCULES avec table de traduction
□ Logic Flow (Structured English)
□ Visualisation ASCII ADAPTÉE AU DOMAINE
□ Normes avec format ❌/✅/📖
□ Trace d'exécution avec tableau
□ Mermaid si exercice complexe

SECTION 4 CORRECTION :
□ 10 sous-sections présentes (4.1 à 4.10)
□ spec.json parsable
□ passing_score: 70
□ Fuzzing section complète
□ 5 mutants avec code COMPLET
□ Préfixe ref_ sur toutes les solutions reference

DEPLOYMENT PACK :
□ hackbrain_version: "5.5.2"
□ engine_version: "v22.1"
□ Metadata complète (26 champs)
□ meme_reference présent
□ Section files avec tous les chemins

RÈGLES GLOBALES :
□ Pas de préfixe ft_
□ Pas de wrapper vide
□ Pas de demande de commentaires
□ Pas de mention "étudiants"/"seniors"
□ QCM avec 10 réponses (A-J) si applicable
□ Cohérence Phase/Difficulté/Lignes/Durée
```

---

**Document généré par HACKBRAIN GRADER v3.0**
**Compatible HACKBRAIN Prompt v5.5.2 + ENGINE v22.1 + Mutation Tester**
**L'excellence pédagogique ne se négocie pas — pas de raccourcis**

---

# 🧠 MÉMO RAPIDE — POINTS CRITIQUES À NE JAMAIS OUBLIER

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     VÉRIFICATIONS INSTANTANÉES                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ 1. THINKING présent AVANT tout contenu ?                                   │
│    → Si non : STOP, ÉCHEC IMMÉDIAT                                         │
│                                                                             │
│ 2. Version langage présente ? (C17, Python 3.14, Rust Edition 2024)        │
│    → Si "C" seul : ÉCHEC                                                   │
│                                                                             │
│ 3. Section 2.4.1 (fun) ET 2.4.2 (académique) présentes ?                   │
│    → Si une manque : ÉCHEC                                                 │
│                                                                             │
│ 4. Analogie intelligente ? (note ≥4/5)                                     │
│    → Si forcée ou cliché : ÉCHEC                                           │
│                                                                             │
│ 5. Section 3 bash MINIMALISTE ? (pas de cat, pas de user@)                 │
│    → Si cat ou prototype visible : ÉCHEC                                   │
│                                                                             │
│ 6. 5 mutants avec CODE COMPLET ?                                           │
│    → Si description sans code : ÉCHEC                                      │
│                                                                             │
│ 7. spec.json parsable ?                                                    │
│    → Si erreur JSON : ÉCHEC                                                │
│                                                                             │
│ 8. Préfixe ref_ sur solution reference ?                                   │
│    → Si absent : ÉCHEC                                                     │
│                                                                             │
│ 9. Pas de ft_ ?                                                            │
│    → Si présent : ÉCHEC                                                    │
│                                                                             │
│ 10. Pas de wrapper vide ?                                                  │
│     → Si return strlen(str); seul : ÉCHEC                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Questions CRITIQUES à me poser :

### 1. ANTI-HASARD (Mission Fondamentale)
- [ ] L'exercice peut-il être résolu par copier-coller d'internet ?
- [ ] Un étudiant qui réussit a-t-il FORCÉMENT compris le concept ?
- [ ] Les mutants représentent-ils des VRAIES erreurs d'étudiants ?
- [ ] Le feedback d'échec indique-t-il PRÉCISÉMENT ce qui manque ?

### 2. AUTONOMIE ÉTUDIANTE
- [ ] Un étudiant qui n'a JAMAIS fait l'exercice peut-il le réaliser avec SEULEMENT sections 1-3 ?
- [ ] Toutes les informations nécessaires sont-elles explicites ?

### 3. PÉDAGOGIE
- [ ] L'analogie m'aide-t-elle VRAIMENT à comprendre le concept ?
- [ ] La Section 5 est-elle un VRAI COURS ou juste un résumé ?
- [ ] L'exercice enseigne-t-il le FOND, pas juste la FORME ?

### 4. TECHNIQUE
- [ ] Le JSON spec.json est-il COMPLET et COHÉRENT avec le reste ?
- [ ] Les tests sont-ils 100% DÉTERMINISTES (pas de réponses ouvertes) ?
- [ ] La complexité est-elle cohérente avec la Phase ?

### 5. MINI-PROJET (si applicable)
- [ ] Les inspirations et noms de fonctions suivent-ils un FIL CONDUCTEUR ?
- [ ] L'ordre de construction est-il logique ?

## Si je doute sur un point → C'est probablement un problème → Score < 100

---

## 🚨 RAPPEL FINAL

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   L'EXCELLENCE N'A PAS DE RACCOURCIS.                                       │
│                                                                             │
│   99/100 = ÉCHEC                                                            │
│   SEUL 100/100 EST ACCEPTABLE                                               │
│                                                                             │
│   Si l'exercice est "pas mal" ou "ok" → INSUFFISANT                        │
│   On veut EXCELLENT, INTELLIGENT, MÉMORABLE                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
