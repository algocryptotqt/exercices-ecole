# Exercice C.1.38 : dns_resolver

**Module :**
C.1 — Reseaux

**Concept :**
38 — Resolution DNS (Hierarchy, A/AAAA/CNAME records, Cache)

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Python 3.14

**Prerequis :**
- Syntaxe de base Python
- Structures de donnees (dict, list)
- Exercice ex36_ip_validator

**Domaines :**
Net, DNS, Cache

**Duree estimee :**
45 min

**XP Base :**
95

**Complexite :**
T2 O(n) pour resolution recursive × S2 O(n) pour le cache

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `dns_resolver.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `dict`, `list`, `time.time`, `re`, built-ins standards |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | `socket.gethostbyname`, `dns.resolver`, bibliotheques DNS |

---

### 1.2 Consigne

#### Section Culture : "The Phone Book of the Internet"

**HACKERS (1995) — "Hack the planet!"**

Quand Dade Murphy tape un nom de domaine, il ne realise pas qu'une chaine de serveurs DNS travaille en coulisses. Root servers, TLD servers, authoritative servers... C'est la hierarchie invisible qui transforme "www.hackers.com" en "192.168.1.1".

Le DNS est le talon d'Achille d'Internet. Controle le DNS, controle le trafic.

*"The DNS is the most critical infrastructure of the Internet. Without it, we're all just numbers."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un simulateur de resolution DNS qui :

1. **Simule la hierarchie DNS** : Root -> TLD -> Authoritative
2. **Gere les types d'enregistrements** : A, AAAA, CNAME, MX, TXT
3. **Implemente un cache** : Avec TTL (Time To Live)
4. **Resout les CNAME** : Chaine de resolution recursive
5. **Detecte les boucles** : Eviter les CNAME circulaires

**Entree :**

```python
class DNSRecord:
    """Represente un enregistrement DNS."""
    def __init__(self, name: str, record_type: str, value: str, ttl: int = 300):
        self.name = name
        self.record_type = record_type  # A, AAAA, CNAME, MX, TXT
        self.value = value
        self.ttl = ttl
        self.created_at = time.time()

class DNSZone:
    """Represente une zone DNS (comme example.com)."""
    def __init__(self, domain: str):
        self.domain = domain
        self.records: list[DNSRecord] = []

    def add_record(self, record: DNSRecord) -> None:
        pass

    def get_records(self, name: str, record_type: str = None) -> list[DNSRecord]:
        pass

class DNSResolver:
    """Simulateur de resolveur DNS."""
    def __init__(self):
        self.zones: dict[str, DNSZone] = {}
        self.cache: dict[str, tuple[DNSRecord, float]] = {}  # (record, expiry_time)
        self.cache_hits = 0
        self.cache_misses = 0

    def add_zone(self, zone: DNSZone) -> None:
        pass

    def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        """
        Resout un nom de domaine.

        Args:
            domain: Nom de domaine (ex: "www.example.com")
            record_type: Type d'enregistrement (A, AAAA, CNAME, MX, TXT)

        Returns:
            Liste des valeurs resolues
        """
        pass

    def clear_cache(self) -> None:
        pass

    def get_cache_stats(self) -> dict:
        pass
```

**Sortie :**

```python
# Configuration du resolveur
resolver = DNSResolver()

# Creer une zone
zone = DNSZone("example.com")
zone.add_record(DNSRecord("example.com", "A", "93.184.216.34"))
zone.add_record(DNSRecord("www.example.com", "CNAME", "example.com"))
zone.add_record(DNSRecord("mail.example.com", "MX", "10 smtp.example.com"))
zone.add_record(DNSRecord("smtp.example.com", "A", "93.184.216.35"))

resolver.add_zone(zone)

# Resolution
>>> resolver.resolve("example.com", "A")
["93.184.216.34"]

>>> resolver.resolve("www.example.com", "A")
["93.184.216.34"]  # Suit le CNAME

>>> resolver.resolve("mail.example.com", "MX")
["10 smtp.example.com"]
```

**Contraintes :**

- Les CNAME doivent etre resolus recursivement (max 10 niveaux)
- Le cache doit respecter le TTL
- Detecter les boucles CNAME (A -> B -> A)
- Les noms de domaine sont case-insensitive
- Gerer les sous-domaines (*.example.com)

**Types d'enregistrements :**

| Type | Description | Exemple de valeur |
|------|-------------|-------------------|
| A | Adresse IPv4 | "93.184.216.34" |
| AAAA | Adresse IPv6 | "2606:2800:220:1:..." |
| CNAME | Alias (Canonical Name) | "www.example.com" |
| MX | Mail Exchanger | "10 mail.example.com" |
| TXT | Texte arbitraire | "v=spf1 include:..." |

---

### 1.3 Prototype

```python
import time
from dataclasses import dataclass
from typing import Optional

@dataclass
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int = 300
    created_at: float = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

    def is_expired(self) -> bool:
        pass

class DNSZone:
    def __init__(self, domain: str):
        pass

    def add_record(self, record: DNSRecord) -> None:
        pass

    def get_records(self, name: str, record_type: str = None) -> list[DNSRecord]:
        pass

class DNSResolver:
    MAX_CNAME_DEPTH = 10

    def __init__(self):
        pass

    def add_zone(self, zone: DNSZone) -> None:
        pass

    def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        pass

    def _resolve_recursive(self, domain: str, record_type: str,
                           depth: int = 0, seen: set = None) -> list[str]:
        pass

    def _check_cache(self, domain: str, record_type: str) -> Optional[list[str]]:
        pass

    def _update_cache(self, domain: str, record_type: str,
                      records: list[DNSRecord]) -> None:
        pass

    def clear_cache(self) -> None:
        pass

    def get_cache_stats(self) -> dict:
        pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Les 13 serveurs racine**

Il n'y a que 13 groupes de serveurs racine DNS (A a M), mais grace a l'anycast, il y en a des centaines physiquement. Le serveur A est gere par Verisign, le K par RIPE NCC. Si tous tombaient, Internet s'effondrerait.

**Le cache DNS peut trahir**

Ton historique de navigation est partiellement stocke dans le cache DNS de ton OS. `ipconfig /displaydns` (Windows) ou l'inspection de `/etc/hosts` peut reveler les sites visites !

**Les attaques DNS**

- DNS Spoofing : Repondre avec de fausses adresses
- DNS Amplification : Utiliser le DNS pour des attaques DDoS
- DNS Tunneling : Exfiltrer des donnees via des requetes DNS

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **SRE/DevOps** | Configurer les zones DNS, debugging de resolution |
| **Security Engineer** | Detecter le DNS tunneling, analyser les logs DNS |
| **Cloud Architect** | Route 53 (AWS), Cloud DNS (GCP), geo-routing |
| **Network Admin** | Gerer les serveurs DNS internes (AD, BIND) |
| **Pentester** | Enumeration de sous-domaines, zone transfers |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3 -c "
from dns_resolver import DNSResolver, DNSZone, DNSRecord

# Creer le resolveur
resolver = DNSResolver()

# Zone example.com
zone = DNSZone('example.com')
zone.add_record(DNSRecord('example.com', 'A', '93.184.216.34', ttl=3600))
zone.add_record(DNSRecord('www.example.com', 'CNAME', 'example.com', ttl=300))
zone.add_record(DNSRecord('api.example.com', 'A', '93.184.216.100', ttl=60))

resolver.add_zone(zone)

# Resolutions
print('A record:', resolver.resolve('example.com', 'A'))
print('CNAME resolution:', resolver.resolve('www.example.com', 'A'))
print('Cache stats:', resolver.get_cache_stats())
"

# Sortie:
# A record: ['93.184.216.34']
# CNAME resolution: ['93.184.216.34']
# Cache stats: {'hits': 1, 'misses': 2, 'size': 2}
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

**Consigne Bonus :**

1. **Wildcard DNS** : Supporter les enregistrements `*.example.com`
2. **Round-robin** : Retourner les IPs dans un ordre different a chaque requete
3. **Negative caching** : Cacher les reponses NXDOMAIN
4. **DNS-over-HTTPS simulation** : Interface compatible DoH

```python
def resolve_wildcard(self, domain: str, record_type: str) -> list[str]:
    """Supporte les wildcards comme *.example.com"""
    pass

def resolve_with_round_robin(self, domain: str) -> list[str]:
    """Retourne les IPs en rotation"""
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | basic_a_record | resolve("example.com", "A") | ["93.184.216.34"] | 5 | Basic |
| 2 | cname_resolution | resolve("www.example.com", "A") | ["93.184.216.34"] | 10 | CNAME |
| 3 | cname_chain | resolve("alias.alias.com", "A") | follows chain | 10 | CNAME |
| 4 | cname_loop_detection | resolve("loop.com", "A") | empty or error | 10 | Safety |
| 5 | cache_hit | second resolve same domain | cache_hits++ | 10 | Cache |
| 6 | cache_expiry | resolve after TTL | cache_misses++ | 10 | Cache |
| 7 | mx_record | resolve("mail.com", "MX") | ["10 smtp..."] | 5 | Types |
| 8 | aaaa_record | resolve("ipv6.com", "AAAA") | ["2001:..."] | 5 | Types |
| 9 | txt_record | resolve("spf.com", "TXT") | ["v=spf1..."] | 5 | Types |
| 10 | case_insensitive | resolve("EXAMPLE.COM") | same as lowercase | 5 | Normalize |
| 11 | nonexistent_domain | resolve("notfound.com") | [] | 5 | Edge |
| 12 | nonexistent_type | resolve("example.com", "SRV") | [] | 5 | Edge |
| 13 | cache_clear | clear_cache() | size=0 | 5 | Cache |
| 14 | multiple_records | A with 3 IPs | [ip1, ip2, ip3] | 5 | Multi |
| 15 | subdomain_resolution | resolve("sub.sub.example.com") | correct | 5 | Hierarchy |

**Total : 100 points**

---

### 4.2 Tests unitaires Python

```python
import pytest
import time
from dns_resolver import DNSResolver, DNSZone, DNSRecord

@pytest.fixture
def resolver():
    r = DNSResolver()

    zone = DNSZone("example.com")
    zone.add_record(DNSRecord("example.com", "A", "93.184.216.34", ttl=300))
    zone.add_record(DNSRecord("www.example.com", "CNAME", "example.com", ttl=300))
    zone.add_record(DNSRecord("example.com", "AAAA", "2606:2800:220:1:248:1893:25c8:1946", ttl=300))
    zone.add_record(DNSRecord("example.com", "MX", "10 mail.example.com", ttl=300))
    zone.add_record(DNSRecord("mail.example.com", "A", "93.184.216.35", ttl=300))

    r.add_zone(zone)
    return r

class TestBasicResolution:
    def test_a_record(self, resolver):
        result = resolver.resolve("example.com", "A")
        assert result == ["93.184.216.34"]

    def test_aaaa_record(self, resolver):
        result = resolver.resolve("example.com", "AAAA")
        assert "2606:2800:220:1:248:1893:25c8:1946" in result

    def test_mx_record(self, resolver):
        result = resolver.resolve("example.com", "MX")
        assert "10 mail.example.com" in result

class TestCNAME:
    def test_cname_resolution(self, resolver):
        result = resolver.resolve("www.example.com", "A")
        assert result == ["93.184.216.34"]

    def test_cname_chain(self, resolver):
        zone = DNSZone("chain.com")
        zone.add_record(DNSRecord("alias1.chain.com", "CNAME", "alias2.chain.com"))
        zone.add_record(DNSRecord("alias2.chain.com", "CNAME", "final.chain.com"))
        zone.add_record(DNSRecord("final.chain.com", "A", "1.2.3.4"))
        resolver.add_zone(zone)

        result = resolver.resolve("alias1.chain.com", "A")
        assert result == ["1.2.3.4"]

    def test_cname_loop_detection(self, resolver):
        zone = DNSZone("loop.com")
        zone.add_record(DNSRecord("a.loop.com", "CNAME", "b.loop.com"))
        zone.add_record(DNSRecord("b.loop.com", "CNAME", "a.loop.com"))
        resolver.add_zone(zone)

        result = resolver.resolve("a.loop.com", "A")
        assert result == []  # Should detect loop and return empty

class TestCache:
    def test_cache_hit(self, resolver):
        resolver.resolve("example.com", "A")
        resolver.resolve("example.com", "A")
        stats = resolver.get_cache_stats()
        assert stats["hits"] >= 1

    def test_cache_expiry(self, resolver):
        # Add record with very short TTL
        zone = DNSZone("short.com")
        zone.add_record(DNSRecord("short.com", "A", "1.2.3.4", ttl=1))
        resolver.add_zone(zone)

        resolver.resolve("short.com", "A")
        time.sleep(1.5)  # Wait for TTL to expire
        resolver.resolve("short.com", "A")

        stats = resolver.get_cache_stats()
        assert stats["misses"] >= 2

    def test_cache_clear(self, resolver):
        resolver.resolve("example.com", "A")
        resolver.clear_cache()
        stats = resolver.get_cache_stats()
        assert stats["size"] == 0

class TestEdgeCases:
    def test_nonexistent_domain(self, resolver):
        result = resolver.resolve("notfound.com", "A")
        assert result == []

    def test_case_insensitive(self, resolver):
        result1 = resolver.resolve("EXAMPLE.COM", "A")
        result2 = resolver.resolve("example.com", "A")
        assert result1 == result2
```

---

### 4.3 Solution de reference (Python)

```python
import time
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int = 300
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.ttl

class DNSZone:
    def __init__(self, domain: str):
        self.domain = domain.lower()
        self.records: list[DNSRecord] = []

    def add_record(self, record: DNSRecord) -> None:
        record.name = record.name.lower()
        self.records.append(record)

    def get_records(self, name: str, record_type: str = None) -> list[DNSRecord]:
        name = name.lower()
        results = []
        for record in self.records:
            if record.name == name:
                if record_type is None or record.record_type == record_type:
                    results.append(record)
        return results

class DNSResolver:
    MAX_CNAME_DEPTH = 10

    def __init__(self):
        self.zones: dict[str, DNSZone] = {}
        self.cache: dict[str, tuple[list[DNSRecord], float]] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    def add_zone(self, zone: DNSZone) -> None:
        self.zones[zone.domain] = zone

    def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        domain = domain.lower()
        return self._resolve_recursive(domain, record_type, 0, set())

    def _resolve_recursive(self, domain: str, record_type: str,
                           depth: int, seen: set) -> list[str]:
        # Check for CNAME loop
        if domain in seen:
            return []

        # Check depth limit
        if depth > self.MAX_CNAME_DEPTH:
            return []

        seen.add(domain)

        # Check cache first
        cached = self._check_cache(domain, record_type)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1

        # Find the zone for this domain
        zone = self._find_zone(domain)
        if zone is None:
            return []

        # Get records
        records = zone.get_records(domain, record_type)

        # If we found records of the requested type, return them
        if records:
            self._update_cache(domain, record_type, records)
            return [r.value for r in records]

        # If looking for A/AAAA and there's a CNAME, follow it
        if record_type in ("A", "AAAA"):
            cname_records = zone.get_records(domain, "CNAME")
            if cname_records:
                cname_target = cname_records[0].value
                return self._resolve_recursive(cname_target, record_type,
                                               depth + 1, seen)

        return []

    def _find_zone(self, domain: str) -> Optional[DNSZone]:
        """Find the zone that contains this domain."""
        parts = domain.split(".")
        for i in range(len(parts)):
            zone_name = ".".join(parts[i:])
            if zone_name in self.zones:
                return self.zones[zone_name]
        return None

    def _check_cache(self, domain: str, record_type: str) -> Optional[list[str]]:
        cache_key = f"{domain}:{record_type}"
        if cache_key in self.cache:
            records, expiry = self.cache[cache_key]
            if time.time() < expiry:
                return [r.value for r in records]
            else:
                del self.cache[cache_key]
        return None

    def _update_cache(self, domain: str, record_type: str,
                      records: list[DNSRecord]) -> None:
        if not records:
            return
        cache_key = f"{domain}:{record_type}"
        min_ttl = min(r.ttl for r in records)
        expiry = time.time() + min_ttl
        self.cache[cache_key] = (records, expiry)

    def clear_cache(self) -> None:
        self.cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0

    def get_cache_stats(self) -> dict:
        return {
            "hits": self.cache_hits,
            "misses": self.cache_misses,
            "size": len(self.cache)
        }
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Pas de detection de boucle CNAME**

```python
# REFUSE : Boucle infinie possible
def _resolve_recursive(self, domain, record_type, depth, seen):
    cname_records = zone.get_records(domain, "CNAME")
    if cname_records:
        return self._resolve_recursive(cname_records[0].value, record_type,
                                       depth + 1, seen)
        # ERREUR: 'seen' n'est pas mis a jour, boucle infinie
```

**Refus 2 : Cache sans respect du TTL**

```python
# REFUSE : Cache eternel
def _check_cache(self, domain, record_type):
    cache_key = f"{domain}:{record_type}"
    if cache_key in self.cache:
        return self.cache[cache_key]  # ERREUR: pas de check TTL
```

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "dns_resolver",
  "language": "python",
  "language_version": "3.14",
  "type": "code",
  "tier": 2,
  "tags": ["moduleC.1", "network", "dns", "cache", "recursion", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "DNSResolver.resolve",
    "prototype": "def resolve(self, domain: str, record_type: str = 'A') -> list[str]",
    "return_type": "list[str]"
  },

  "driver": {
    "edge_cases": [
      {
        "name": "cname_loop",
        "args": ["a->b->a", "A"],
        "expected": [],
        "is_trap": true,
        "trap_explanation": "Boucle CNAME doit etre detectee"
      },
      {
        "name": "deep_cname",
        "args": ["11 levels deep", "A"],
        "expected": [],
        "is_trap": true,
        "trap_explanation": "Max 10 niveaux de CNAME"
      }
    ]
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Recursion) : Pas de limite de profondeur**

```python
# Mutant A: Recursion infinie possible
def _resolve_recursive(self, domain, record_type, depth, seen):
    # ERREUR: pas de check de depth
    if domain in seen:
        return []
    # ... continue sans limit
# Pourquoi c'est faux: Une chaine CNAME trop longue cause un stack overflow
```

**Mutant B (Cache) : Cache key sans record_type**

```python
# Mutant B: Collision de cache
def _check_cache(self, domain, record_type):
    cache_key = domain  # ERREUR: devrait inclure record_type
    if cache_key in self.cache:
        return self.cache[cache_key]
# Pourquoi c'est faux: A et AAAA pour le meme domaine retournent la meme chose
```

**Mutant C (Case) : Case-sensitive**

```python
# Mutant C: Pas de normalisation
def resolve(self, domain, record_type):
    # ERREUR: pas de .lower()
    return self._resolve_recursive(domain, record_type, 0, set())
# Pourquoi c'est faux: "EXAMPLE.COM" et "example.com" sont traites differemment
```

**Mutant D (Loop) : Set non passe par reference**

```python
# Mutant D: Nouveau set a chaque appel
def _resolve_recursive(self, domain, record_type, depth, seen=None):
    if seen is None:
        seen = set()  # ERREUR: set local a chaque branche
    seen.add(domain)
    # ...
    return self._resolve_recursive(target, record_type, depth+1)  # seen non passe!
# Pourquoi c'est faux: Chaque branche a son propre set, boucles non detectees
```

**Mutant E (TTL) : Expiry mal calcule**

```python
# Mutant E: TTL interprete comme timestamp
def _update_cache(self, domain, record_type, records):
    expiry = records[0].ttl  # ERREUR: devrait etre time.time() + ttl
    self.cache[cache_key] = (records, expiry)
# Pourquoi c'est faux: Le cache expire immediatement si TTL < time.time()
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Hierarchie DNS | Root -> TLD -> Authoritative | Fondamental |
| Types d'enregistrements | A, AAAA, CNAME, MX, TXT | Essentiel |
| Resolution recursive | Suivre les CNAME | Important |
| Cache et TTL | Performance et fraicheur | Critique |
| Detection de boucles | Eviter la recursion infinie | Securite |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION resolve QUI PREND domain ET record_type
DEBUT FONCTION
    NORMALISER domain EN MINUSCULES
    APPELER _resolve_recursive AVEC domain, record_type, profondeur=0, vus=ENSEMBLE_VIDE
FIN FONCTION

FONCTION _resolve_recursive QUI PREND domain, record_type, profondeur, vus
DEBUT FONCTION
    SI domain DANS vus ALORS
        RETOURNER LISTE_VIDE (boucle detectee)
    FIN SI

    SI profondeur > 10 ALORS
        RETOURNER LISTE_VIDE (trop profond)
    FIN SI

    AJOUTER domain A vus

    VERIFIER LE CACHE
    SI TROUVE ET NON EXPIRE ALORS
        INCREMENTER cache_hits
        RETOURNER VALEUR CACHEE
    FIN SI

    INCREMENTER cache_misses
    CHERCHER LA ZONE POUR domain
    OBTENIR LES ENREGISTREMENTS DE TYPE record_type

    SI ENREGISTREMENTS TROUVES ALORS
        METTRE EN CACHE
        RETOURNER VALEURS
    FIN SI

    SI record_type EST "A" OU "AAAA" ALORS
        CHERCHER CNAME
        SI CNAME TROUVE ALORS
            RETOURNER _resolve_recursive(cname_target, record_type, profondeur+1, vus)
        FIN SI
    FIN SI

    RETOURNER LISTE_VIDE
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Hierarchie DNS :**

```
                    +-------------+
                    | Root Server |
                    |   (.)       |
                    +------+------+
                           |
         +-----------------+-----------------+
         |                 |                 |
    +----+----+      +-----+-----+     +-----+-----+
    | .com    |      | .org      |     | .net      |
    | TLD     |      | TLD       |     | TLD       |
    +----+----+      +-----------+     +-----------+
         |
    +----+----+
    |example  |
    |.com     |
    |Authority|
    +----+----+
         |
    +----+----+
    | www.    |
    |example  |
    |.com     |
    +---------+
```

**Resolution d'un CNAME :**

```
Query: www.example.com (A)

1. Check cache -> Miss
2. Find zone: example.com
3. Get records for www.example.com, type A -> None
4. Get records for www.example.com, type CNAME -> "example.com"
5. Recursive call: resolve("example.com", "A")
   5.1 Check cache -> Miss
   5.2 Get records for example.com, type A -> "93.184.216.34"
   5.3 Cache result
   5.4 Return ["93.184.216.34"]
6. Return ["93.184.216.34"]
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Boucle CNAME

```python
# a.com -> CNAME -> b.com
# b.com -> CNAME -> a.com
# Sans detection: recursion infinie!

# Solution: Garder un set des domaines visites
if domain in seen:
    return []  # Boucle detectee
seen.add(domain)
```

#### Piege 2 : Cache sans TTL

```python
# Un enregistrement avec TTL=60 doit expirer apres 60 secondes
# Sinon: donnees obsoletes servies indefiniment

expiry = time.time() + record.ttl
if time.time() > expiry:
    # Cache expire, refaire la requete
```

---

### 5.5 Cours Complet

#### 5.5.1 Le systeme DNS

Le DNS (Domain Name System) traduit les noms de domaine en adresses IP.

**Types d'enregistrements courants :**

| Type | Usage |
|------|-------|
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Canonical name (alias) |
| MX | Mail exchanger |
| TXT | Text (SPF, DKIM, etc.) |
| NS | Name server |
| SOA | Start of Authority |

#### 5.5.2 Le cache DNS

Le cache DNS stocke les reponses pour eviter des requetes repetees.

**TTL (Time To Live) :**
- Duree de validite d'un enregistrement
- Varie de quelques secondes a plusieurs jours
- Compromis entre performance et fraicheur

---

### 5.7 Simulation avec trace d'execution

```
resolve("www.example.com", "A")

+-------+----------------------------------+-------------------+
| Etape | Operation                        | Resultat          |
+-------+----------------------------------+-------------------+
|   1   | normalize("www.example.com")     | "www.example.com" |
|   2   | check_cache("www.example.com:A") | None (miss)       |
|   3   | find_zone("www.example.com")     | zone "example.com"|
|   4   | get_records("www", "A")          | []                |
|   5   | get_records("www", "CNAME")      | ["example.com"]   |
|   6   | recursive: resolve("example.com")| Appel recursif    |
|   7   | check_cache("example.com:A")     | None (miss)       |
|   8   | get_records("example.com", "A")  | ["93.184.216.34"] |
|   9   | update_cache("example.com:A")    | Cached            |
|  10   | return ["93.184.216.34"]         | Resultat final    |
+-------+----------------------------------+-------------------+
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Boucle CNAME | Stack overflow | Set de domaines visites |
| 2 | Pas de limite profondeur | Recursion infinie | MAX_CNAME_DEPTH |
| 3 | Cache sans TTL | Donnees obsoletes | Check expiry time |
| 4 | Case-sensitive | Miss de cache | Normaliser en lowercase |
| 5 | Cache key incomplete | Collision A/AAAA | Inclure record_type |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quel enregistrement DNS cree un alias vers un autre domaine ?

- A) A
- B) MX
- C) CNAME
- D) TXT

**Reponse : C** — CNAME (Canonical Name) cree un alias.

---

### Question 2 (4 points)
Pourquoi limiter la profondeur de resolution CNAME ?

- A) Pour economiser la memoire
- B) Pour eviter la recursion infinie
- C) Pour respecter les standards RFC
- D) Toutes ces raisons

**Reponse : D** — Toutes ces raisons sont valides.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.1.38 |
| **Nom** | dns_resolver |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 95 |
| **Langage** | Python 3.14 |
| **Concepts cles** | DNS, CNAME, cache, TTL, recursion |

---

*Document genere selon HACKBRAIN v5.5.2*
