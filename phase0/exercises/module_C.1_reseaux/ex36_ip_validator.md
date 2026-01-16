# Exercice C.1.36 : ip_validator

**Module :**
C.1 — Reseaux

**Concept :**
36 — Validation d'adresses IP (IPv4/IPv6, publique/privee)

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Syntaxe de base Python
- Manipulation de chaines de caracteres
- Expressions regulieres (basique)

**Domaines :**
Net, Validation, Parsing

**Duree estimee :**
30 min

**XP Base :**
80

**Complexite :**
T1 O(n) × S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `ip_validator.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `re`, `str.split`, `int`, built-ins standards |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | `ipaddress` (module standard), `socket.inet_aton`, `socket.inet_pton` |

---

### 1.2 Consigne

#### Section Culture : "The IP Address"

**THE MATRIX — "Knock, knock, Neo..."**

Dans la Matrix, chaque entite connectee possede une adresse unique. Trinity localise Neo grace a son adresse IP. Sans cette adresse, impossible de communiquer — c'est l'equivalent numerique de ton adresse postale.

Mais attention : toutes les adresses ne se ressemblent pas. Il y a les anciennes (IPv4, 32 bits) et les nouvelles (IPv6, 128 bits). Il y a les publiques (visibles sur Internet) et les privees (cachees derriere un routeur).

*"The Matrix has you... but first, it needs your IP address."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un module de validation d'adresses IP qui :

1. **Valide le format** : Determine si une chaine est une adresse IPv4 ou IPv6 valide
2. **Classifie le type** : IPv4 ou IPv6
3. **Determine la visibilite** : Publique ou privee
4. **Retourne des informations structurees** : Dictionnaire avec toutes les informations

**Entree :**

```python
def validate_ip(ip_string: str) -> dict:
    """
    Valide et classifie une adresse IP.

    Args:
        ip_string: Chaine representant une adresse IP

    Returns:
        dict avec les cles:
            - "valid": bool
            - "version": int (4 ou 6) ou None si invalide
            - "type": str ("public", "private", "loopback", "link-local") ou None
            - "normalized": str (forme canonique) ou None
    """
    pass

def is_valid_ipv4(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv4 valide."""
    pass

def is_valid_ipv6(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv6 valide."""
    pass

def is_private_ip(ip_string: str) -> bool:
    """Determine si l'adresse IP est privee."""
    pass
```

**Sortie :**

```python
>>> validate_ip("192.168.1.1")
{"valid": True, "version": 4, "type": "private", "normalized": "192.168.1.1"}

>>> validate_ip("8.8.8.8")
{"valid": True, "version": 4, "type": "public", "normalized": "8.8.8.8"}

>>> validate_ip("::1")
{"valid": True, "version": 6, "type": "loopback", "normalized": "0000:0000:0000:0000:0000:0000:0000:0001"}

>>> validate_ip("999.999.999.999")
{"valid": False, "version": None, "type": None, "normalized": None}
```

**Contraintes :**

- IPv4 : 4 octets separes par des points, chaque octet entre 0-255
- IPv6 : 8 groupes de 4 chiffres hexadecimaux separes par `:`, compression `::` autorisee
- Plages privees IPv4 : `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Plages privees IPv6 : `fc00::/7` (Unique Local Addresses)
- Loopback : `127.0.0.0/8` (IPv4), `::1` (IPv6)
- Link-local : `169.254.0.0/16` (IPv4), `fe80::/10` (IPv6)

**Exemples :**

| Entree | Sortie (valid) | Version | Type |
|--------|----------------|---------|------|
| `"192.168.1.1"` | True | 4 | private |
| `"8.8.8.8"` | True | 4 | public |
| `"10.0.0.1"` | True | 4 | private |
| `"172.16.0.1"` | True | 4 | private |
| `"127.0.0.1"` | True | 4 | loopback |
| `"169.254.1.1"` | True | 4 | link-local |
| `"256.1.1.1"` | False | None | None |
| `"2001:db8::1"` | True | 6 | public |
| `"::1"` | True | 6 | loopback |
| `"fe80::1"` | True | 6 | link-local |

---

### 1.3 Prototype

```python
def validate_ip(ip_string: str) -> dict:
    """Valide et classifie une adresse IP."""
    pass

def is_valid_ipv4(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv4 valide."""
    pass

def is_valid_ipv6(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv6 valide."""
    pass

def is_private_ip(ip_string: str) -> bool:
    """Determine si l'adresse IP est privee."""
    pass

def get_ip_type(ip_string: str) -> str | None:
    """Retourne le type de l'adresse IP."""
    pass

def normalize_ipv6(ip_string: str) -> str:
    """Normalise une adresse IPv6 en forme complete."""
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**L'epuisement IPv4 est reel !**

Il n'existe que 4,294,967,296 adresses IPv4 possibles (2^32). En 2011, l'IANA a distribue les derniers blocs /8. Aujourd'hui, les FAI recyclent les adresses et utilisent massivement le NAT. IPv6 resout ce probleme avec 340 sextillions d'adresses (2^128) — assez pour donner une adresse a chaque atome sur Terre !

**Les adresses "privees" sont partout !**

Quand tu te connectes chez toi, tu as probablement une adresse en `192.168.x.x`. Cette adresse n'existe pas sur Internet ! Ton routeur fait la traduction (NAT) vers ton adresse publique. C'est comme avoir un numero de telephone interne dans une entreprise.

**Le mystere du 127.0.0.1**

L'adresse `127.0.0.1` (localhost) ne quitte jamais ta machine. Le paquet fait "demi-tour" dans la pile reseau. Tout le bloc `127.0.0.0/8` (16 millions d'adresses) est reserve au loopback — un gaspillage legendaire de l'ere IPv4 !

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps Engineer** | Configurer des firewalls, detecter les IP suspectes |
| **Network Admin** | Planifier l'adressage, detecter les conflits |
| **Security Analyst** | Identifier les sources d'attaque, geolocalisaton IP |
| **Backend Developer** | Valider les inputs utilisateur, rate limiting par IP |
| **Cloud Architect** | Concevoir des VPCs, subnets, peering |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3 -c "
from ip_validator import validate_ip, is_valid_ipv4, is_private_ip

# Test IPv4 valides
print(validate_ip('192.168.1.1'))
# {'valid': True, 'version': 4, 'type': 'private', 'normalized': '192.168.1.1'}

print(validate_ip('8.8.8.8'))
# {'valid': True, 'version': 4, 'type': 'public', 'normalized': '8.8.8.8'}

# Test IPv4 invalides
print(validate_ip('256.1.1.1'))
# {'valid': False, 'version': None, 'type': None, 'normalized': None}

# Test IPv6
print(validate_ip('::1'))
# {'valid': True, 'version': 6, 'type': 'loopback', 'normalized': '0000:0000:0000:0000:0000:0000:0000:0001'}

# Fonctions utilitaires
print(is_valid_ipv4('192.168.1.1'))  # True
print(is_private_ip('10.0.0.1'))     # True
"
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

**Consigne Bonus :**

Ajouter les fonctionnalites suivantes :

1. **Geolocalisation basique** : Identifier les blocs reserves (IANA, APNIC, RIPE, etc.)
2. **Validation CIDR** : Supporter la notation `192.168.1.0/24`
3. **Calcul de plage** : Retourner la premiere et derniere adresse d'un bloc CIDR
4. **Detection de broadcast** : Identifier les adresses de broadcast

```python
def validate_cidr(cidr_string: str) -> dict:
    """
    Valide et analyse une notation CIDR.

    Returns:
        dict avec: network_address, broadcast_address, first_host,
                   last_host, num_hosts, prefix_length
    """
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | valid_ipv4_simple | `"192.168.1.1"` | valid=True, v=4 | 5 | Basic |
| 2 | valid_ipv4_public | `"8.8.8.8"` | valid=True, type=public | 5 | Basic |
| 3 | valid_ipv4_private_10 | `"10.0.0.1"` | type=private | 5 | Classification |
| 4 | valid_ipv4_private_172 | `"172.16.0.1"` | type=private | 5 | Classification |
| 5 | valid_ipv4_private_192 | `"192.168.0.1"` | type=private | 5 | Classification |
| 6 | valid_ipv4_loopback | `"127.0.0.1"` | type=loopback | 5 | Classification |
| 7 | valid_ipv4_linklocal | `"169.254.1.1"` | type=link-local | 5 | Classification |
| 8 | invalid_ipv4_overflow | `"256.1.1.1"` | valid=False | 10 | Edge |
| 9 | invalid_ipv4_negative | `"-1.1.1.1"` | valid=False | 5 | Edge |
| 10 | invalid_ipv4_letters | `"a.b.c.d"` | valid=False | 5 | Edge |
| 11 | invalid_ipv4_missing | `"192.168.1"` | valid=False | 5 | Edge |
| 12 | valid_ipv6_full | `"2001:0db8:0000:0000:0000:0000:0000:0001"` | valid=True | 5 | IPv6 |
| 13 | valid_ipv6_compressed | `"2001:db8::1"` | valid=True | 5 | IPv6 |
| 14 | valid_ipv6_loopback | `"::1"` | type=loopback | 5 | IPv6 |
| 15 | valid_ipv6_linklocal | `"fe80::1"` | type=link-local | 5 | IPv6 |
| 16 | normalize_ipv6 | `"::1"` | `"0000:...0001"` | 10 | Normalize |
| 17 | empty_string | `""` | valid=False | 5 | Edge |
| 18 | whitespace | `" 192.168.1.1 "` | valid=False | 5 | Edge |

**Total : 100 points**

---

### 4.2 Tests unitaires Python

```python
import pytest
from ip_validator import validate_ip, is_valid_ipv4, is_valid_ipv6, is_private_ip

class TestIPv4Validation:
    def test_valid_simple(self):
        result = validate_ip("192.168.1.1")
        assert result["valid"] == True
        assert result["version"] == 4

    def test_valid_public(self):
        result = validate_ip("8.8.8.8")
        assert result["valid"] == True
        assert result["type"] == "public"

    def test_private_10_block(self):
        assert is_private_ip("10.0.0.1") == True
        assert is_private_ip("10.255.255.255") == True

    def test_private_172_block(self):
        assert is_private_ip("172.16.0.1") == True
        assert is_private_ip("172.31.255.255") == True
        assert is_private_ip("172.15.0.1") == False  # Not in range

    def test_private_192_block(self):
        assert is_private_ip("192.168.0.1") == True
        assert is_private_ip("192.167.0.1") == False

    def test_loopback(self):
        result = validate_ip("127.0.0.1")
        assert result["type"] == "loopback"

    def test_linklocal(self):
        result = validate_ip("169.254.1.1")
        assert result["type"] == "link-local"

    def test_invalid_overflow(self):
        assert validate_ip("256.1.1.1")["valid"] == False
        assert validate_ip("192.168.1.256")["valid"] == False

    def test_invalid_format(self):
        assert validate_ip("192.168.1")["valid"] == False
        assert validate_ip("192.168.1.1.1")["valid"] == False
        assert validate_ip("a.b.c.d")["valid"] == False

class TestIPv6Validation:
    def test_valid_full(self):
        result = validate_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert result["valid"] == True
        assert result["version"] == 6

    def test_valid_compressed(self):
        result = validate_ip("2001:db8::1")
        assert result["valid"] == True
        assert result["version"] == 6

    def test_loopback(self):
        result = validate_ip("::1")
        assert result["valid"] == True
        assert result["type"] == "loopback"

    def test_linklocal(self):
        result = validate_ip("fe80::1")
        assert result["type"] == "link-local"

    def test_normalize(self):
        result = validate_ip("::1")
        assert result["normalized"] == "0000:0000:0000:0000:0000:0000:0000:0001"

class TestEdgeCases:
    def test_empty_string(self):
        assert validate_ip("")["valid"] == False

    def test_whitespace(self):
        assert validate_ip(" 192.168.1.1 ")["valid"] == False

    def test_none_handling(self):
        # Should not crash
        try:
            validate_ip(None)
        except TypeError:
            pass  # Expected
```

---

### 4.3 Solution de reference (Python)

```python
import re

def validate_ip(ip_string: str) -> dict:
    """Valide et classifie une adresse IP."""
    result = {
        "valid": False,
        "version": None,
        "type": None,
        "normalized": None
    }

    if not isinstance(ip_string, str) or not ip_string:
        return result

    if is_valid_ipv4(ip_string):
        result["valid"] = True
        result["version"] = 4
        result["type"] = get_ipv4_type(ip_string)
        result["normalized"] = ip_string
    elif is_valid_ipv6(ip_string):
        result["valid"] = True
        result["version"] = 6
        result["type"] = get_ipv6_type(ip_string)
        result["normalized"] = normalize_ipv6(ip_string)

    return result

def is_valid_ipv4(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv4 valide."""
    if not ip_string:
        return False

    parts = ip_string.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part:
            return False
        if not part.isdigit():
            return False
        if len(part) > 1 and part[0] == '0':  # Leading zeros
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False

    return True

def is_valid_ipv6(ip_string: str) -> bool:
    """Verifie si la chaine est une IPv6 valide."""
    if not ip_string:
        return False

    # Handle :: compression
    if ip_string == "::":
        return True

    # Count :: occurrences
    double_colon_count = ip_string.count("::")
    if double_colon_count > 1:
        return False

    if double_colon_count == 1:
        # Expand ::
        parts = ip_string.split("::")
        left = parts[0].split(":") if parts[0] else []
        right = parts[1].split(":") if parts[1] else []

        left = [p for p in left if p]
        right = [p for p in right if p]

        total_groups = len(left) + len(right)
        if total_groups > 7:
            return False

        all_parts = left + right
    else:
        all_parts = ip_string.split(":")
        if len(all_parts) != 8:
            return False

    hex_pattern = re.compile(r'^[0-9a-fA-F]{1,4}$')
    for part in all_parts:
        if not hex_pattern.match(part):
            return False

    return True

def is_private_ip(ip_string: str) -> bool:
    """Determine si l'adresse IP est privee."""
    if is_valid_ipv4(ip_string):
        parts = [int(p) for p in ip_string.split(".")]
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        return False

    if is_valid_ipv6(ip_string):
        normalized = normalize_ipv6(ip_string).lower()
        # fc00::/7 (Unique Local Address)
        first_block = normalized.split(":")[0]
        first_byte = int(first_block[:2], 16)
        if first_byte >= 0xfc and first_byte <= 0xfd:
            return True
        return False

    return False

def get_ipv4_type(ip_string: str) -> str:
    """Retourne le type de l'adresse IPv4."""
    parts = [int(p) for p in ip_string.split(".")]

    # Loopback: 127.0.0.0/8
    if parts[0] == 127:
        return "loopback"

    # Link-local: 169.254.0.0/16
    if parts[0] == 169 and parts[1] == 254:
        return "link-local"

    # Private ranges
    if is_private_ip(ip_string):
        return "private"

    return "public"

def get_ipv6_type(ip_string: str) -> str:
    """Retourne le type de l'adresse IPv6."""
    normalized = normalize_ipv6(ip_string).lower()

    # Loopback: ::1
    if normalized == "0000:0000:0000:0000:0000:0000:0000:0001":
        return "loopback"

    # Link-local: fe80::/10
    first_block = normalized.split(":")[0]
    if first_block.startswith("fe8") or first_block.startswith("fe9") or \
       first_block.startswith("fea") or first_block.startswith("feb"):
        return "link-local"

    # Private (ULA): fc00::/7
    if is_private_ip(ip_string):
        return "private"

    return "public"

def normalize_ipv6(ip_string: str) -> str:
    """Normalise une adresse IPv6 en forme complete."""
    if ip_string == "::":
        return ":".join(["0000"] * 8)

    if "::" in ip_string:
        parts = ip_string.split("::")
        left = parts[0].split(":") if parts[0] else []
        right = parts[1].split(":") if parts[1] else []

        left = [p for p in left if p]
        right = [p for p in right if p]

        missing = 8 - len(left) - len(right)
        middle = ["0000"] * missing

        all_parts = left + middle + right
    else:
        all_parts = ip_string.split(":")

    # Pad each part to 4 characters
    normalized = [part.zfill(4) for part in all_parts]

    return ":".join(normalized)

def get_ip_type(ip_string: str) -> str | None:
    """Retourne le type de l'adresse IP."""
    if is_valid_ipv4(ip_string):
        return get_ipv4_type(ip_string)
    if is_valid_ipv6(ip_string):
        return get_ipv6_type(ip_string)
    return None
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de regex complet pour IPv4**

```python
def is_valid_ipv4_regex(ip_string: str) -> bool:
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip_string))
```

**Alternative 2 : Approche fonctionnelle**

```python
def is_valid_ipv4_functional(ip_string: str) -> bool:
    parts = ip_string.split(".")
    return (len(parts) == 4 and
            all(p.isdigit() and 0 <= int(p) <= 255 and
                (len(p) == 1 or p[0] != '0') for p in parts))
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Utilisation du module ipaddress**

```python
# REFUSE : Utilise le module interdit
import ipaddress

def is_valid_ipv4(ip_string: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except:
        return False
```
**Pourquoi refuse :** L'exercice demande d'implementer la validation manuellement.

**Refus 2 : Accepte les leading zeros**

```python
# REFUSE : Accepte "192.168.001.001"
def is_valid_ipv4(ip_string: str) -> bool:
    parts = ip_string.split(".")
    return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
```
**Pourquoi refuse :** Les leading zeros peuvent etre interpretes comme de l'octal.

**Refus 3 : Ne gere pas la compression IPv6**

```python
# REFUSE : Rejette "::1"
def is_valid_ipv6(ip_string: str) -> bool:
    parts = ip_string.split(":")
    return len(parts) == 8  # Echoue sur ::1
```
**Pourquoi refuse :** La notation `::` est standard et doit etre supportee.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "ip_validator",
  "language": "python",
  "language_version": "3.14",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["moduleC.1", "network", "ip", "validation", "ipv4", "ipv6", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "validate_ip",
    "prototype": "def validate_ip(ip_string: str) -> dict",
    "return_type": "dict",
    "parameters": [
      {"name": "ip_string", "type": "str"}
    ]
  },

  "driver": {
    "reference": "See section 4.3",

    "edge_cases": [
      {
        "name": "empty_string",
        "args": [""],
        "expected": {"valid": false},
        "is_trap": true,
        "trap_explanation": "Chaine vide doit retourner valid=False"
      },
      {
        "name": "ipv4_overflow",
        "args": ["256.1.1.1"],
        "expected": {"valid": false},
        "is_trap": true,
        "trap_explanation": "Octet > 255 est invalide"
      },
      {
        "name": "ipv6_double_compression",
        "args": ["2001::db8::1"],
        "expected": {"valid": false},
        "is_trap": true,
        "trap_explanation": "Double :: est ambigu et invalide"
      },
      {
        "name": "leading_zeros",
        "args": ["192.168.001.001"],
        "expected": {"valid": false},
        "is_trap": true,
        "trap_explanation": "Leading zeros peuvent etre interpretes comme octal"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "string",
          "param_index": 0,
          "params": {"pattern": "ip_like"}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["re", "str.split", "str.isdigit", "int"],
    "forbidden_functions": ["ipaddress", "socket.inet_aton", "socket.inet_pton"],
    "check_security": true,
    "blocking": true
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Off-by-one sur la plage**

```python
# Mutant A (Boundary) : Plage 172.16-30 au lieu de 172.16-31
def is_private_ip(ip_string: str) -> bool:
    parts = [int(p) for p in ip_string.split(".")]
    if parts[0] == 172 and 16 <= parts[1] <= 30:  # ERREUR: devrait etre <= 31
        return True
    # ...
# Pourquoi c'est faux : 172.31.x.x est aussi prive
# Ce qui etait pense : "Le bloc /12 s'arrete a 30"
```

**Mutant B (Logic) : Confusion sur le loopback**

```python
# Mutant B (Logic) : Verifie seulement 127.0.0.1
def get_ipv4_type(ip_string: str) -> str:
    if ip_string == "127.0.0.1":  # ERREUR: tout 127.x.x.x est loopback
        return "loopback"
    # ...
# Pourquoi c'est faux : 127.0.0.2, 127.255.255.255 sont aussi loopback
# Ce qui etait pense : "Seul 127.0.0.1 est loopback"
```

**Mutant C (Validation) : Accepte les leading zeros**

```python
# Mutant C (Validation) : Pas de check leading zeros
def is_valid_ipv4(ip_string: str) -> bool:
    parts = ip_string.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        num = int(part)  # ERREUR: "010" -> 10, mais pourrait etre octal
        if num < 0 or num > 255:
            return False
    return True
# Pourquoi c'est faux : "192.168.001.001" devrait etre invalide
```

**Mutant D (IPv6) : Ne gere pas :: vide**

```python
# Mutant D (IPv6) : Crash sur "::"
def normalize_ipv6(ip_string: str) -> str:
    parts = ip_string.split("::")
    left = parts[0].split(":")  # ERREUR: split("") donne [''] pas []
    right = parts[1].split(":")
    # ...
# Pourquoi c'est faux : "::" devient [''] + [''] = erreur de calcul
# Ce qui etait pense : "split gere les chaines vides"
```

**Mutant E (Return) : Oublie de retourner None**

```python
# Mutant E (Return) : Retourne un dict incomplet
def validate_ip(ip_string: str) -> dict:
    if is_valid_ipv4(ip_string):
        return {
            "valid": True,
            "version": 4,
            "type": get_ipv4_type(ip_string)
            # ERREUR: "normalized" manquant
        }
    # ...
# Pourquoi c'est faux : Le dict retourne n'a pas toutes les cles attendues
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Adressage IPv4 | Structure 32 bits, notation decimale pointee | Fondamental |
| Adressage IPv6 | Structure 128 bits, notation hexadecimale | Essentiel |
| Plages reservees | Private, loopback, link-local | Important |
| Validation d'entrees | Parsing robuste, edge cases | Critique |
| Classification reseau | Public vs prive, NAT | Pratique |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION validate_ip QUI PREND ip_string COMME CHAINE
DEBUT FONCTION
    CREER result COMME DICTIONNAIRE AVEC valid=FAUX, version=NUL, type=NUL, normalized=NUL

    SI ip_string EST VIDE OU N'EST PAS UNE CHAINE ALORS
        RETOURNER result
    FIN SI

    SI is_valid_ipv4(ip_string) EST VRAI ALORS
        AFFECTER VRAI A result["valid"]
        AFFECTER 4 A result["version"]
        AFFECTER get_ipv4_type(ip_string) A result["type"]
        AFFECTER ip_string A result["normalized"]
    SINON SI is_valid_ipv6(ip_string) EST VRAI ALORS
        AFFECTER VRAI A result["valid"]
        AFFECTER 6 A result["version"]
        AFFECTER get_ipv6_type(ip_string) A result["type"]
        AFFECTER normalize_ipv6(ip_string) A result["normalized"]
    FIN SI

    RETOURNER result
FIN FONCTION

FONCTION is_valid_ipv4 QUI PREND ip_string COMME CHAINE
DEBUT FONCTION
    SEPARER ip_string PAR "." DANS parts

    SI LONGUEUR DE parts N'EST PAS EGALE A 4 ALORS
        RETOURNER FAUX
    FIN SI

    POUR CHAQUE part DANS parts FAIRE
        SI part N'EST PAS UN NOMBRE ALORS
            RETOURNER FAUX
        FIN SI
        SI VALEUR DE part < 0 OU > 255 ALORS
            RETOURNER FAUX
        FIN SI
    FIN POUR

    RETOURNER VRAI
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Structure d'une adresse IPv4 :**

```
Adresse IPv4 : 192.168.1.100

    Decimal:   192    .   168    .     1    .   100
               |          |           |          |
    Binaire:  11000000  10101000  00000001  01100100
               |          |           |          |
    Octets:   Octet 1   Octet 2   Octet 3   Octet 4
               |_____|_____|_____|_____|
                         32 bits

Classes d'adresses (historique):
    Classe A: 0xxxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx  (0-127.x.x.x)
    Classe B: 10xxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx  (128-191.x.x.x)
    Classe C: 110xxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx  (192-223.x.x.x)
```

**Plages d'adresses privees IPv4 :**

```
+------------------+-------------------+-------------------+
|      Plage       |   Notation CIDR   |  Nombre d'hotes   |
+------------------+-------------------+-------------------+
| 10.0.0.0 -       |   10.0.0.0/8      |   16,777,214      |
| 10.255.255.255   |                   |                   |
+------------------+-------------------+-------------------+
| 172.16.0.0 -     |   172.16.0.0/12   |   1,048,574       |
| 172.31.255.255   |                   |                   |
+------------------+-------------------+-------------------+
| 192.168.0.0 -    |   192.168.0.0/16  |   65,534          |
| 192.168.255.255  |                   |                   |
+------------------+-------------------+-------------------+
```

**Structure d'une adresse IPv6 :**

```
Adresse IPv6 : 2001:0db8:85a3:0000:0000:8a2e:0370:7334

    |    |    |    |    |    |    |    |    |
   2001:0db8:85a3:0000:0000:8a2e:0370:7334
    |____|____|____|____|____|____|____|____|
           8 groupes de 16 bits = 128 bits

Compression :: :
    2001:0db8:0000:0000:0000:0000:0000:0001
              |____|____|____|____|____|
                   Zeros consecutifs
                         |
                         v
    2001:0db8::1  (forme compacte)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Leading zeros en IPv4

```python
# "010" en Python 3 est une erreur de syntaxe (pas d'octal implicite)
# Mais int("010") = 10, pas 8
# Certains systemes interpretent les leading zeros comme de l'octal

# Exemple dangereux:
# "192.168.01.01" pourrait etre interprete comme 192.168.1.1
# Mais sur certains systemes, c'est invalide ou octal

# Solution: Rejeter les leading zeros
if len(part) > 1 and part[0] == '0':
    return False
```

#### Piege 2 : Double compression IPv6

```python
# "2001::db8::1" est INVALIDE
# On ne peut avoir qu'un seul "::" car sinon c'est ambigu
# Combien de zeros entre les deux :: ?

# Valide:   2001:db8::1         (6 zeros au milieu)
# Invalide: 2001::db8::1        (ambigu)
```

#### Piege 3 : Plage 172.16.0.0/12

```python
# La plage privee 172.16.0.0/12 va de 172.16.0.0 a 172.31.255.255
# PAS de 172.16.0.0 a 172.32.0.0

# Le /12 signifie que les 12 premiers bits sont fixes:
# 172 = 10101100, 16 = 0001xxxx
# Donc 172.16-31.x.x

# Erreur courante: penser que c'est 172.16-32
```

---

### 5.5 Cours Complet

#### 5.5.1 Introduction a l'adressage IP

L'adresse IP (Internet Protocol) est l'identifiant unique d'un appareil sur un reseau. Elle permet l'acheminement des paquets de donnees.

**IPv4 (Internet Protocol version 4)**
- Defini en 1981 (RFC 791)
- 32 bits = 4 octets
- Notation decimale pointee: `192.168.1.1`
- ~4.3 milliards d'adresses possibles

**IPv6 (Internet Protocol version 6)**
- Defini en 1998 (RFC 2460)
- 128 bits = 16 octets
- Notation hexadecimale: `2001:db8::1`
- 3.4 × 10^38 adresses possibles

#### 5.5.2 Classification des adresses

**Adresses publiques**
- Routables sur Internet
- Uniques mondialement
- Attribuees par les RIR (ARIN, RIPE, APNIC, etc.)

**Adresses privees (RFC 1918)**
- Non routables sur Internet
- Reutilisables dans chaque reseau local
- Necessitent NAT pour acceder a Internet

**Adresses speciales**
- Loopback: Communication interne a la machine
- Link-local: Communication sans serveur DHCP
- Broadcast: Envoi a tous les hotes du reseau

---

### 5.6 Normes avec explications pedagogiques

```
+---------------------------------------------------------------+
| HORS NORME (compile, mais interdit)                           |
+---------------------------------------------------------------+
| def is_valid_ipv4(ip): return ipaddress.IPv4Address(ip)       |
+---------------------------------------------------------------+
| CONFORME                                                       |
+---------------------------------------------------------------+
| def is_valid_ipv4(ip_string: str) -> bool:                    |
|     parts = ip_string.split(".")                              |
|     if len(parts) != 4:                                       |
|         return False                                          |
|     for part in parts:                                        |
|         if not part.isdigit():                                |
|             return False                                      |
|         if int(part) < 0 or int(part) > 255:                  |
|             return False                                      |
|     return True                                               |
+---------------------------------------------------------------+
| POURQUOI ?                                                     |
|                                                                |
| - Apprentissage: Comprendre la structure d'une adresse IP     |
| - Pas de dependance: Module ipaddress non disponible partout  |
| - Controle: Gestion precise des edge cases                    |
+---------------------------------------------------------------+
```

---

### 5.7 Simulation avec trace d'execution

**Scenario : Validation de "192.168.1.1"**

```
+-------+----------------------------------+------------------+
| Etape | Operation                        | Resultat         |
+-------+----------------------------------+------------------+
|   1   | validate_ip("192.168.1.1")       | Debut            |
|   2   | is_valid_ipv4("192.168.1.1")     | Appel            |
|   3   | split(".") -> ["192","168","1","1"] | 4 parties     |
|   4   | len(parts) == 4 ?                | OUI              |
|   5   | "192".isdigit() ?                | OUI              |
|   6   | 0 <= 192 <= 255 ?                | OUI              |
|   7   | "168".isdigit() ?                | OUI              |
|   8   | 0 <= 168 <= 255 ?                | OUI              |
|   9   | "1".isdigit() ?                  | OUI              |
|  10   | 0 <= 1 <= 255 ?                  | OUI              |
|  11   | is_valid_ipv4 -> True            | IPv4 valide      |
|  12   | get_ipv4_type("192.168.1.1")     | Appel            |
|  13   | parts[0] == 127 ?                | NON (192)        |
|  14   | parts[0]==169, parts[1]==254 ?   | NON              |
|  15   | is_private_ip() ?                | Appel            |
|  16   | parts[0]==192, parts[1]==168 ?   | OUI -> private   |
|  17   | Retourne dict avec type=private  | Resultat final   |
+-------+----------------------------------+------------------+
```

---

### 5.8 Mnemotechniques

#### MEME : "There's No Place Like 127.0.0.1"

```
     _________________________
    |                         |
    |  There's No Place Like  |
    |       127.0.0.1         |
    |      (localhost)        |
    |_________________________|

"Home is where the loopback is"
```

#### MEME : Les plages privees

```
10.x.x.x       = "DIX millions d'adresses pour ton reseau"
172.16-31.x.x  = "Le MILIEU du terrain (16 a 31)"
192.168.x.x    = "L'adresse de MAISON (home network)"
```

---

### 5.9 Applications pratiques

| Application | Utilisation |
|-------------|-------------|
| Firewall | Bloquer les IP malveillantes |
| Load Balancer | Distribuer le trafic par IP source |
| Geolocalisation | Determiner le pays d'origine |
| Rate Limiting | Limiter les requetes par IP |
| Logging | Identifier les utilisateurs |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Leading zeros IPv4 | Interpretation octale | Rejeter si len>1 et start='0' |
| 2 | Double :: IPv6 | Ambiguite | Compter occurrences de :: |
| 3 | Plage 172.16/12 | Mauvaise classification | 172.16-31, pas 172.16-32 |
| 4 | Chaine vide | Crash sur split | Verifier avant traitement |
| 5 | Whitespace | Faux positif | Ne pas trimmer automatiquement |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle plage d'adresses est privee ?

- A) 8.8.8.0/24
- B) 172.32.0.0/16
- C) 192.168.0.0/16
- D) 224.0.0.0/8
- E) 169.254.0.0/16

**Reponse : C** — 192.168.0.0/16 est une plage privee RFC 1918.

---

### Question 2 (3 points)
Combien de bits contient une adresse IPv6 ?

- A) 32
- B) 64
- C) 128
- D) 256

**Reponse : C** — IPv6 utilise 128 bits (16 octets).

---

### Question 3 (4 points)
Quelle forme IPv6 est invalide ?

- A) ::1
- B) 2001:db8::1
- C) 2001::db8::1
- D) fe80::1

**Reponse : C** — Double :: est ambigu et donc invalide.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.1.36 |
| **Nom** | ip_validator |
| **Difficulte** | 3/10 |
| **Duree** | 30 min |
| **XP Base** | 80 |
| **Langage** | Python 3.14 |
| **Concepts cles** | IPv4, IPv6, validation, classification |

---

*Document genere selon HACKBRAIN v5.5.2*
