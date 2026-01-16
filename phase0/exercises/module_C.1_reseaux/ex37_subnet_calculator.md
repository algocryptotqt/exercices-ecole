# Exercice C.1.37 : subnet_calculator

**Module :**
C.1 — Reseaux

**Concept :**
37 — Calcul de sous-reseaux (Subnet mask, CIDR, Network address)

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Syntaxe de base Python
- Manipulation de bits
- Conversion binaire/decimal
- Exercice ex36_ip_validator

**Domaines :**
Net, Binary, Algo

**Duree estimee :**
40 min

**XP Base :**
90

**Complexite :**
T1 O(1) × S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `subnet_calculator.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `int`, `bin`, `str`, operateurs binaires (`&`, `|`, `^`, `~`, `<<`, `>>`) |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | `ipaddress`, `netaddr`, bibliotheques reseau tierces |

---

### 1.2 Consigne

#### Section Culture : "Divide and Conquer"

**MR. ROBOT — "Every network has its secrets"**

Elliot sait que chaque reseau d'entreprise est divise en sous-reseaux. Les serveurs de production sont isoles des postes de travail. Les cameras de surveillance ont leur propre segment. Cette segmentation est la premiere ligne de defense.

Pour comprendre un reseau, il faut maitriser le subnetting : comment une adresse IP et un masque definissent un territoire numerique.

*"A subnet is like a room in a building. The mask tells you which floor you're on."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un calculateur de sous-reseaux qui :

1. **Parse la notation CIDR** : Extraire l'adresse et le prefixe
2. **Calcule l'adresse reseau** : Appliquer le masque a l'adresse
3. **Calcule l'adresse de broadcast** : Derniere adresse du sous-reseau
4. **Determine la plage d'hotes** : Premiere et derniere adresse utilisable
5. **Compte les hotes possibles** : 2^(32-prefix) - 2

**Entree :**

```python
def parse_cidr(cidr: str) -> tuple[str, int]:
    """
    Parse une notation CIDR.

    Args:
        cidr: Chaine au format "192.168.1.0/24"

    Returns:
        Tuple (adresse_ip, prefix_length)
    """
    pass

def calculate_subnet(cidr: str) -> dict:
    """
    Calcule toutes les informations d'un sous-reseau.

    Args:
        cidr: Notation CIDR (ex: "192.168.1.0/24")

    Returns:
        dict avec:
            - "network_address": str
            - "broadcast_address": str
            - "subnet_mask": str
            - "wildcard_mask": str
            - "first_host": str
            - "last_host": str
            - "num_hosts": int
            - "prefix_length": int
    """
    pass

def ip_to_int(ip: str) -> int:
    """Convertit une adresse IP en entier 32 bits."""
    pass

def int_to_ip(num: int) -> str:
    """Convertit un entier 32 bits en adresse IP."""
    pass

def is_ip_in_subnet(ip: str, cidr: str) -> bool:
    """Verifie si une IP appartient a un sous-reseau."""
    pass
```

**Sortie :**

```python
>>> calculate_subnet("192.168.1.0/24")
{
    "network_address": "192.168.1.0",
    "broadcast_address": "192.168.1.255",
    "subnet_mask": "255.255.255.0",
    "wildcard_mask": "0.0.0.255",
    "first_host": "192.168.1.1",
    "last_host": "192.168.1.254",
    "num_hosts": 254,
    "prefix_length": 24
}

>>> calculate_subnet("10.0.0.0/8")
{
    "network_address": "10.0.0.0",
    "broadcast_address": "10.255.255.255",
    "subnet_mask": "255.0.0.0",
    "wildcard_mask": "0.255.255.255",
    "first_host": "10.0.0.1",
    "last_host": "10.255.255.254",
    "num_hosts": 16777214,
    "prefix_length": 8
}

>>> is_ip_in_subnet("192.168.1.100", "192.168.1.0/24")
True

>>> is_ip_in_subnet("192.168.2.1", "192.168.1.0/24")
False
```

**Contraintes :**

- Prefix length : 0 a 32 (IPv4 uniquement)
- Gerer /31 (2 hotes, point-to-point) et /32 (1 hote)
- Le masque de sous-reseau doit etre contigu (pas de trous)
- Wildcard mask = inverse bit a bit du subnet mask

**Exemples :**

| CIDR | Network | Broadcast | Hosts |
|------|---------|-----------|-------|
| `192.168.1.0/24` | 192.168.1.0 | 192.168.1.255 | 254 |
| `10.0.0.0/8` | 10.0.0.0 | 10.255.255.255 | 16,777,214 |
| `172.16.0.0/16` | 172.16.0.0 | 172.16.255.255 | 65,534 |
| `192.168.1.128/25` | 192.168.1.128 | 192.168.1.255 | 126 |
| `192.168.1.64/26` | 192.168.1.64 | 192.168.1.127 | 62 |

---

### 1.3 Prototype

```python
def parse_cidr(cidr: str) -> tuple[str, int]:
    """Parse une notation CIDR."""
    pass

def calculate_subnet(cidr: str) -> dict:
    """Calcule toutes les informations d'un sous-reseau."""
    pass

def ip_to_int(ip: str) -> int:
    """Convertit une adresse IP en entier 32 bits."""
    pass

def int_to_ip(num: int) -> str:
    """Convertit un entier 32 bits en adresse IP."""
    pass

def prefix_to_mask(prefix: int) -> int:
    """Convertit un prefix length en masque entier."""
    pass

def is_ip_in_subnet(ip: str, cidr: str) -> bool:
    """Verifie si une IP appartient a un sous-reseau."""
    pass

def get_subnet_mask(prefix: int) -> str:
    """Retourne le masque de sous-reseau en notation decimale."""
    pass

def get_wildcard_mask(prefix: int) -> str:
    """Retourne le wildcard mask."""
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Le CIDR a sauve Internet !**

Avant CIDR (1993), on utilisait les classes A, B, C. Une entreprise qui avait besoin de 300 adresses devait prendre une classe B (65,534 adresses) — un gaspillage enorme ! CIDR permet une allocation flexible : exactement ce dont on a besoin.

**Les /31 sont speciaux**

Un /31 n'a que 2 adresses : pas de network address ni broadcast. C'est parfait pour les liens point-to-point entre routeurs. Defini dans RFC 3021.

**Le wildcard mask des routeurs Cisco**

Cisco utilise le "wildcard mask" (inverse du subnet mask) dans ses ACLs. `0.0.0.255` signifie "ignore les 8 derniers bits" = match tout le /24. C'est contre-intuitif mais tres puissant !

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Network Engineer** | Planifier l'adressage IP d'une entreprise |
| **Cloud Architect** | Definir les VPCs et subnets AWS/GCP/Azure |
| **Security Engineer** | Configurer les regles de firewall par subnet |
| **DevOps** | Configurer les reseaux Docker/Kubernetes |
| **ISP Engineer** | Allouer des blocs IP aux clients |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3 -c "
from subnet_calculator import calculate_subnet, is_ip_in_subnet

# Calcul d'un sous-reseau /24
result = calculate_subnet('192.168.1.0/24')
print(f'Network: {result[\"network_address\"]}')
print(f'Broadcast: {result[\"broadcast_address\"]}')
print(f'Mask: {result[\"subnet_mask\"]}')
print(f'Hosts: {result[\"num_hosts\"]}')
print(f'Range: {result[\"first_host\"]} - {result[\"last_host\"]}')

# Verification d'appartenance
print(is_ip_in_subnet('192.168.1.100', '192.168.1.0/24'))  # True
print(is_ip_in_subnet('192.168.2.1', '192.168.1.0/24'))    # False
"
```

**Sortie :**
```
Network: 192.168.1.0
Broadcast: 192.168.1.255
Mask: 255.255.255.0
Hosts: 254
Range: 192.168.1.1 - 192.168.1.254
True
False
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer les fonctionnalites avancees :

1. **Supernetting** : Agreger plusieurs sous-reseaux contigus
2. **Subnetting** : Diviser un sous-reseau en N sous-reseaux egaux
3. **VLSM** : Variable Length Subnet Masking pour allocation optimale

```python
def supernet(cidrs: list[str]) -> str | None:
    """
    Agregre des sous-reseaux contigus en un supernet.
    Retourne None si non contigus.
    """
    pass

def subnet_divide(cidr: str, num_subnets: int) -> list[str]:
    """
    Divise un sous-reseau en N sous-reseaux egaux.
    N doit etre une puissance de 2.
    """
    pass

def vlsm_allocate(cidr: str, host_requirements: list[int]) -> list[dict]:
    """
    Alloue des sous-reseaux de taille variable selon les besoins.
    host_requirements: liste du nombre d'hotes requis par sous-reseau.
    """
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | basic_24 | `"192.168.1.0/24"` | network=192.168.1.0 | 5 | Basic |
| 2 | broadcast_24 | `"192.168.1.0/24"` | broadcast=192.168.1.255 | 5 | Basic |
| 3 | hosts_24 | `"192.168.1.0/24"` | num_hosts=254 | 5 | Basic |
| 4 | mask_24 | `"192.168.1.0/24"` | mask=255.255.255.0 | 5 | Basic |
| 5 | basic_8 | `"10.0.0.0/8"` | network=10.0.0.0 | 5 | Class A |
| 6 | hosts_8 | `"10.0.0.0/8"` | num_hosts=16777214 | 5 | Class A |
| 7 | basic_16 | `"172.16.0.0/16"` | network=172.16.0.0 | 5 | Class B |
| 8 | subnet_25 | `"192.168.1.128/25"` | network=192.168.1.128 | 10 | VLSM |
| 9 | subnet_26 | `"192.168.1.64/26"` | broadcast=192.168.1.127 | 10 | VLSM |
| 10 | ip_in_subnet_true | `is_ip_in_subnet("192.168.1.50", "/24")` | True | 5 | Membership |
| 11 | ip_in_subnet_false | `is_ip_in_subnet("192.168.2.1", "/24")` | False | 5 | Membership |
| 12 | edge_31 | `"10.0.0.0/31"` | num_hosts=2 | 10 | Edge |
| 13 | edge_32 | `"10.0.0.1/32"` | num_hosts=1 | 10 | Edge |
| 14 | wildcard_mask | `"192.168.1.0/24"` | wildcard=0.0.0.255 | 5 | Wildcard |
| 15 | ip_to_int | `"255.255.255.255"` | 4294967295 | 5 | Conversion |

**Total : 100 points**

---

### 4.2 Tests unitaires Python

```python
import pytest
from subnet_calculator import (
    calculate_subnet, is_ip_in_subnet, ip_to_int, int_to_ip,
    parse_cidr, prefix_to_mask
)

class TestConversions:
    def test_ip_to_int(self):
        assert ip_to_int("0.0.0.0") == 0
        assert ip_to_int("255.255.255.255") == 4294967295
        assert ip_to_int("192.168.1.1") == 3232235777

    def test_int_to_ip(self):
        assert int_to_ip(0) == "0.0.0.0"
        assert int_to_ip(4294967295) == "255.255.255.255"
        assert int_to_ip(3232235777) == "192.168.1.1"

    def test_roundtrip(self):
        ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        for ip in ips:
            assert int_to_ip(ip_to_int(ip)) == ip

class TestSubnetCalculation:
    def test_slash_24(self):
        result = calculate_subnet("192.168.1.0/24")
        assert result["network_address"] == "192.168.1.0"
        assert result["broadcast_address"] == "192.168.1.255"
        assert result["subnet_mask"] == "255.255.255.0"
        assert result["wildcard_mask"] == "0.0.0.255"
        assert result["first_host"] == "192.168.1.1"
        assert result["last_host"] == "192.168.1.254"
        assert result["num_hosts"] == 254

    def test_slash_8(self):
        result = calculate_subnet("10.0.0.0/8")
        assert result["network_address"] == "10.0.0.0"
        assert result["broadcast_address"] == "10.255.255.255"
        assert result["num_hosts"] == 16777214

    def test_slash_25(self):
        result = calculate_subnet("192.168.1.128/25")
        assert result["network_address"] == "192.168.1.128"
        assert result["broadcast_address"] == "192.168.1.255"
        assert result["num_hosts"] == 126

    def test_slash_31(self):
        result = calculate_subnet("10.0.0.0/31")
        assert result["num_hosts"] == 2
        assert result["first_host"] == "10.0.0.0"
        assert result["last_host"] == "10.0.0.1"

    def test_slash_32(self):
        result = calculate_subnet("10.0.0.1/32")
        assert result["num_hosts"] == 1
        assert result["first_host"] == "10.0.0.1"
        assert result["last_host"] == "10.0.0.1"

class TestMembership:
    def test_ip_in_subnet(self):
        assert is_ip_in_subnet("192.168.1.100", "192.168.1.0/24") == True
        assert is_ip_in_subnet("192.168.1.1", "192.168.1.0/24") == True
        assert is_ip_in_subnet("192.168.1.254", "192.168.1.0/24") == True

    def test_ip_not_in_subnet(self):
        assert is_ip_in_subnet("192.168.2.1", "192.168.1.0/24") == False
        assert is_ip_in_subnet("10.0.0.1", "192.168.1.0/24") == False

    def test_boundary(self):
        # Network address is technically in the subnet
        assert is_ip_in_subnet("192.168.1.0", "192.168.1.0/24") == True
        # Broadcast address is technically in the subnet
        assert is_ip_in_subnet("192.168.1.255", "192.168.1.0/24") == True
```

---

### 4.3 Solution de reference (Python)

```python
def ip_to_int(ip: str) -> int:
    """Convertit une adresse IP en entier 32 bits."""
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
           (int(parts[2]) << 8) + int(parts[3])

def int_to_ip(num: int) -> str:
    """Convertit un entier 32 bits en adresse IP."""
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"

def prefix_to_mask(prefix: int) -> int:
    """Convertit un prefix length en masque entier."""
    if prefix == 0:
        return 0
    return ((1 << 32) - 1) << (32 - prefix)

def parse_cidr(cidr: str) -> tuple[str, int]:
    """Parse une notation CIDR."""
    parts = cidr.split("/")
    ip = parts[0]
    prefix = int(parts[1])
    return (ip, prefix)

def get_subnet_mask(prefix: int) -> str:
    """Retourne le masque de sous-reseau en notation decimale."""
    mask_int = prefix_to_mask(prefix)
    return int_to_ip(mask_int)

def get_wildcard_mask(prefix: int) -> str:
    """Retourne le wildcard mask."""
    mask_int = prefix_to_mask(prefix)
    wildcard_int = ~mask_int & 0xFFFFFFFF
    return int_to_ip(wildcard_int)

def calculate_subnet(cidr: str) -> dict:
    """Calcule toutes les informations d'un sous-reseau."""
    ip, prefix = parse_cidr(cidr)
    ip_int = ip_to_int(ip)
    mask_int = prefix_to_mask(prefix)

    # Network address: IP AND mask
    network_int = ip_int & mask_int

    # Broadcast address: network OR (NOT mask)
    broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)

    # Number of hosts
    if prefix == 32:
        num_hosts = 1
        first_host_int = network_int
        last_host_int = network_int
    elif prefix == 31:
        num_hosts = 2
        first_host_int = network_int
        last_host_int = broadcast_int
    else:
        num_hosts = (1 << (32 - prefix)) - 2
        first_host_int = network_int + 1
        last_host_int = broadcast_int - 1

    return {
        "network_address": int_to_ip(network_int),
        "broadcast_address": int_to_ip(broadcast_int),
        "subnet_mask": get_subnet_mask(prefix),
        "wildcard_mask": get_wildcard_mask(prefix),
        "first_host": int_to_ip(first_host_int),
        "last_host": int_to_ip(last_host_int),
        "num_hosts": num_hosts,
        "prefix_length": prefix
    }

def is_ip_in_subnet(ip: str, cidr: str) -> bool:
    """Verifie si une IP appartient a un sous-reseau."""
    network_ip, prefix = parse_cidr(cidr)
    mask_int = prefix_to_mask(prefix)

    ip_int = ip_to_int(ip)
    network_int = ip_to_int(network_ip) & mask_int

    return (ip_int & mask_int) == network_int
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de format strings**

```python
def int_to_ip_format(num: int) -> str:
    return ".".join(str((num >> (8 * i)) & 255) for i in range(3, -1, -1))
```

**Alternative 2 : Approche avec bytes**

```python
def ip_to_int_bytes(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return int.from_bytes(bytes(parts), 'big')

def int_to_ip_bytes(num: int) -> str:
    return ".".join(str(b) for b in num.to_bytes(4, 'big'))
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Utilisation de ipaddress**

```python
# REFUSE : Module interdit
import ipaddress
def calculate_subnet(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    return {"network_address": str(network.network_address), ...}
```

**Refus 2 : Mauvais calcul du nombre d'hotes pour /31**

```python
# REFUSE : Ne gere pas /31 correctement
def calculate_subnet(cidr):
    prefix = int(cidr.split("/")[1])
    num_hosts = (2 ** (32 - prefix)) - 2  # ERREUR: -2 pour /31 donne 0
```

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "subnet_calculator",
  "language": "python",
  "language_version": "3.14",
  "type": "code",
  "tier": 1,
  "tags": ["moduleC.1", "network", "subnet", "cidr", "binary", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "calculate_subnet",
    "prototype": "def calculate_subnet(cidr: str) -> dict",
    "return_type": "dict",
    "parameters": [{"name": "cidr", "type": "str"}]
  },

  "driver": {
    "edge_cases": [
      {
        "name": "slash_31",
        "args": ["10.0.0.0/31"],
        "expected": {"num_hosts": 2},
        "is_trap": true,
        "trap_explanation": "/31 a 2 hotes sans network/broadcast dedies"
      },
      {
        "name": "slash_32",
        "args": ["10.0.0.1/32"],
        "expected": {"num_hosts": 1},
        "is_trap": true,
        "trap_explanation": "/32 est une adresse unique"
      }
    ]
  },

  "norm": {
    "allowed_functions": ["int", "bin", "str", "bitwise_operators"],
    "forbidden_functions": ["ipaddress", "netaddr"],
    "check_security": true,
    "blocking": true
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Oublie le cas /31**

```python
# Mutant A: Toujours soustrait 2 pour les hotes
def calculate_subnet(cidr):
    prefix = int(cidr.split("/")[1])
    num_hosts = (2 ** (32 - prefix)) - 2  # ERREUR: /31 -> 0, /32 -> -1
# Pourquoi c'est faux: /31 et /32 sont des cas speciaux
```

**Mutant B (Logic) : Mauvais calcul du masque**

```python
# Mutant B: Masque inverse
def prefix_to_mask(prefix):
    return (1 << (32 - prefix)) - 1  # ERREUR: c'est le wildcard, pas le masque
# Pourquoi c'est faux: Donne le wildcard au lieu du subnet mask
```

**Mutant C (Binary) : Oublie le AND avec 0xFFFFFFFF**

```python
# Mutant C: Pas de limitation a 32 bits
def get_wildcard_mask(prefix):
    mask_int = prefix_to_mask(prefix)
    wildcard_int = ~mask_int  # ERREUR: nombre negatif en Python
    return int_to_ip(wildcard_int)
# Pourquoi c'est faux: ~0xFF... donne un nombre negatif, pas 0x00...
```

**Mutant D (Conversion) : Mauvais ordre des octets**

```python
# Mutant D: Little endian au lieu de big endian
def ip_to_int(ip):
    parts = ip.split(".")
    return int(parts[3]) << 24 | int(parts[2]) << 16 | int(parts[1]) << 8 | int(parts[0])
# Pourquoi c'est faux: 192.168.1.1 devient 1.1.168.192
```

**Mutant E (Off-by-one) : first_host/last_host incorrects**

```python
# Mutant E: N'ajoute pas 1 au network pour first_host
def calculate_subnet(cidr):
    # ...
    first_host_int = network_int  # ERREUR: devrait etre network_int + 1
    last_host_int = broadcast_int  # ERREUR: devrait etre broadcast_int - 1
# Pourquoi c'est faux: Network et broadcast ne sont pas des hotes valides
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Notation CIDR | Representation compacte des sous-reseaux | Fondamental |
| Masque de sous-reseau | Separation partie reseau/hote | Fondamental |
| Operations binaires | AND, OR, NOT sur les adresses | Essentiel |
| Calcul de plages | Determiner les adresses utilisables | Pratique |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION calculate_subnet QUI PREND cidr COMME CHAINE
DEBUT FONCTION
    EXTRAIRE ip ET prefix DE cidr

    CALCULER mask_int COMME ((1 DECALE DE 32) - 1) DECALE DE (32 - prefix)

    CALCULER network_int COMME ip_int ET mask_int (operation AND)

    CALCULER broadcast_int COMME network_int OU (NON mask_int) (operation OR)

    SI prefix EST EGAL A 32 ALORS
        num_hosts = 1
    SINON SI prefix EST EGAL A 31 ALORS
        num_hosts = 2
    SINON
        num_hosts = 2 PUISSANCE (32 - prefix) MOINS 2
    FIN SI

    RETOURNER DICTIONNAIRE AVEC TOUTES LES VALEURS
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Structure d'un sous-reseau /24 :**

```
192.168.1.0/24

Adresse IP:     11000000.10101000.00000001.00000000
Masque (/24):   11111111.11111111.11111111.00000000
                |------ Partie Reseau ------||Hotes|

Network:        11000000.10101000.00000001.00000000 = 192.168.1.0
Broadcast:      11000000.10101000.00000001.11111111 = 192.168.1.255
First Host:     11000000.10101000.00000001.00000001 = 192.168.1.1
Last Host:      11000000.10101000.00000001.11111110 = 192.168.1.254

Nombre d'hotes: 2^8 - 2 = 254
```

**Division d'un /24 en /25 :**

```
192.168.1.0/24 divise en deux /25:

192.168.1.0/25:
+-------------------+-------------------+
| Network: .0       | Broadcast: .127   |
| Hosts: .1 - .126  | (126 hotes)       |
+-------------------+-------------------+

192.168.1.128/25:
+-------------------+-------------------+
| Network: .128     | Broadcast: .255   |
| Hosts: .129 - .254| (126 hotes)       |
+-------------------+-------------------+
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Nombres negatifs en Python avec NOT

```python
# Python: ~0 = -1 (pas 0xFFFFFFFF)
mask = 0xFF000000
wildcard = ~mask        # -4278190081 (negatif!)
wildcard = ~mask & 0xFFFFFFFF  # 16777215 (correct)
```

#### Piege 2 : /31 et /32 sont speciaux

```python
# /31: Point-to-point, pas de network/broadcast dedies
# /32: Une seule adresse (host route)

# Ne pas faire: 2^(32-31) - 2 = 0 hotes (faux!)
# Faire: cas special, 2 hotes pour /31, 1 pour /32
```

---

### 5.5 Cours Complet

#### 5.5.1 La notation CIDR

CIDR (Classless Inter-Domain Routing) remplace les classes A/B/C :

| Notation | Signification |
|----------|---------------|
| /8 | Masque 255.0.0.0 |
| /16 | Masque 255.255.0.0 |
| /24 | Masque 255.255.255.0 |
| /25 | Masque 255.255.255.128 |
| /26 | Masque 255.255.255.192 |

#### 5.5.2 Calcul du masque

Le masque est une suite de 1 suivie de 0 :

```
/24 = 11111111.11111111.11111111.00000000 = 255.255.255.0
/25 = 11111111.11111111.11111111.10000000 = 255.255.255.128
/26 = 11111111.11111111.11111111.11000000 = 255.255.255.192
```

Formule : `mask = ((1 << 32) - 1) << (32 - prefix)`

---

### 5.7 Simulation avec trace d'execution

```
calculate_subnet("192.168.1.0/24")

+-------+----------------------------------+----------------------------+
| Etape | Operation                        | Resultat                   |
+-------+----------------------------------+----------------------------+
|   1   | parse_cidr("192.168.1.0/24")     | ("192.168.1.0", 24)        |
|   2   | ip_to_int("192.168.1.0")         | 3232235776                 |
|   3   | prefix_to_mask(24)               | 4294967040 (0xFFFFFF00)    |
|   4   | network = ip & mask              | 3232235776 (192.168.1.0)   |
|   5   | broadcast = network | ~mask      | 3232236031 (192.168.1.255) |
|   6   | num_hosts = 2^8 - 2              | 254                        |
|   7   | first_host = network + 1         | 192.168.1.1                |
|   8   | last_host = broadcast - 1        | 192.168.1.254              |
+-------+----------------------------------+----------------------------+
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | NOT en Python | Nombres negatifs | AND avec 0xFFFFFFFF |
| 2 | /31 et /32 | 0 ou -1 hotes | Cas speciaux |
| 3 | Ordre des octets | IP inversee | Big endian (MSB first) |
| 4 | Network/Broadcast comme hotes | Comptage faux | -2 sauf cas speciaux |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Combien d'hotes utilisables dans un /24 ?

- A) 256
- B) 255
- C) 254
- D) 252

**Reponse : C** — 2^8 - 2 = 254 (network et broadcast exclus)

---

### Question 2 (4 points)
Quel est le masque pour /26 ?

- A) 255.255.255.0
- B) 255.255.255.128
- C) 255.255.255.192
- D) 255.255.255.224

**Reponse : C** — 26 bits a 1 = 255.255.255.192

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.1.37 |
| **Nom** | subnet_calculator |
| **Difficulte** | 4/10 |
| **Duree** | 40 min |
| **XP Base** | 90 |
| **Langage** | Python 3.14 |
| **Concepts cles** | CIDR, subnet mask, binary operations |

---

*Document genere selon HACKBRAIN v5.5.2*
