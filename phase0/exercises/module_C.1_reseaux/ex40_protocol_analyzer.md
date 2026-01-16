# Exercice C.1.40 : protocol_analyzer

**Module :**
C.1 — Reseaux

**Concept :**
40 — Analyse de protocoles (OSI model, TCP vs UDP, Ports)

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
- Structures de donnees (dict, list)
- Notions de base sur les reseaux

**Domaines :**
Net, Protocol, Analysis

**Duree estimee :**
35 min

**XP Base :**
85

**Complexite :**
T1 O(n) × S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `protocol_analyzer.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `dict`, `list`, `struct`, `int`, built-ins standards |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | `scapy`, `dpkt`, bibliotheques de packet parsing |

---

### 1.2 Consigne

#### Section Culture : "Layers of the Network"

**HACKERS (1995) — "Mess with the best, die like the rest"**

Quand les hackers de 1995 penetraient les reseaux, ils devaient comprendre chaque couche. De l'Ethernet au TCP, chaque protocole a ses secrets. Le modele OSI n'est pas qu'une theorie academique — c'est la carte au tresor des networks.

Savoir si un paquet est TCP ou UDP, connaitre les ports standards, identifier les protocoles... C'est le B.A.-BA de l'analyse reseau.

*"Every packet tells a story. Learn to read the headers, and you'll understand the network."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un analyseur de protocoles qui :

1. **Identifie les couches OSI** : Physique a Application
2. **Distingue TCP et UDP** : Caracteristiques et use cases
3. **Connait les ports standards** : Well-known ports (0-1023)
4. **Analyse des headers simples** : Extraction d'informations basiques

**Entree :**

```python
class ProtocolInfo:
    """Informations sur un protocole."""
    def __init__(self, name: str, layer: int, description: str):
        self.name = name
        self.layer = layer  # 1-7 OSI
        self.description = description

class PortInfo:
    """Informations sur un port."""
    def __init__(self, number: int, protocol: str, service: str):
        self.number = number
        self.protocol = protocol  # TCP, UDP, ou les deux
        self.service = service

def get_osi_layer(layer_number: int) -> dict:
    """
    Retourne les informations sur une couche OSI.

    Args:
        layer_number: Numero de la couche (1-7)

    Returns:
        dict avec: name, protocols, description, examples
    """
    pass

def get_port_info(port: int) -> PortInfo | None:
    """
    Retourne les informations sur un port well-known.

    Args:
        port: Numero de port (0-65535)

    Returns:
        PortInfo ou None si inconnu
    """
    pass

def compare_tcp_udp() -> dict:
    """
    Compare TCP et UDP.

    Returns:
        dict avec les caracteristiques de chaque protocole
    """
    pass

def identify_protocol_by_port(port: int, transport: str = "TCP") -> str | None:
    """
    Identifie le protocole applicatif probable pour un port.

    Args:
        port: Numero de port
        transport: "TCP" ou "UDP"

    Returns:
        Nom du protocole ou None
    """
    pass

def parse_tcp_header(data: bytes) -> dict:
    """
    Parse un header TCP basique (sans options).

    Args:
        data: 20 bytes minimum

    Returns:
        dict avec: src_port, dst_port, seq_num, ack_num, flags
    """
    pass
```

**Sortie :**

```python
>>> get_osi_layer(4)
{
    "name": "Transport",
    "protocols": ["TCP", "UDP", "SCTP"],
    "description": "Segmentation, controle de flux, fiabilite",
    "examples": ["Port source/destination", "Numeros de sequence"]
}

>>> get_port_info(80)
PortInfo(number=80, protocol="TCP", service="HTTP")

>>> get_port_info(53)
PortInfo(number=53, protocol="TCP/UDP", service="DNS")

>>> compare_tcp_udp()
{
    "TCP": {"reliable": True, "ordered": True, "connection": True, ...},
    "UDP": {"reliable": False, "ordered": False, "connection": False, ...}
}

>>> identify_protocol_by_port(443, "TCP")
"HTTPS"
```

**Contraintes :**

- Couches OSI : 1 (Physique) a 7 (Application)
- Ports well-known : 0-1023 (quelques-uns a connaitre)
- Gerer les ports utilises par TCP et UDP

**Ports well-known a connaitre :**

| Port | Protocol | Service |
|------|----------|---------|
| 20 | TCP | FTP Data |
| 21 | TCP | FTP Control |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS |
| 3306 | TCP | MySQL |
| 5432 | TCP | PostgreSQL |
| 6379 | TCP | Redis |
| 27017 | TCP | MongoDB |

---

### 1.3 Prototype

```python
from dataclasses import dataclass
from typing import Optional
import struct

@dataclass
class ProtocolInfo:
    name: str
    layer: int
    description: str

@dataclass
class PortInfo:
    number: int
    protocol: str
    service: str

def get_osi_layer(layer_number: int) -> dict:
    """Retourne les informations sur une couche OSI."""
    pass

def get_osi_layer_name(layer_number: int) -> str:
    """Retourne le nom d'une couche OSI."""
    pass

def get_port_info(port: int) -> Optional[PortInfo]:
    """Retourne les informations sur un port well-known."""
    pass

def compare_tcp_udp() -> dict:
    """Compare TCP et UDP."""
    pass

def identify_protocol_by_port(port: int, transport: str = "TCP") -> Optional[str]:
    """Identifie le protocole applicatif probable pour un port."""
    pass

def parse_tcp_header(data: bytes) -> dict:
    """Parse un header TCP basique."""
    pass

def parse_udp_header(data: bytes) -> dict:
    """Parse un header UDP."""
    pass

def get_tcp_flags(flags_byte: int) -> dict:
    """Decode les flags TCP."""
    pass

def is_well_known_port(port: int) -> bool:
    """Verifie si c'est un port well-known."""
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Le modele OSI n'a jamais vraiment ete utilise !**

Le modele OSI a 7 couches est un modele theorique de l'ISO. En pratique, Internet utilise le modele TCP/IP a 4 couches. Mais OSI reste la reference pedagogique car il est plus detaille.

**Les ports 0-1023 sont privilegies**

Sur Unix, seul root peut ouvrir un socket sur les ports 0-1023. C'est pourquoi les serveurs web utilisent souvent des reverse proxies : Nginx sur le port 80 redirige vers une app sur le port 3000.

**TCP vs UDP : le debat eternel**

Les jeux video utilisent souvent UDP pour la position des joueurs (perdre un paquet n'est pas grave) mais TCP pour le chat (chaque message doit arriver). Netflix utilise TCP malgre le streaming car la qualite prime sur la latence.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Network Engineer** | Debugger avec Wireshark, analyser les captures |
| **Security Analyst** | Detecter les scans de ports, identifier les intrusions |
| **DevOps** | Configurer les firewalls, diagnostiquer les problemes |
| **Game Developer** | Choisir entre TCP et UDP selon le use case |
| **Backend Developer** | Comprendre les timeouts, connexions persistantes |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3 -c "
from protocol_analyzer import (
    get_osi_layer, get_port_info, compare_tcp_udp,
    identify_protocol_by_port
)

# Couches OSI
for i in range(1, 8):
    layer = get_osi_layer(i)
    print(f'Layer {i}: {layer[\"name\"]}')

# Ports
print()
for port in [22, 80, 443, 53]:
    info = get_port_info(port)
    print(f'Port {port}: {info.service} ({info.protocol})')

# TCP vs UDP
print()
comparison = compare_tcp_udp()
print(f'TCP reliable: {comparison[\"TCP\"][\"reliable\"]}')
print(f'UDP reliable: {comparison[\"UDP\"][\"reliable\"]}')
"
```

**Sortie :**
```
Layer 1: Physical
Layer 2: Data Link
Layer 3: Network
Layer 4: Transport
Layer 5: Session
Layer 6: Presentation
Layer 7: Application

Port 22: SSH (TCP)
Port 80: HTTP (TCP)
Port 443: HTTPS (TCP)
Port 53: DNS (TCP/UDP)

TCP reliable: True
UDP reliable: False
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

**Consigne Bonus :**

1. **Parser complet des headers** : TCP avec options, IPv4/IPv6
2. **Calcul de checksum** : Verifier l'integrite TCP/UDP
3. **Analyse de capture** : Parser un fichier PCAP simplifie

```python
def parse_ipv4_header(data: bytes) -> dict:
    """Parse un header IPv4 complet."""
    pass

def calculate_tcp_checksum(tcp_header: bytes, pseudo_header: bytes) -> int:
    """Calcule le checksum TCP."""
    pass

def parse_tcp_options(data: bytes) -> list[dict]:
    """Parse les options TCP (MSS, Window Scale, etc.)."""
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | osi_layer_1 | get_osi_layer(1) | name=Physical | 5 | OSI |
| 2 | osi_layer_4 | get_osi_layer(4) | name=Transport | 5 | OSI |
| 3 | osi_layer_7 | get_osi_layer(7) | name=Application | 5 | OSI |
| 4 | osi_invalid | get_osi_layer(0) | None or error | 5 | Edge |
| 5 | port_22 | get_port_info(22) | SSH, TCP | 5 | Ports |
| 6 | port_80 | get_port_info(80) | HTTP, TCP | 5 | Ports |
| 7 | port_53 | get_port_info(53) | DNS, TCP/UDP | 5 | Ports |
| 8 | port_443 | get_port_info(443) | HTTPS, TCP | 5 | Ports |
| 9 | port_unknown | get_port_info(12345) | None | 5 | Edge |
| 10 | tcp_reliable | compare_tcp_udp() | TCP.reliable=True | 5 | Compare |
| 11 | udp_unreliable | compare_tcp_udp() | UDP.reliable=False | 5 | Compare |
| 12 | tcp_connection | compare_tcp_udp() | TCP.connection=True | 5 | Compare |
| 13 | identify_http | identify_protocol_by_port(80) | "HTTP" | 5 | Identify |
| 14 | identify_ssh | identify_protocol_by_port(22) | "SSH" | 5 | Identify |
| 15 | parse_tcp_ports | parse_tcp_header(bytes) | src/dst correct | 10 | Parse |
| 16 | parse_tcp_flags | parse_tcp_header(bytes) | flags correct | 10 | Parse |
| 17 | parse_udp | parse_udp_header(bytes) | src/dst/len correct | 10 | Parse |

**Total : 100 points**

---

### 4.2 Tests unitaires Python

```python
import pytest
from protocol_analyzer import (
    get_osi_layer, get_port_info, compare_tcp_udp,
    identify_protocol_by_port, parse_tcp_header, parse_udp_header,
    get_tcp_flags, PortInfo
)

class TestOSILayers:
    def test_layer_1(self):
        layer = get_osi_layer(1)
        assert layer["name"] == "Physical"

    def test_layer_4(self):
        layer = get_osi_layer(4)
        assert layer["name"] == "Transport"
        assert "TCP" in layer["protocols"]
        assert "UDP" in layer["protocols"]

    def test_layer_7(self):
        layer = get_osi_layer(7)
        assert layer["name"] == "Application"

    def test_invalid_layer(self):
        result = get_osi_layer(0)
        assert result is None or "error" in result

class TestPorts:
    def test_well_known_ports(self):
        assert get_port_info(22).service == "SSH"
        assert get_port_info(80).service == "HTTP"
        assert get_port_info(443).service == "HTTPS"

    def test_port_53_dual(self):
        info = get_port_info(53)
        assert info.service == "DNS"
        assert "TCP" in info.protocol and "UDP" in info.protocol

    def test_unknown_port(self):
        assert get_port_info(12345) is None

class TestComparison:
    def test_tcp_characteristics(self):
        comparison = compare_tcp_udp()
        tcp = comparison["TCP"]
        assert tcp["reliable"] == True
        assert tcp["ordered"] == True
        assert tcp["connection"] == True

    def test_udp_characteristics(self):
        comparison = compare_tcp_udp()
        udp = comparison["UDP"]
        assert udp["reliable"] == False
        assert udp["ordered"] == False
        assert udp["connection"] == False

class TestIdentify:
    def test_identify_http(self):
        assert identify_protocol_by_port(80, "TCP") == "HTTP"

    def test_identify_https(self):
        assert identify_protocol_by_port(443, "TCP") == "HTTPS"

    def test_identify_dns(self):
        assert identify_protocol_by_port(53, "UDP") == "DNS"

class TestParsing:
    def test_parse_tcp_header(self):
        # TCP header: src=80, dst=12345, seq=1, ack=2, flags=0x12 (SYN-ACK)
        data = bytes([
            0x00, 0x50,  # src port (80)
            0x30, 0x39,  # dst port (12345)
            0x00, 0x00, 0x00, 0x01,  # seq
            0x00, 0x00, 0x00, 0x02,  # ack
            0x50, 0x12,  # data offset + flags
            0xFF, 0xFF,  # window
            0x00, 0x00,  # checksum
            0x00, 0x00,  # urgent
        ])
        result = parse_tcp_header(data)
        assert result["src_port"] == 80
        assert result["dst_port"] == 12345

    def test_parse_udp_header(self):
        # UDP header: src=53, dst=12345, length=20
        data = bytes([
            0x00, 0x35,  # src port (53)
            0x30, 0x39,  # dst port (12345)
            0x00, 0x14,  # length (20)
            0x00, 0x00,  # checksum
        ])
        result = parse_udp_header(data)
        assert result["src_port"] == 53
        assert result["dst_port"] == 12345
        assert result["length"] == 20
```

---

### 4.3 Solution de reference (Python)

```python
from dataclasses import dataclass
from typing import Optional
import struct

@dataclass
class PortInfo:
    number: int
    protocol: str
    service: str

# Base de donnees des couches OSI
OSI_LAYERS = {
    1: {
        "name": "Physical",
        "protocols": ["Ethernet PHY", "USB", "Bluetooth PHY"],
        "description": "Transmission de bits bruts sur le medium physique",
        "examples": ["Cables", "Signaux electriques", "Ondes radio"]
    },
    2: {
        "name": "Data Link",
        "protocols": ["Ethernet", "Wi-Fi (802.11)", "PPP"],
        "description": "Transfert de trames entre noeuds adjacents",
        "examples": ["Adresses MAC", "VLAN", "ARP"]
    },
    3: {
        "name": "Network",
        "protocols": ["IPv4", "IPv6", "ICMP", "IPsec"],
        "description": "Routage des paquets a travers le reseau",
        "examples": ["Adresses IP", "Routage", "Fragmentation"]
    },
    4: {
        "name": "Transport",
        "protocols": ["TCP", "UDP", "SCTP"],
        "description": "Transfert de bout en bout, controle de flux",
        "examples": ["Ports", "Numeros de sequence", "Controle de congestion"]
    },
    5: {
        "name": "Session",
        "protocols": ["NetBIOS", "RPC", "SOCKS"],
        "description": "Gestion des sessions de communication",
        "examples": ["Etablissement de session", "Synchronisation"]
    },
    6: {
        "name": "Presentation",
        "protocols": ["SSL/TLS", "MIME", "ASCII/Unicode"],
        "description": "Formatage et chiffrement des donnees",
        "examples": ["Compression", "Chiffrement", "Encodage"]
    },
    7: {
        "name": "Application",
        "protocols": ["HTTP", "HTTPS", "FTP", "SMTP", "DNS", "SSH"],
        "description": "Services reseau pour les applications",
        "examples": ["Pages web", "Emails", "Transfert de fichiers"]
    }
}

# Base de donnees des ports well-known
WELL_KNOWN_PORTS = {
    20: PortInfo(20, "TCP", "FTP Data"),
    21: PortInfo(21, "TCP", "FTP Control"),
    22: PortInfo(22, "TCP", "SSH"),
    23: PortInfo(23, "TCP", "Telnet"),
    25: PortInfo(25, "TCP", "SMTP"),
    53: PortInfo(53, "TCP/UDP", "DNS"),
    67: PortInfo(67, "UDP", "DHCP Server"),
    68: PortInfo(68, "UDP", "DHCP Client"),
    80: PortInfo(80, "TCP", "HTTP"),
    110: PortInfo(110, "TCP", "POP3"),
    143: PortInfo(143, "TCP", "IMAP"),
    443: PortInfo(443, "TCP", "HTTPS"),
    465: PortInfo(465, "TCP", "SMTPS"),
    587: PortInfo(587, "TCP", "SMTP Submission"),
    993: PortInfo(993, "TCP", "IMAPS"),
    995: PortInfo(995, "TCP", "POP3S"),
    3306: PortInfo(3306, "TCP", "MySQL"),
    5432: PortInfo(5432, "TCP", "PostgreSQL"),
    6379: PortInfo(6379, "TCP", "Redis"),
    27017: PortInfo(27017, "TCP", "MongoDB"),
}

def get_osi_layer(layer_number: int) -> Optional[dict]:
    """Retourne les informations sur une couche OSI."""
    return OSI_LAYERS.get(layer_number)

def get_osi_layer_name(layer_number: int) -> Optional[str]:
    """Retourne le nom d'une couche OSI."""
    layer = OSI_LAYERS.get(layer_number)
    return layer["name"] if layer else None

def get_port_info(port: int) -> Optional[PortInfo]:
    """Retourne les informations sur un port well-known."""
    return WELL_KNOWN_PORTS.get(port)

def compare_tcp_udp() -> dict:
    """Compare TCP et UDP."""
    return {
        "TCP": {
            "reliable": True,
            "ordered": True,
            "connection": True,
            "error_checking": True,
            "flow_control": True,
            "congestion_control": True,
            "header_size": "20-60 bytes",
            "use_cases": ["HTTP", "FTP", "SMTP", "SSH"]
        },
        "UDP": {
            "reliable": False,
            "ordered": False,
            "connection": False,
            "error_checking": True,
            "flow_control": False,
            "congestion_control": False,
            "header_size": "8 bytes",
            "use_cases": ["DNS", "DHCP", "VoIP", "Gaming", "Streaming"]
        }
    }

def identify_protocol_by_port(port: int, transport: str = "TCP") -> Optional[str]:
    """Identifie le protocole applicatif probable pour un port."""
    port_info = WELL_KNOWN_PORTS.get(port)
    if port_info is None:
        return None

    # Verifier si le transport correspond
    if transport.upper() in port_info.protocol.upper():
        return port_info.service

    return None

def parse_tcp_header(data: bytes) -> dict:
    """Parse un header TCP basique (20 bytes minimum)."""
    if len(data) < 20:
        raise ValueError("TCP header requires at least 20 bytes")

    src_port, dst_port = struct.unpack("!HH", data[0:4])
    seq_num = struct.unpack("!I", data[4:8])[0]
    ack_num = struct.unpack("!I", data[8:12])[0]
    data_offset_flags = struct.unpack("!H", data[12:14])[0]

    data_offset = (data_offset_flags >> 12) * 4
    flags = data_offset_flags & 0x1FF

    window = struct.unpack("!H", data[14:16])[0]
    checksum = struct.unpack("!H", data[16:18])[0]
    urgent = struct.unpack("!H", data[18:20])[0]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "data_offset": data_offset,
        "flags": get_tcp_flags(flags),
        "window": window,
        "checksum": checksum,
        "urgent_pointer": urgent
    }

def parse_udp_header(data: bytes) -> dict:
    """Parse un header UDP (8 bytes)."""
    if len(data) < 8:
        raise ValueError("UDP header requires 8 bytes")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[0:8])

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum
    }

def get_tcp_flags(flags: int) -> dict:
    """Decode les flags TCP."""
    return {
        "FIN": bool(flags & 0x01),
        "SYN": bool(flags & 0x02),
        "RST": bool(flags & 0x04),
        "PSH": bool(flags & 0x08),
        "ACK": bool(flags & 0x10),
        "URG": bool(flags & 0x20),
        "ECE": bool(flags & 0x40),
        "CWR": bool(flags & 0x80),
        "NS": bool(flags & 0x100)
    }

def is_well_known_port(port: int) -> bool:
    """Verifie si c'est un port well-known."""
    return 0 <= port <= 1023
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Mauvais ordre des bytes**

```python
# REFUSE : Little-endian au lieu de big-endian (network byte order)
src_port, dst_port = struct.unpack("<HH", data[0:4])  # ERREUR: < au lieu de !
```
**Pourquoi refuse :** Les protocoles reseau utilisent le network byte order (big-endian).

**Refus 2 : Layers incorrect**

```python
# REFUSE : Numerotation de 0 a 6
OSI_LAYERS = {
    0: {"name": "Physical"},  # ERREUR: commence a 1
    ...
}
```
**Pourquoi refuse :** Le modele OSI numerote les couches de 1 a 7.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "protocol_analyzer",
  "language": "python",
  "language_version": "3.14",
  "type": "code",
  "tier": 1,
  "tags": ["moduleC.1", "network", "osi", "tcp", "udp", "ports", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "get_osi_layer",
    "prototype": "def get_osi_layer(layer_number: int) -> dict",
    "return_type": "dict"
  },

  "driver": {
    "edge_cases": [
      {
        "name": "layer_0",
        "args": [0],
        "expected": "None or error",
        "is_trap": true,
        "trap_explanation": "Layer 0 n'existe pas dans OSI"
      },
      {
        "name": "layer_8",
        "args": [8],
        "expected": "None or error",
        "is_trap": true,
        "trap_explanation": "OSI n'a que 7 couches"
      }
    ]
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Endianness) : Mauvais byte order**

```python
# Mutant A: Little-endian
src_port = struct.unpack("<H", data[0:2])[0]  # ERREUR: network byte order = big-endian
# Pourquoi c'est faux: Port 80 (0x0050) devient 20480 (0x5000)
```

**Mutant B (Offset) : Mauvais calcul du data offset**

```python
# Mutant B: Data offset non multiplie par 4
data_offset = (data_offset_flags >> 12)  # ERREUR: en words, pas bytes
# Pourquoi c'est faux: Le data offset est en mots de 32 bits (4 bytes)
```

**Mutant C (Flags) : Masquage incorrect**

```python
# Mutant C: Mauvais masque pour les flags
flags = data_offset_flags & 0xFF  # ERREUR: les flags sont sur 9 bits
# Pourquoi c'est faux: Le flag NS (bit 8) est perdu
```

**Mutant D (Layer) : Numerotation de 0**

```python
# Mutant D: Couches numerotees de 0 a 6
OSI_LAYERS = {0: {"name": "Physical"}, ...}  # ERREUR
# Pourquoi c'est faux: OSI numerote de 1 (Physical) a 7 (Application)
```

**Mutant E (Port) : Port 53 mal gere**

```python
# Mutant E: DNS seulement en UDP
WELL_KNOWN_PORTS = {
    53: PortInfo(53, "UDP", "DNS"),  # ERREUR: aussi TCP
}
# Pourquoi c'est faux: DNS utilise TCP pour les transferts de zone et grosses reponses
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Modele OSI | 7 couches de communication | Fondamental |
| TCP vs UDP | Caracteristiques et use cases | Essentiel |
| Ports | Identification des services | Pratique |
| Headers | Structure des paquets | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION parse_tcp_header QUI PREND data COMME BYTES
DEBUT FONCTION
    SI LONGUEUR DE data < 20 ALORS
        LEVER ERREUR "Header trop court"
    FIN SI

    EXTRAIRE src_port DES BYTES 0-2 EN BIG-ENDIAN
    EXTRAIRE dst_port DES BYTES 2-4 EN BIG-ENDIAN
    EXTRAIRE seq_num DES BYTES 4-8 EN BIG-ENDIAN (32 bits)
    EXTRAIRE ack_num DES BYTES 8-12 EN BIG-ENDIAN (32 bits)
    EXTRAIRE data_offset_flags DES BYTES 12-14 EN BIG-ENDIAN

    CALCULER data_offset = (data_offset_flags >> 12) * 4
    CALCULER flags = data_offset_flags AND 0x1FF

    RETOURNER DICTIONNAIRE AVEC TOUS LES CHAMPS
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Le modele OSI :**

```
+-------------------+-------------------+------------------------+
| Layer | Name      | Protocols         | Data Unit             |
+-------+-----------+-------------------+------------------------+
|   7   | Application | HTTP, DNS, SSH   | Data                   |
+-------+-----------+-------------------+------------------------+
|   6   | Presentation | SSL/TLS, MIME   | Data                   |
+-------+-----------+-------------------+------------------------+
|   5   | Session   | NetBIOS, RPC     | Data                   |
+-------+-----------+-------------------+------------------------+
|   4   | Transport | TCP, UDP         | Segment (TCP)          |
|       |           |                   | Datagram (UDP)         |
+-------+-----------+-------------------+------------------------+
|   3   | Network   | IP, ICMP         | Packet                 |
+-------+-----------+-------------------+------------------------+
|   2   | Data Link | Ethernet, Wi-Fi  | Frame                  |
+-------+-----------+-------------------+------------------------+
|   1   | Physical  | Cables, Signaux  | Bits                   |
+-------+-----------+-------------------+------------------------+
```

**Structure d'un header TCP :**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Structure d'un header UDP :**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Network byte order

```python
# Les protocoles reseau utilisent big-endian
# struct.unpack("!") = network byte order = big-endian
# struct.unpack("<") = little-endian (ERREUR pour le reseau)

# Correct:
port = struct.unpack("!H", data[0:2])[0]  # ! = big-endian

# Incorrect:
port = struct.unpack("<H", data[0:2])[0]  # < = little-endian
```

#### Piege 2 : TCP data offset

```python
# Le data offset est en mots de 32 bits (4 bytes)
# Un data offset de 5 signifie 5 * 4 = 20 bytes

# Correct:
header_length = data_offset * 4

# Incorrect:
header_length = data_offset  # Oublie de multiplier par 4
```

---

### 5.5 Cours Complet

#### 5.5.1 TCP vs UDP

| Caracteristique | TCP | UDP |
|-----------------|-----|-----|
| Connexion | Orientee connexion | Sans connexion |
| Fiabilite | Garantie de livraison | Best-effort |
| Ordre | Garanti | Non garanti |
| Controle de flux | Oui | Non |
| Header | 20-60 bytes | 8 bytes |
| Latence | Plus elevee | Plus faible |

#### 5.5.2 Les flags TCP

| Flag | Nom | Usage |
|------|-----|-------|
| SYN | Synchronize | Demande de connexion |
| ACK | Acknowledge | Acquittement |
| FIN | Finish | Fin de connexion |
| RST | Reset | Reinitialisation |
| PSH | Push | Envoi immediat |
| URG | Urgent | Donnees urgentes |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Little-endian | Ports incorrects | Utiliser ! (big-endian) |
| 2 | Data offset | Header mal parse | Multiplier par 4 |
| 3 | Flags 8 bits | NS perdu | Masque 0x1FF |
| 4 | Layers de 0 | Decalage | Commencer a 1 |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle couche OSI gere l'adressage IP ?

- A) Transport
- B) Network
- C) Data Link
- D) Physical

**Reponse : B** — La couche Network (3) gere l'adressage IP et le routage.

---

### Question 2 (4 points)
Quel protocole est fiable et ordonne ?

- A) UDP
- B) TCP
- C) ICMP
- D) ARP

**Reponse : B** — TCP garantit la fiabilite et l'ordre des donnees.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.1.40 |
| **Nom** | protocol_analyzer |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 85 |
| **Langage** | Python 3.14 |
| **Concepts cles** | OSI, TCP, UDP, ports, headers |

---

*Document genere selon HACKBRAIN v5.5.2*
