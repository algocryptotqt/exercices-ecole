# Exercice C.1.39 : http_parser

**Module :**
C.1 — Reseaux

**Concept :**
39 — Parsing HTTP (Request/Response, Methods, Status codes, Headers)

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
- Manipulation de chaines de caracteres
- Expressions regulieres (basique)

**Domaines :**
Net, HTTP, Parsing

**Duree estimee :**
40 min

**XP Base :**
90

**Complexite :**
T2 O(n) × S1 O(n) ou n = taille du message

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Python | `http_parser.py` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Python | `str.split`, `str.strip`, `re`, `dict`, `list`, built-ins |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Python | `http.client`, `urllib`, `requests`, bibliotheques HTTP |

---

### 1.2 Consigne

#### Section Culture : "Speaking HTTP"

**THE SOCIAL NETWORK — "A million users"**

Quand Mark Zuckerberg a lance Facebook, chaque clic, chaque "like", chaque photo uploadee passait par HTTP. Des millions de requetes GET, POST, PUT, DELETE — le langage silencieux du web.

Comprendre HTTP, c'est comprendre comment le web parle. Chaque requete a une methode, des headers, un body. Chaque reponse a un status code qui raconte une histoire : 200 OK, 404 Not Found, 500 Internal Server Error.

*"HTTP is the language of the web. Learn to read it, and you can read the internet's mind."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un parser HTTP qui :

1. **Parse les requetes HTTP** : Methode, URI, version, headers, body
2. **Parse les reponses HTTP** : Version, status code, reason, headers, body
3. **Valide la structure** : Format conforme HTTP/1.1
4. **Genere des messages HTTP** : Construire requetes et reponses

**Entree :**

```python
@dataclass
class HTTPRequest:
    method: str           # GET, POST, PUT, DELETE, etc.
    uri: str              # /path/to/resource
    version: str          # HTTP/1.1
    headers: dict[str, str]
    body: str = ""

@dataclass
class HTTPResponse:
    version: str          # HTTP/1.1
    status_code: int      # 200, 404, 500, etc.
    reason: str           # OK, Not Found, etc.
    headers: dict[str, str]
    body: str = ""

def parse_request(raw: str) -> HTTPRequest:
    """
    Parse une requete HTTP brute.

    Args:
        raw: Chaine representant une requete HTTP complete

    Returns:
        HTTPRequest avec tous les champs remplis

    Raises:
        ValueError: Si le format est invalide
    """
    pass

def parse_response(raw: str) -> HTTPResponse:
    """
    Parse une reponse HTTP brute.

    Args:
        raw: Chaine representant une reponse HTTP complete

    Returns:
        HTTPResponse avec tous les champs remplis
    """
    pass

def build_request(request: HTTPRequest) -> str:
    """Construit une requete HTTP brute a partir d'un objet."""
    pass

def build_response(response: HTTPResponse) -> str:
    """Construit une reponse HTTP brute a partir d'un objet."""
    pass
```

**Sortie :**

```python
# Parse une requete
raw_request = """GET /index.html HTTP/1.1\r
Host: www.example.com\r
User-Agent: Mozilla/5.0\r
Accept: text/html\r
\r
"""

>>> req = parse_request(raw_request)
>>> req.method
"GET"
>>> req.uri
"/index.html"
>>> req.headers["Host"]
"www.example.com"

# Parse une reponse
raw_response = """HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: 13\r
\r
Hello, World!"""

>>> resp = parse_response(raw_response)
>>> resp.status_code
200
>>> resp.body
"Hello, World!"
```

**Contraintes :**

- Les lignes sont separees par `\r\n` (CRLF)
- Les headers sont termines par une ligne vide (`\r\n\r\n`)
- Les noms de headers sont case-insensitive
- Gerer Content-Length pour le body
- Methodes a supporter : GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH

**Status codes courants :**

| Code | Reason | Signification |
|------|--------|---------------|
| 200 | OK | Succes |
| 201 | Created | Ressource creee |
| 301 | Moved Permanently | Redirection permanente |
| 302 | Found | Redirection temporaire |
| 400 | Bad Request | Requete malformee |
| 401 | Unauthorized | Authentification requise |
| 403 | Forbidden | Acces refuse |
| 404 | Not Found | Ressource introuvable |
| 500 | Internal Server Error | Erreur serveur |
| 503 | Service Unavailable | Service indisponible |

---

### 1.3 Prototype

```python
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class HTTPRequest:
    method: str
    uri: str
    version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

@dataclass
class HTTPResponse:
    version: str = "HTTP/1.1"
    status_code: int = 200
    reason: str = "OK"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

def parse_request(raw: str) -> HTTPRequest:
    """Parse une requete HTTP brute."""
    pass

def parse_response(raw: str) -> HTTPResponse:
    """Parse une reponse HTTP brute."""
    pass

def build_request(request: HTTPRequest) -> str:
    """Construit une requete HTTP brute."""
    pass

def build_response(response: HTTPResponse) -> str:
    """Construit une reponse HTTP brute."""
    pass

def parse_headers(header_lines: list[str]) -> dict[str, str]:
    """Parse les lignes de headers en dictionnaire."""
    pass

def get_status_reason(code: int) -> str:
    """Retourne la raison standard pour un code HTTP."""
    pass

def validate_method(method: str) -> bool:
    """Verifie si la methode HTTP est valide."""
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**HTTP a 30 ans !**

HTTP/0.9 est apparu en 1991, cree par Tim Berners-Lee au CERN. Il ne supportait qu'une methode : GET. Pas de headers, pas de status codes. Juste "GET /page" et la reponse HTML.

**Les codes HTTP ont une histoire**

- 418 "I'm a teapot" : Une blague du 1er avril 1998 (RFC 2324)
- 451 "Unavailable For Legal Reasons" : Reference a Fahrenheit 451
- 420 "Enhance Your Calm" : Invente par Twitter pour le rate limiting

**Keep-Alive a revolutionne le web**

Avant HTTP/1.1, chaque requete ouvrait une nouvelle connexion TCP. Avec Keep-Alive, on peut envoyer plusieurs requetes sur la meme connexion. HTTP/2 va encore plus loin avec le multiplexing.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Backend Developer** | Implementer des APIs REST |
| **Security Engineer** | Analyser les requetes pour detecter les attaques |
| **DevOps** | Debugger les problemes de proxy/load balancer |
| **Pentester** | Manipuler les requetes HTTP (injection, bypass) |
| **Frontend Developer** | Comprendre les erreurs reseau |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ python3 -c "
from http_parser import parse_request, parse_response, build_request, HTTPRequest

# Parser une requete
raw = '''GET /api/users HTTP/1.1\r
Host: api.example.com\r
Authorization: Bearer token123\r
Accept: application/json\r
\r
'''

req = parse_request(raw)
print(f'Method: {req.method}')
print(f'URI: {req.uri}')
print(f'Host: {req.headers.get(\"Host\")}')

# Construire une requete
new_req = HTTPRequest(
    method='POST',
    uri='/api/users',
    headers={'Content-Type': 'application/json', 'Host': 'api.example.com'},
    body='{\"name\": \"John\"}'
)
print(build_request(new_req))
"
```

**Sortie :**
```
Method: GET
URI: /api/users
Host: api.example.com
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 16

{"name": "John"}
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

**Consigne Bonus :**

1. **Chunked Transfer Encoding** : Parser les reponses avec Transfer-Encoding: chunked
2. **Query String Parser** : Extraire les parametres de l'URI
3. **Cookie Parser** : Parser et generer les headers Cookie/Set-Cookie
4. **Multipart Parser** : Parser les requetes multipart/form-data

```python
def parse_query_string(uri: str) -> tuple[str, dict[str, str]]:
    """Extrait le path et les parametres de l'URI."""
    pass

def parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse un header Cookie."""
    pass

def parse_chunked_body(raw_body: str) -> str:
    """Decode un body en chunked encoding."""
    pass
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | parse_get_request | GET /path HTTP/1.1 | method=GET | 5 | Basic |
| 2 | parse_post_request | POST /api HTTP/1.1 | method=POST | 5 | Basic |
| 3 | parse_uri | GET /path/to/file | uri=/path/to/file | 5 | Basic |
| 4 | parse_headers | Host: example.com | headers[Host] | 10 | Headers |
| 5 | parse_multiple_headers | 5 headers | all parsed | 10 | Headers |
| 6 | parse_body | POST with body | body extracted | 10 | Body |
| 7 | parse_response_200 | HTTP/1.1 200 OK | status_code=200 | 5 | Response |
| 8 | parse_response_404 | HTTP/1.1 404 | status_code=404 | 5 | Response |
| 9 | build_request | HTTPRequest obj | valid HTTP | 10 | Build |
| 10 | build_response | HTTPResponse obj | valid HTTP | 10 | Build |
| 11 | case_insensitive_headers | Content-TYPE | normalized | 5 | Normalize |
| 12 | empty_body | GET request | body="" | 5 | Edge |
| 13 | content_length | POST with Content-Length | correct body | 10 | Body |
| 14 | invalid_method | INVALID /path | ValueError | 5 | Validation |

**Total : 100 points**

---

### 4.2 Tests unitaires Python

```python
import pytest
from http_parser import (
    parse_request, parse_response, build_request, build_response,
    HTTPRequest, HTTPResponse
)

class TestParseRequest:
    def test_simple_get(self):
        raw = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = parse_request(raw)
        assert req.method == "GET"
        assert req.uri == "/index.html"
        assert req.version == "HTTP/1.1"
        assert req.headers["Host"] == "example.com"

    def test_post_with_body(self):
        raw = "POST /api HTTP/1.1\r\nContent-Length: 11\r\n\r\nHello World"
        req = parse_request(raw)
        assert req.method == "POST"
        assert req.body == "Hello World"

    def test_multiple_headers(self):
        raw = ("GET / HTTP/1.1\r\n"
               "Host: example.com\r\n"
               "User-Agent: Test\r\n"
               "Accept: */*\r\n\r\n")
        req = parse_request(raw)
        assert len(req.headers) == 3

    def test_case_insensitive_headers(self):
        raw = "GET / HTTP/1.1\r\nCONTENT-TYPE: text/html\r\n\r\n"
        req = parse_request(raw)
        # Headers should be accessible case-insensitively
        assert "Content-Type" in req.headers or "content-type" in req.headers

class TestParseResponse:
    def test_simple_response(self):
        raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        resp = parse_response(raw)
        assert resp.status_code == 200
        assert resp.reason == "OK"
        assert resp.body == "<html></html>"

    def test_404_response(self):
        raw = "HTTP/1.1 404 Not Found\r\n\r\n"
        resp = parse_response(raw)
        assert resp.status_code == 404
        assert resp.reason == "Not Found"

    def test_response_with_content_length(self):
        raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
        resp = parse_response(raw)
        assert resp.body == "Hello"

class TestBuildRequest:
    def test_build_get(self):
        req = HTTPRequest(method="GET", uri="/test", headers={"Host": "example.com"})
        raw = build_request(req)
        assert "GET /test HTTP/1.1" in raw
        assert "Host: example.com" in raw

    def test_build_post_with_body(self):
        req = HTTPRequest(
            method="POST", uri="/api",
            headers={"Content-Type": "application/json"},
            body='{"key": "value"}'
        )
        raw = build_request(req)
        assert "POST /api HTTP/1.1" in raw
        assert "Content-Length: 16" in raw
        assert '{"key": "value"}' in raw

class TestBuildResponse:
    def test_build_200(self):
        resp = HTTPResponse(
            status_code=200, reason="OK",
            headers={"Content-Type": "text/plain"},
            body="Hello"
        )
        raw = build_response(resp)
        assert "HTTP/1.1 200 OK" in raw
        assert "Content-Type: text/plain" in raw
        assert "Hello" in raw

class TestEdgeCases:
    def test_empty_body(self):
        raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = parse_request(raw)
        assert req.body == ""

    def test_invalid_method(self):
        raw = "INVALID / HTTP/1.1\r\n\r\n"
        with pytest.raises(ValueError):
            parse_request(raw)
```

---

### 4.3 Solution de reference (Python)

```python
from dataclasses import dataclass, field
from typing import Optional
import re

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}

STATUS_REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

@dataclass
class HTTPRequest:
    method: str
    uri: str
    version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

@dataclass
class HTTPResponse:
    version: str = "HTTP/1.1"
    status_code: int = 200
    reason: str = "OK"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

def parse_request(raw: str) -> HTTPRequest:
    """Parse une requete HTTP brute."""
    # Split headers and body
    if "\r\n\r\n" in raw:
        header_section, body = raw.split("\r\n\r\n", 1)
    else:
        header_section = raw
        body = ""

    lines = header_section.split("\r\n")
    if not lines:
        raise ValueError("Empty request")

    # Parse request line
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 3:
        raise ValueError(f"Invalid request line: {request_line}")

    method = parts[0].upper()
    uri = parts[1]
    version = parts[2]

    if method not in VALID_METHODS:
        raise ValueError(f"Invalid method: {method}")

    # Parse headers
    headers = parse_headers(lines[1:])

    return HTTPRequest(
        method=method,
        uri=uri,
        version=version,
        headers=headers,
        body=body
    )

def parse_response(raw: str) -> HTTPResponse:
    """Parse une reponse HTTP brute."""
    # Split headers and body
    if "\r\n\r\n" in raw:
        header_section, body = raw.split("\r\n\r\n", 1)
    else:
        header_section = raw
        body = ""

    lines = header_section.split("\r\n")
    if not lines:
        raise ValueError("Empty response")

    # Parse status line
    status_line = lines[0]
    match = re.match(r'^(HTTP/\d\.\d)\s+(\d+)\s*(.*)?$', status_line)
    if not match:
        raise ValueError(f"Invalid status line: {status_line}")

    version = match.group(1)
    status_code = int(match.group(2))
    reason = match.group(3) or STATUS_REASONS.get(status_code, "")

    # Parse headers
    headers = parse_headers(lines[1:])

    return HTTPResponse(
        version=version,
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body
    )

def parse_headers(lines: list[str]) -> dict[str, str]:
    """Parse les lignes de headers en dictionnaire."""
    headers = {}
    for line in lines:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        # Normalize header name to Title-Case
        name = "-".join(word.capitalize() for word in name.strip().split("-"))
        headers[name] = value.strip()
    return headers

def build_request(request: HTTPRequest) -> str:
    """Construit une requete HTTP brute."""
    lines = []

    # Request line
    lines.append(f"{request.method} {request.uri} {request.version}")

    # Headers
    headers = dict(request.headers)
    if request.body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(request.body))

    for name, value in headers.items():
        lines.append(f"{name}: {value}")

    # Empty line
    lines.append("")

    # Body
    if request.body:
        lines.append(request.body)

    return "\r\n".join(lines)

def build_response(response: HTTPResponse) -> str:
    """Construit une reponse HTTP brute."""
    lines = []

    # Status line
    lines.append(f"{response.version} {response.status_code} {response.reason}")

    # Headers
    headers = dict(response.headers)
    if response.body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(response.body))

    for name, value in headers.items():
        lines.append(f"{name}: {value}")

    # Empty line
    lines.append("")

    # Body
    if response.body:
        lines.append(response.body)

    return "\r\n".join(lines)

def get_status_reason(code: int) -> str:
    """Retourne la raison standard pour un code HTTP."""
    return STATUS_REASONS.get(code, "Unknown")

def validate_method(method: str) -> bool:
    """Verifie si la methode HTTP est valide."""
    return method.upper() in VALID_METHODS
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Split sur \n au lieu de \r\n**

```python
# REFUSE : Ne gere pas correctement les terminaisons de ligne
def parse_request(raw):
    lines = raw.split("\n")  # ERREUR: devrait etre \r\n
```
**Pourquoi refuse :** HTTP utilise CRLF, pas LF seul.

**Refus 2 : Headers non normalises**

```python
# REFUSE : Headers case-sensitive
headers[name] = value  # ERREUR: "Content-Type" != "content-type"
```
**Pourquoi refuse :** Les headers HTTP sont case-insensitive.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "http_parser",
  "language": "python",
  "language_version": "3.14",
  "type": "code",
  "tier": 1,
  "tags": ["moduleC.1", "network", "http", "parsing", "rest", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "parse_request",
    "prototype": "def parse_request(raw: str) -> HTTPRequest",
    "return_type": "HTTPRequest"
  },

  "driver": {
    "edge_cases": [
      {
        "name": "crlf_required",
        "args": ["GET / HTTP/1.1\nHost: x\n\n"],
        "expected": "may_fail_or_succeed",
        "is_trap": true,
        "trap_explanation": "CRLF est le standard, LF seul peut etre accepte ou non"
      },
      {
        "name": "invalid_method",
        "args": ["INVALID / HTTP/1.1\r\n\r\n"],
        "expected": "ValueError",
        "is_trap": true,
        "trap_explanation": "Les methodes non standard doivent lever une erreur"
      }
    ]
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Delimiter) : Mauvais separateur**

```python
# Mutant A: Utilise \n au lieu de \r\n
def parse_request(raw):
    lines = raw.split("\n")  # ERREUR: HTTP utilise CRLF
    # ...
# Pourquoi c'est faux: Les requetes HTTP valides utilisent \r\n
```

**Mutant B (Headers) : Ne normalise pas les headers**

```python
# Mutant B: Headers case-sensitive
def parse_headers(lines):
    headers = {}
    for line in lines:
        name, value = line.split(":", 1)
        headers[name] = value.strip()  # ERREUR: pas de normalisation
    return headers
# Pourquoi c'est faux: "Content-Type" et "content-type" sont identiques en HTTP
```

**Mutant C (Body) : Ignore Content-Length**

```python
# Mutant C: Prend tout apres les headers comme body
def parse_request(raw):
    header_section, body = raw.split("\r\n\r\n", 1)
    # ERREUR: ne verifie pas Content-Length
    return HTTPRequest(..., body=body)
# Pourquoi c'est faux: Le body peut etre plus court que ce qui reste
```

**Mutant D (Build) : Oublie Content-Length**

```python
# Mutant D: N'ajoute pas Content-Length automatiquement
def build_request(request):
    lines = [f"{request.method} {request.uri} {request.version}"]
    for name, value in request.headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append(request.body)
    # ERREUR: Content-Length non ajoute
    return "\r\n".join(lines)
# Pourquoi c'est faux: Sans Content-Length, le serveur ne sait pas ou finit le body
```

**Mutant E (Status) : Parse mal la status line**

```python
# Mutant E: Split simple au lieu de regex
def parse_response(raw):
    lines = raw.split("\r\n")
    parts = lines[0].split(" ")
    version = parts[0]
    status_code = int(parts[1])
    reason = parts[2]  # ERREUR: "Not Found" devient juste "Not"
    # ...
# Pourquoi c'est faux: La raison peut contenir des espaces
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Structure HTTP | Request line, headers, body | Fondamental |
| Methodes HTTP | GET, POST, PUT, DELETE, etc. | Essentiel |
| Status codes | 2xx, 3xx, 4xx, 5xx | Pratique |
| Headers | Content-Type, Content-Length, etc. | Important |
| Parsing robuste | Gerer les edge cases | Critique |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION parse_request QUI PREND raw COMME CHAINE
DEBUT FONCTION
    SEPARER raw EN header_section ET body AU NIVEAU DE "\r\n\r\n"

    SEPARER header_section EN lines AU NIVEAU DE "\r\n"

    EXTRAIRE method, uri, version DE LA PREMIERE LIGNE

    SI method N'EST PAS DANS METHODES_VALIDES ALORS
        LEVER ERREUR "Methode invalide"
    FIN SI

    POUR CHAQUE line DANS lines[1:] FAIRE
        SEPARER line EN name ET value AU NIVEAU DE ":"
        NORMALISER name EN Title-Case
        AJOUTER {name: value} A headers
    FIN POUR

    RETOURNER HTTPRequest(method, uri, version, headers, body)
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Structure d'une requete HTTP :**

```
+--------------------------------------------------+
|                  HTTP REQUEST                     |
+--------------------------------------------------+
| Request Line:                                     |
|   GET /index.html HTTP/1.1                        |
|   |   |           |                               |
|   |   |           +-- Version du protocole        |
|   |   +-------------- URI (chemin + query)        |
|   +------------------ Methode                     |
+--------------------------------------------------+
| Headers:                                          |
|   Host: www.example.com                           |
|   User-Agent: Mozilla/5.0                         |
|   Accept: text/html                               |
|   Content-Length: 0                               |
+--------------------------------------------------+
| Empty Line: \r\n                                  |
+--------------------------------------------------+
| Body: (vide pour GET, contenu pour POST)          |
|   {"username": "john", "password": "secret"}      |
+--------------------------------------------------+
```

**Structure d'une reponse HTTP :**

```
+--------------------------------------------------+
|                  HTTP RESPONSE                    |
+--------------------------------------------------+
| Status Line:                                      |
|   HTTP/1.1 200 OK                                 |
|   |        |   |                                  |
|   |        |   +-- Reason phrase                  |
|   |        +------ Status code                    |
|   +--------------- Version                        |
+--------------------------------------------------+
| Headers:                                          |
|   Content-Type: text/html; charset=utf-8          |
|   Content-Length: 1234                            |
|   Set-Cookie: session=abc123                      |
+--------------------------------------------------+
| Empty Line: \r\n                                  |
+--------------------------------------------------+
| Body:                                             |
|   <!DOCTYPE html>                                 |
|   <html>...</html>                                |
+--------------------------------------------------+
```

---

### 5.4 Les pieges en detail

#### Piege 1 : CRLF vs LF

```python
# HTTP utilise CRLF (\r\n), pas juste LF (\n)
# Certains serveurs tolerent LF, d'autres non

# Correct:
"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

# Potentiellement problematique:
"GET / HTTP/1.1\nHost: example.com\n\n"
```

#### Piege 2 : Reason phrase avec espaces

```python
# "404 Not Found" -> status_code=404, reason="Not Found"
# Avec split(" "), reason devient juste "Not"

# Solution: regex ou split limite
status_line.split(" ", 2)  # Max 2 splits
```

---

### 5.5 Cours Complet

#### 5.5.1 Les methodes HTTP

| Methode | Usage | Idempotent | Safe |
|---------|-------|------------|------|
| GET | Recuperer une ressource | Oui | Oui |
| HEAD | GET sans body | Oui | Oui |
| POST | Creer une ressource | Non | Non |
| PUT | Remplacer une ressource | Oui | Non |
| PATCH | Modifier partiellement | Non | Non |
| DELETE | Supprimer une ressource | Oui | Non |
| OPTIONS | Connaitre les methodes supportees | Oui | Oui |

#### 5.5.2 Les categories de status codes

| Plage | Categorie | Exemples |
|-------|-----------|----------|
| 1xx | Informational | 100 Continue, 101 Switching Protocols |
| 2xx | Success | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirection | 301 Moved, 302 Found, 304 Not Modified |
| 4xx | Client Error | 400 Bad Request, 401 Unauthorized, 404 Not Found |
| 5xx | Server Error | 500 Internal Error, 502 Bad Gateway, 503 Unavailable |

---

### 5.7 Simulation avec trace d'execution

```
parse_request("GET /api/users HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n")

+-------+----------------------------------+----------------------------+
| Etape | Operation                        | Resultat                   |
+-------+----------------------------------+----------------------------+
|   1   | split("\r\n\r\n")                | [headers_section, ""]      |
|   2   | split("\r\n") on headers         | 3 lines                    |
|   3   | parse line 0                     | "GET /api/users HTTP/1.1"  |
|   4   | extract method                   | "GET"                      |
|   5   | validate method                  | OK (in VALID_METHODS)      |
|   6   | extract uri                      | "/api/users"               |
|   7   | extract version                  | "HTTP/1.1"                 |
|   8   | parse "Host: api.example.com"    | {"Host": "api.example.com"}|
|   9   | parse "Accept: application/json" | {"Accept": "application..."}|
|  10   | body = ""                        | (pas de body)              |
+-------+----------------------------------+----------------------------+
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | \n au lieu de \r\n | Parsing incorrect | Utiliser \r\n |
| 2 | Headers case-sensitive | Key not found | Normaliser |
| 3 | Reason avec espaces | Reason tronquee | split limite |
| 4 | Pas de Content-Length | Body mal delimite | Ajouter automatiquement |
| 5 | Methodes invalides | Comportement indefini | Valider la methode |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle methode HTTP est idempotente ET safe ?

- A) POST
- B) DELETE
- C) GET
- D) PUT

**Reponse : C** — GET est la seule methode a la fois idempotente et safe.

---

### Question 2 (4 points)
Quel status code indique une redirection permanente ?

- A) 302
- B) 301
- C) 200
- D) 404

**Reponse : B** — 301 Moved Permanently indique une redirection permanente.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.1.39 |
| **Nom** | http_parser |
| **Difficulte** | 4/10 |
| **Duree** | 40 min |
| **XP Base** | 90 |
| **Langage** | Python 3.14 |
| **Concepts cles** | HTTP, methods, status codes, headers, parsing |

---

*Document genere selon HACKBRAIN v5.5.2*
