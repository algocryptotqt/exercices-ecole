<thinking>
## Analyse du Concept
- Concept : Berkeley Sockets API (création, adressage, conversion)
- Phase : 2
- Adapté ? OUI - API fondamentale POSIX pour le networking

## Combo Base + Bonus
- Base : Wrapper autour de l'API sockets avec gestion d'erreurs robuste
- Bonus : Dual-stack IPv4/IPv6 automatique + socket pool manager
- Palier : 🔥 Avancé (7/10)
- Progression : OUI

## Prérequis & Difficulté
- Prérequis : ex00 (networking), ex01 (TCP/UDP), file descriptors
- Difficulté : 6/10 (base), 7/10 (bonus)
- Cohérent : OUI

## Aspect Fun/Culture
- Contexte : Cowboy Bebop (communication dans l'espace)
- Analogie : Les sockets sont comme les radios du Bebop - différents canaux (ports), différentes fréquences (protocoles)
- MEME : "See you space cowboy" - fermer proprement les sockets
- Note : 95/100

## Scénarios d'Échec
1. Mutant A (Boundary) : Port hors limites (>65535)
2. Mutant B (Safety) : Pas de vérification socket() == -1
3. Mutant C (Resource) : Oubli de close() sur erreur
4. Mutant D (Logic) : Oubli htons() sur le port
5. Mutant E (Return) : Retourne fd au lieu de 0 sur succès

## Verdict
VALIDE
</thinking>

# Exercice 2.5.5-a : socket_endpoint

**Module :** 2.5 — Networking
**Concept :** a — Berkeley Sockets API
**Difficulté :** ★★★★★★☆☆☆☆ (6/10)
**Type :** complet
**Tiers :** 1 — Concept isolé
**Langage :** C (C17)
**Prérequis :** ex00, ex01, file descriptors
**Domaines :** Net, FS
**Durée estimée :** 300 min
**XP Base :** 200
**Complexité :** T1 O(1) × S1 O(1)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier :** `socket_endpoint.c`

**Autorisées :** socket, bind, listen, accept, connect, send, recv, close, setsockopt, inet_pton, inet_ntop, htons, ntohs, htonl, ntohl

**Interdites :** getaddrinfo (trop haut niveau pour cet exercice)

### 1.2 Consigne

**🚀 Cowboy Bebop — Space Radio Communications**

Comme l'équipage du Bebop qui utilise différentes fréquences radio pour communiquer, tu vas créer une bibliothèque de gestion de sockets avec :
- Création de sockets (IPv4, IPv6, Unix)
- Conversion d'adresses (string ↔ binary)
- Gestion d'options (SO_REUSEADDR, etc.)
- Fermeture propre avec gestion d'erreurs

**Contraintes :**
- Valider ports (1-65535)
- Gérer l'endianness (htons/htonl)
- Fermer sur TOUS les chemins d'erreur
- Support IPv4 et IPv6

### 1.3 Prototype

```c
typedef struct {
    int fd;
    int domain;  // AF_INET, AF_INET6, AF_UNIX
    int type;    // SOCK_STREAM, SOCK_DGRAM
    bool bound;
} socket_t;

int socket_create(socket_t *sock, int domain, int type, int protocol);
int socket_bind_ipv4(socket_t *sock, const char *ip, uint16_t port);
int socket_bind_ipv6(socket_t *sock, const char *ip, uint16_t port);
int socket_set_option(socket_t *sock, int level, int optname, int value);
int socket_close(socket_t *sock);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

L'API Berkeley Sockets a été créée en 1983 pour BSD Unix. C'est devenu LE standard POSIX pour le networking. Même Windows l'a adopté (Winsock) !

**DANS LA VRAIE VIE - DevOps Engineer :** Configure des load balancers avec SO_REUSEPORT pour distribuer les connexions sur plusieurs processus.

---

## 🖥️ SECTION 3 : EXEMPLE

```bash
$ gcc -Wall -Wextra -Werror socket_endpoint.c main.c -o socket_test
$ ./socket_test
Socket created: fd=3
Bound to 0.0.0.0:8080 ✓
SO_REUSEADDR set ✓
Socket closed ✓
```

### 3.1 🔥 BONUS (7/10, XP ×3)

Dual-stack automatique + connection pool manager avec recyclage de sockets.

---

## ✅ SECTION 4 : ZONE CORRECTION

### 4.3 Solution de référence

```c
int socket_create(socket_t *sock, int domain, int type, int protocol) {
    if (!sock)
        return -1;

    int fd = socket(domain, type, protocol);
    if (fd == -1)
        return -1;

    sock->fd = fd;
    sock->domain = domain;
    sock->type = type;
    sock->bound = false;

    return 0;
}

int socket_bind_ipv4(socket_t *sock, const char *ip, uint16_t port) {
    if (!sock || !ip || port == 0)
        return -1;

    if (sock->fd == -1)
        return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);  // CRITICAL: Network byte order

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
        return -1;

    if (bind(sock->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
        return -1;

    sock->bound = true;
    return 0;
}

int socket_close(socket_t *sock) {
    if (!sock || sock->fd == -1)
        return -1;

    int ret = close(sock->fd);
    sock->fd = -1;
    sock->bound = false;

    return ret;
}
```

### 4.9 spec.json

```json
{
  "name": "socket_endpoint",
  "language": "c",
  "function": {"name": "socket_create", "return_type": "int"},
  "driver": {
    "reference": "int ref_socket_create(socket_t *sock, int domain, int type, int protocol) { if (!sock) return -1; int fd = socket(domain, type, protocol); if (fd == -1) return -1; sock->fd = fd; sock->domain = domain; sock->type = type; sock->bound = false; return 0; }",
    "edge_cases": [
      {"name": "null_sock", "expected": -1, "is_trap": true},
      {"name": "port_zero", "expected": -1, "is_trap": true},
      {"name": "port_overflow", "expected": -1, "is_trap": true}
    ]
  }
}
```

### 4.10 Mutants

```c
/* Mutant A : Port non validé */
if (port == 0) {}  // Oublie de vérifier > 65535

/* Mutant B : Pas de vérification socket() */
int fd = socket(domain, type, protocol);
sock->fd = fd;  // Sans if (fd == -1)

/* Mutant C : Fuite sur erreur */
int fd = socket(domain, type, protocol);
if (bind(...) == -1)
    return -1;  // Pas de close(fd)

/* Mutant D : Oubli htons */
addr.sin_port = port;  // Sans htons()

/* Mutant E : Mauvais retour */
return fd;  // Au lieu de 0
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Concepts

- **Socket** : Point de communication réseau (comme un téléphone)
- **File descriptor** : Le socket est un fd (comme un fichier)
- **Endianness** : htons/htonl pour network byte order (big-endian)
- **sockaddr_in** : Structure IPv4 (famille, port, IP)

### 5.2 LDA

```
FONCTION socket_create
DÉBUT
    SI sock EST NUL ALORS RETOURNER MOINS 1
    DÉCLARER fd COMME ENTIER
    AFFECTER socket(domain, type, protocol) À fd
    SI fd EST ÉGAL À MOINS 1 ALORS RETOURNER MOINS 1
    AFFECTER fd À sock->fd
    RETOURNER 0
FIN
```

### 5.3 Visualisation

```
SOCKET LIFECYCLE :

socket() ──> bind() ──> listen() ──> accept() ──> send/recv ──> close()
   │           │           │            │             │            │
  fd=3      Assigned    Backlog     New fd=4      Data        fd=-1
          to port

SOCKADDR_IN STRUCTURE :

struct sockaddr_in {
  ┌─────────────────┐
  │ sin_family  │AF_INET│ = 2
  ├─────────────────┤
  │ sin_port    │8080 │ = htons(8080) = 0x1F90
  ├─────────────────┤
  │ sin_addr    │192.168.1.1│ = 0xC0A80101
  └─────────────────┘
}
```

### 5.4 Pièges

1. **Oubli htons()** : Le port DOIT être en network byte order
2. **Port 0** : Port 0 = "kernel chooses", valide mais souvent non voulu
3. **Fuite fd** : Toujours close() sur erreur après socket()
4. **sockaddr cast** : Toujours caster en (struct sockaddr*)

### 5.8 Mnémotechniques

**🚀 MEME : "See you space cowboy"**

Comme l'équipage du Bebop qui ferme toujours proprement les communications avant de partir, TOUJOURS fermer les sockets avec close().

```c
socket_t sock;
socket_create(&sock, AF_INET, SOCK_STREAM, 0);
// Do stuff
socket_close(&sock);  // See you space cowboy...
```

---

## ⚠️ SECTION 6 : PIÈGES

- Oubli htons/htonl
- Port non validé
- Fuite fd sur erreur
- Cast sockaddr manquant

---

## 📝 SECTION 7 : QCM

**Q1 :** Quelle fonction convertit host → network byte order pour un port ?
A) ntohl  B) htons ✅  C) inet_pton  D) ntohs

**Q2 :** Quel domaine pour IPv4 ?
A) AF_UNIX  B) AF_INET ✅  C) AF_INET6  D) PF_INET

**Q3 :** SOCK_STREAM correspond à :
A) UDP  B) TCP ✅  C) ICMP  D) Raw

---

## 📊 SECTION 8 : RÉCAPITULATIF

✅ socket() - créer endpoint
✅ sockaddr_in - adresse IPv4
✅ htons/htonl - endianness
✅ bind() - assigner port
✅ close() - fermer proprement

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "2.5.5-a-socket-endpoint",
    "metadata": {
      "difficulty": 6,
      "xp_base": 200,
      "meme_reference": "Cowboy Bebop - Space Radio"
    }
  }
}
```

---

**FIN DE L'EXERCICE**
