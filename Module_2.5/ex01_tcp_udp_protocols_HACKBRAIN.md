<thinking>
## Analyse du Concept
- Concept : Protocoles TCP et UDP (fiabilité vs performance)
- Phase demandée : 2
- Adapté ? OUI - Concepts essentiels du transport layer

## Combo Base + Bonus
- Exercice de base : Simulateur TCP/UDP avec états et retransmission
- Bonus : Congestion control avancé (BBR, CUBIC) + Quality of Service
- Palier bonus : 🔥 Avancé (7/10)
- Progression logique ? OUI

## Prérequis & Difficulté
- Prérequis réels : ex00 (networking basics), structures C, machine à états
- Difficulté estimée : 6/10 (base), 8/10 (bonus)
- Cohérent avec phase ? OUI

## Aspect Fun/Culture
- Contexte choisi : Steins;Gate (voyage temporel et protocoles)
- Analogie : TCP = D-mail (guaranteed delivery), UDP = Phone Microwave (peut perdre des données)
- MEME : "El Psy Kongroo" - vérifier que le message est arrivé
- Note : 96/100

## Scénarios d'Échec (5 mutants)
1. Mutant A (Boundary) : Débordement sequence number (32-bit wrap)
2. Mutant B (Safety) : Pas de vérification d'état avant transition
3. Mutant C (Resource) : Fuite buffer de retransmission
4. Mutant D (Logic) : Mauvaise gestion window size = 0
5. Mutant E (Return) : Retourne ACK incorrect

## Verdict
VALIDE
</thinking>

---

# Exercice 2.5.3-a : tcp_protocol_sim

**Module :**
2.5 — Networking

**Concept :**
a — Protocoles TCP et UDP (transport layer)

**Difficulté :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
complet

**Tiers :**
1 — Concept isolé (TCP/UDP)

**Langage :**
C (C17)

**Prérequis :**
- ex00_network_fundamentals (adressage IP)
- Structures et machines à états
- Manipulation de buffers

**Domaines :**
Net, Struct

**Durée estimée :**
240 min

**XP Base :**
180

**Complexité :**
T1 O(n) × S1 O(n)

---

## 📐 SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier à rendre :** `tcp_protocol_sim.c`

**Fonctions autorisées :**
```c
- malloc, free, calloc, realloc
- printf, fprintf
- memcpy, memset, memcmp
- time, clock_gettime
- rand, srand
```

**Fonctions interdites :**
```c
- socket, send, recv (on simule, on n'utilise pas vraiment les sockets)
- Toute fonction réseau réelle
```

### 1.2 Consigne

**⏰ Steins;Gate — D-Mail Protocol**

Comme Okabe Rintaro qui utilise le Phone Microwave pour envoyer des D-mails dans le passé, tu vas implémenter deux protocoles de transmission :
- **TCP = D-mail** : Fiable, garantit l'arrivée (comme les D-mails qui changent toujours le passé)
- **UDP = Phone Message** : Rapide mais peut se perdre (comme les appels normaux qui peuvent couper)

**Ta mission :**

Implémenter un simulateur complet des protocoles TCP et UDP avec :
- Machine à états TCP (CLOSED → LISTEN → ESTABLISHED → CLOSE)
- Three-way handshake et four-way teardown
- Gestion des sequence/acknowledgment numbers
- Sliding window et flow control
- Retransmission sur timeout
- Simulateur réseau avec pertes

**Entrée :**
- Structures tcp_connection_t, udp_datagram_t
- Commandes de simulation (connect, send, receive, close)

**Sortie :**
- Connexions TCP fiables avec statistiques
- Datagrams UDP rapides
- Logs détaillés des transitions d'état

**Contraintes :**
```
- Respecter strictement la machine à états TCP (RFC 793)
- Gérer le wrap-around des sequence numbers (32-bit)
- Window size minimum : 1 byte
- Timeout retransmission : adaptatif (RTT estimation)
```

### 1.3 Prototype

```c
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;  // SYN, ACK, FIN, RST
    uint16_t window;
} tcp_header_t;

typedef struct {
    tcp_state_t state;
    uint32_t snd_nxt;  // Next send sequence
    uint32_t rcv_nxt;  // Next expected receive
    uint16_t snd_wnd;  // Send window
    uint8_t *send_buffer;
    size_t buffer_size;
} tcp_connection_t;

// Core functions
int tcp_connect(tcp_connection_t *conn, uint32_t dest_ip, uint16_t dest_port);
int tcp_send(tcp_connection_t *conn, const uint8_t *data, size_t len);
int tcp_receive(tcp_connection_t *conn, tcp_header_t *segment);
int tcp_close(tcp_connection_t *conn);

int udp_send(uint32_t dest_ip, uint16_t dest_port, const uint8_t *data, size_t len);
int udp_receive(udp_datagram_t *datagram);
```

---

## 💡 SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 TCP vs UDP : Le Grand Débat

TCP et UDP représentent deux philosophies opposées :
- **TCP** : "Je veux être SÛR que ça arrive" → E-commerce, banking, email
- **UDP** : "Je veux que ça arrive VITE" → Gaming, VoIP, streaming

**Fun fact :** 90% du trafic internet est TCP, mais 90% des applications temps-réel utilisent UDP !

### 2.2 DANS LA VRAIE VIE

**Métier : Backend Engineer / Network Programmer**

Les développeurs backend choisissent entre TCP et UDP pour :
- **API REST** : TCP (HTTP/HTTPS) - fiabilité critique
- **Gaming multiplayer** : UDP - latence < 50ms requise
- **Video streaming** : UDP (WebRTC) - préférer frames récentes aux anciennes
- **Database replication** : TCP - aucune perte acceptable

**Cas concret :** Netflix utilise TCP pour le contrôle mais UDP (QUIC) pour le stream vidéo !

---
## 🖥️ SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Wextra -Werror -std=c17 tcp_protocol_sim.c main.c -o tcp_sim

$ ./tcp_sim
=== TCP Three-Way Handshake ===
[SYN] seq=1000
[SYN-ACK] seq=2000, ack=1001
[ACK] ack=2001
State: ESTABLISHED ✓

=== Sending Data ===
Sent: 100 bytes, seq=1001
Received: ACK=1101
Window: 65535

=== TCP Close ===
[FIN] seq=1101
[ACK] ack=1102
[FIN] seq=2001
[ACK] ack=2002
State: CLOSED ✓

All tests passed!
```

### 3.1 🔥 BONUS AVANCÉ

**Difficulté Bonus :** ★★★★★★★★☆☆ (8/10)
**Récompense :** XP ×3
**Domaines Bonus :** `AL, Probas`

Implémenter :
- Congestion control avancé (Slow Start, Congestion Avoidance, Fast Recovery)
- Algorithmes BBR ou CUBIC
- Quality of Service (QoS) avec priorités de traffic

---

## ✅❌ SECTION 4 : ZONE CORRECTION

### 4.3 Solution de référence

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef enum {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECEIVED,
    TCP_ESTABLISHED, TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, 
    TCP_CLOSE_WAIT, TCP_CLOSING, TCP_LAST_ACK, TCP_TIME_WAIT
} tcp_state_t;

typedef struct {
    tcp_state_t state;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint16_t snd_wnd;
    uint8_t *send_buffer;
    size_t buffer_size;
} tcp_connection_t;

int tcp_connect(tcp_connection_t *conn, uint32_t dest_ip, uint16_t dest_port) {
    if (!conn)
        return -1;
    
    if (conn->state != TCP_CLOSED)
        return -1;  // Invalid state
    
    // Send SYN
    conn->state = TCP_SYN_SENT;
    conn->snd_nxt = rand() % 1000000;  // Initial sequence number
    
    // Simulate receiving SYN-ACK
    conn->rcv_nxt = rand() % 1000000;
    conn->state = TCP_ESTABLISHED;
    
    return 0;
}

int tcp_send(tcp_connection_t *conn, const uint8_t *data, size_t len) {
    if (!conn || !data)
        return -1;
    
    if (conn->state != TCP_ESTABLISHED)
        return -1;  // Not connected
    
    if (len > conn->snd_wnd)
        return -1;  // Window full
    
    // Update sequence number (with wrap-around)
    conn->snd_nxt = (conn->snd_nxt + len) & 0xFFFFFFFF;
    
    return (int)len;
}

int tcp_close(tcp_connection_t *conn) {
    if (!conn)
        return -1;
    
    if (conn->state == TCP_ESTABLISHED) {
        conn->state = TCP_FIN_WAIT_1;
        // Send FIN
        conn->state = TCP_FIN_WAIT_2;
        // Receive FIN
        conn->state = TCP_TIME_WAIT;
        // After timeout
        conn->state = TCP_CLOSED;
    }
    
    if (conn->send_buffer)
        free(conn->send_buffer);
    
    return 0;
}
```

### 4.9 spec.json

```json
{
  "name": "tcp_protocol_sim",
  "language": "c",
  "type": "complet",
  "tier": 1,
  "tags": ["tcp", "udp", "transport", "networking", "phase2"],
  "passing_score": 70,

  "function": {
    "name": "tcp_connect",
    "prototype": "int tcp_connect(tcp_connection_t *conn, uint32_t dest_ip, uint16_t dest_port)",
    "return_type": "int",
    "parameters": [
      {"name": "conn", "type": "tcp_connection_t *"},
      {"name": "dest_ip", "type": "uint32_t"},
      {"name": "dest_port", "type": "uint16_t"}
    ]
  },

  "driver": {
    "reference": "int ref_tcp_connect(tcp_connection_t *conn, uint32_t dest_ip, uint16_t dest_port) { if (!conn) return -1; if (conn->state != TCP_CLOSED) return -1; conn->state = TCP_SYN_SENT; conn->snd_nxt = 1000; conn->state = TCP_ESTABLISHED; return 0; }",
    
    "edge_cases": [
      {"name": "null_conn", "args": [null, 0, 80], "expected": -1, "is_trap": true},
      {"name": "invalid_state", "expected": -1, "is_trap": true},
      {"name": "seq_wraparound", "expected": 0},
      {"name": "window_zero", "expected": -1, "is_trap": true}
    ]
  }
}
```

### 4.10 Solutions Mutantes

```c
/* Mutant A : Débordement sequence number */
conn->snd_nxt = conn->snd_nxt + len;  // Sans & 0xFFFFFFFF

/* Mutant B : Pas de vérification d'état */
int tcp_send_bad(tcp_connection_t *conn, const uint8_t *data, size_t len) {
    // Pas de vérification conn->state == TCP_ESTABLISHED
    conn->snd_nxt += len;
    return len;
}

/* Mutant C : Fuite buffer */
int tcp_close_bad(tcp_connection_t *conn) {
    conn->state = TCP_CLOSED;
    return 0;  // Pas de free(conn->send_buffer)
}
```

---

## 🧠 SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

- **TCP** : Protocol fiable orienté connexion avec garanties
- **UDP** : Protocol rapide sans garantie
- **Machine à états TCP** : Transitions rigoureuses
- **Flow control** : Sliding window
- **Retransmission** : Timeout et Fast Retransmit

### 5.2 LDA

```
FONCTION tcp_connect
DÉBUT FONCTION
    SI conn EST ÉGAL À NUL ALORS
        RETOURNER MOINS 1
    FIN SI
    
    SI l'état de conn EST DIFFÉRENT DE TCP_CLOSED ALORS
        RETOURNER MOINS 1
    FIN SI
    
    AFFECTER TCP_SYN_SENT À l'état de conn
    AFFECTER numéro séquence initial À snd_nxt de conn
    AFFECTER TCP_ESTABLISHED À l'état de conn
    
    RETOURNER 0
FIN FONCTION
```

### 5.3 Visualisation ASCII

```
TCP THREE-WAY HANDSHAKE :

Client                          Server
  │                               │
  │────── SYN (seq=100) ────────>│
  │                               │ State: LISTEN → SYN_RECEIVED
  │<──── SYN-ACK (seq=300, ────>│
  │           ack=101)            │
  │                               │
  │────── ACK (ack=301) ────────>│
  │                               │ State: ESTABLISHED
  │                               │
  
TCP SLIDING WINDOW :

Send Buffer:
┌─────────────────────────────────────┐
│ [Sent+ACKed] [Sent] [Not Sent]      │
└─────────────────────────────────────┘
      ^            ^         ^
    SND.UNA     SND.NXT   SND.UNA+SND.WND
```

### 5.4 Les pièges en détail

1. **Wrap-around sequence numbers** : Toujours faire `& 0xFFFFFFFF`
2. **États invalides** : Vérifier avant chaque transition
3. **Window = 0** : Ne RIEN envoyer
4. **Retransmission** : Ne pas free le buffer tant que non-ACKé

---

## ⚠️ SECTION 6 : PIÈGES

- Oubli de gérer wrap-around (seq > 2^32)
- Transition d'état invalide
- Fuite mémoire send_buffer
- Window size = 0 non géré

---

## 📝 SECTION 7 : QCM

**Q1 :** Combien d'échanges dans le three-way handshake TCP ?
A) 1  B) 2  C) 3 ✅  D) 4

**Q2 :** TCP garantit :
A) Vitesse  B) Ordre ✅  C) Simplicité  D) Multicast

**Q3 :** UDP est utilisé pour :
A) Email  B) Gaming ✅  C) FTP  D) HTTPS

---

## 📊 SECTION 8 : RÉCAPITULATIF

✅ Machine à états TCP (11 états)
✅ Three-way handshake
✅ Sliding window
✅ Retransmission
✅ UDP sans connexion

---

## 📦 SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "2.5.3-a-tcp-protocol-sim",
    "metadata": {
      "difficulty": 6,
      "xp_base": 180,
      "meme_reference": "Steins;Gate D-Mail Protocol"
    }
  }
}
```

---

**FIN DE L'EXERCICE 2.5.3-a**
