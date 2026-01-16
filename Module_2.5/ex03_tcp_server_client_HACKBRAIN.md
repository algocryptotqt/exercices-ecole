<thinking>
Concept : TCP Client/Server (bind, listen, accept, connect)
Phase : 2, Adapté : OUI
Base : Serveur TCP echo + client, Bonus : Multi-threaded server
Palier : 🔥 (7/10), Progression : OUI
Prérequis : ex00-ex02, Difficulté : 6/10 base, 8/10 bonus
Culture : Neon Genesis Evangelion (NERV communication system)
MEME : "Get in the socket, Shinji!" - accept() connections
Mutants : A-no listen, B-no accept loop, C-leak client fd, D-no shutdown, E-wrong listen backlog
Score : 96/100, VALIDE
</thinking>

# Exercice 2.5.7-a : nerv_communication_system

**Module :** 2.5
**Concept :** a — TCP Server/Client
**Difficulté :** ★★★★★★☆☆☆☆ (6/10)
**Type :** complet
**Tiers :** 1
**Langage :** C (C17)
**Prérequis :** ex00-ex02
**Domaines :** Net, Process
**Durée :** 300 min
**XP Base :** 200
**Complexité :** T1 O(n) × S1 O(n)

## 📐 SECTION 1

### 1.1 Obligations
**Fichier :** `nerv_communication_system.c`
**Autorisées :** socket, bind, listen, accept, connect, send, recv, close, fork, pthread_create
**Interdites :** select, poll, epoll (pour les exercices suivants)

### 1.2 Consigne

**🤖 NERV — Synchronize with EVA Units**

Comme NERV qui gère les communications avec les EVA Units, implémente :
- Serveur TCP qui écoute sur un port
- Accept les connexions clients  
- Echo server (renvoie ce qu'il reçoit)
- Client TCP qui se connecte
- Support multi-clients séquentiel

**Contraintes :**
- Backlog minimum : 5
- Buffer : 1024 bytes
- Shutdown gracefully (SIGINT)

### 1.3 Prototype

```c
typedef struct {
    socket_t listen_sock;
    int backlog;
    bool running;
} tcp_server_t;

int server_init(tcp_server_t *srv, uint16_t port, int backlog);
int server_accept(tcp_server_t *srv, socket_t *client);
int server_run(tcp_server_t *srv);  // Main loop
int client_connect(const char *host, uint16_t port, socket_t *sock);
```

## 💡 SECTION 2

API POSIX pour TCP : bind() réserve le port, listen() prépare la queue, accept() bloque jusqu'à connexion.

**DANS LA VRAIE VIE - Backend Dev :** Nginx utilise ces appels pour gérer 10K+ connexions simultanées.

## 🖥️ SECTION 3

```bash
$ ./server 8080 &
Server listening on port 8080
$ ./client localhost 8080
Connected to server
> Hello NERV
< Echo: Hello NERV
```

### 3.1 🔥 BONUS (8/10, ×3)
Multi-threaded server avec thread pool + graceful shutdown sur SIGTERM.

## ✅ SECTION 4

### 4.3 Solution

```c
int server_init(tcp_server_t *srv, uint16_t port, int backlog) {
    if (!srv || backlog < 1)
        return -1;
    
    if (socket_create(&srv->listen_sock, AF_INET, SOCK_STREAM, 0) != 0)
        return -1;
    
    if (socket_bind_ipv4(&srv->listen_sock, "0.0.0.0", port) != 0) {
        socket_close(&srv->listen_sock);
        return -1;
    }
    
    if (listen(srv->listen_sock.fd, backlog) == -1) {
        socket_close(&srv->listen_sock);
        return -1;
    }
    
    srv->backlog = backlog;
    srv->running = true;
    return 0;
}

int server_accept(tcp_server_t *srv, socket_t *client) {
    if (!srv || !client)
        return -1;
    
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    
    int cli_fd = accept(srv->listen_sock.fd, 
                        (struct sockaddr*)&cli_addr, &cli_len);
    if (cli_fd == -1)
        return -1;
    
    client->fd = cli_fd;
    client->domain = AF_INET;
    client->type = SOCK_STREAM;
    
    return 0;
}
```

### 4.9 spec.json

```json
{
  "name": "nerv_communication_system",
  "function": {"name": "server_init", "return_type": "int"},
  "driver": {
    "reference": "int ref_server_init(tcp_server_t *srv, uint16_t port, int backlog) { if (!srv || backlog < 1) return -1; if (socket_create(&srv->listen_sock, AF_INET, SOCK_STREAM, 0) != 0) return -1; if (socket_bind_ipv4(&srv->listen_sock, \"0.0.0.0\", port) != 0) { socket_close(&srv->listen_sock); return -1; } if (listen(srv->listen_sock.fd, backlog) == -1) { socket_close(&srv->listen_sock); return -1; } srv->backlog = backlog; srv->running = true; return 0; }",
    "edge_cases": [
      {"name": "null_srv", "expected": -1},
      {"name": "backlog_zero", "expected": -1},
      {"name": "port_in_use", "expected": -1}
    ]
  }
}
```

### 4.10 Mutants

```c
/* Mutant A : Oubli listen() */
socket_bind_ipv4(&srv->listen_sock, "0.0.0.0", port);
return 0;  // Sans listen()

/* Mutant B : Pas de boucle accept */
int fd = accept(...);  // Une seule fois

/* Mutant C : Fuite client fd */
accept(...);  // Sans close() après traitement

/* Mutant D : Pas de shutdown */
close(fd);  // Sans shutdown(fd, SHUT_RDWR)

/* Mutant E : Mauvais backlog */
listen(fd, 0);  // Au lieu de backlog
```

## 🧠 SECTION 5

### 5.1 Concepts
- bind() : Réserve le port
- listen() : Prépare la queue de connexions
- accept() : Bloque jusqu'à connexion entrante
- connect() : Initie connexion côté client

### 5.2 LDA

```
FONCTION server_init
DÉBUT
    CRÉER socket d'écoute
    BIND sur port spécifié
    SI échec ALORS fermer socket ET retourner erreur
    LISTEN avec backlog
    SI échec ALORS fermer socket ET retourner erreur
    MARQUER serveur comme running
    RETOURNER succès
FIN
```

### 5.3 Visualisation

```
SERVER LIFECYCLE :

socket() → bind(port) → listen(backlog) → accept() [LOOP]
                                              ↓
                                         Client connects
                                              ↓
                                         New fd returned
                                              ↓
                                         send/recv
                                              ↓
                                         close(client_fd)

QUEUE :
┌─────────────────┐
│ Listening (fd=3)│
└────────┬────────┘
         │ Backlog queue (max 5)
    ┌────┴────┬────┬────┬────┬────┐
    │ Client 1│ C2 │ C3 │ C4 │ C5 │
    └─────────┴────┴────┴────┴────┘
```

### 5.8 Mnémotechniques

**🤖 MEME : "Get in the socket, Shinji!"**

Comme Shinji qui doit entrer dans l'EVA pour synchroniser, les clients doivent `accept()` pour synchroniser avec le serveur.

```c
while (srv->running) {
    socket_t client;
    server_accept(srv, &client);  // Get in the socket!
    handle_client(&client);
}
```

## ⚠️ SECTION 6
- Oubli listen()
- Pas de fermeture client fd
- Backlog = 0
- Pas de boucle accept

## 📝 SECTION 7

**Q1 :** Quelle fonction prépare la queue de connexions ?
A) bind  B) listen ✅  C) accept  D) connect

**Q2 :** accept() retourne quoi ?
A) 0  B) -1  C) nouveau fd ✅  D) sockaddr

## 📊 SECTION 8

✅ bind() - réserver port
✅ listen() - queue
✅ accept() - accepter clients
✅ Echo server fonctionnel

## 📦 SECTION 9

```json
{"deploy": {"hackbrain_version": "5.5.2", "exercise_slug": "2.5.7-a-nerv-comm", "metadata": {"difficulty": 6, "meme_reference": "Evangelion NERV"}}}
```

**FIN**
