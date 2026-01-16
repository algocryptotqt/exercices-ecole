# Exercice 0.9.40 : socket_server

**Module :**
0.9 — Systems Programming

**Concept :**
socket(), bind(), listen(), accept(), TCP/IP networking

**Difficulte :**
6/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
C (c17)

**Prerequis :**
- Syntaxe C de base
- fork() et processus
- File descriptors et I/O
- Notions de base sur les reseaux (IP, ports)

**Domaines :**
Network, IPC, Unix, Sys

**Duree estimee :**
90 min

**XP Base :**
200

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `socket_server.c`, `socket_server.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `read`, `write`, `close`, `shutdown`, `setsockopt`, `getsockopt`, `getaddrinfo`, `freeaddrinfo`, `inet_ntop`, `inet_pton`, `htons`, `htonl`, `ntohs`, `ntohl`, `fork`, `wait`, `select`, `poll`, `perror`, `printf` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | Bibliotheques reseau de haut niveau (pas de libcurl, etc.) |

---

### 1.2 Consigne

#### Section Culture : "Stargate - Le Reseau Galactique"

**STARGATE SG-1 - "Chevron Seven Locked!"**

La Porte des Etoiles est un systeme de communication inter-galactique. Pour etablir une connexion, il faut :
1. **Dial** (composer l'adresse) = `socket()` + `connect()`
2. **Chevrons** (7 symboles) = IP + Port (adresse complete)
3. **Kawoosh** (etablissement) = `accept()` (connexion etablie)
4. **Wormhole** (tunnel) = connexion TCP etablie
5. **IDC** (code d'identification) = authentification

*"In the network of the universe, every computer is a Stargate. socket() is how you dial out, accept() is how you receive travelers."*

Le General Hammond t'explique :
- **SGC (Serveur)** = `bind()` + `listen()` - attend les connexions entrantes
- **SG-1 (Client)** = `connect()` - initie la connexion
- **Iris** = pare-feu - filtre les connexions non autorisees
- **GDO** = protocole applicatif - messages echanges

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un serveur TCP et un client avec les fonctionnalites suivantes :

1. **create_server** : Cree un socket serveur et le met en ecoute
2. **accept_client** : Accepte une connexion entrante
3. **create_client** : Connecte un client a un serveur
4. **send_message** : Envoie des donnees sur une connexion
5. **receive_message** : Recoit des donnees d'une connexion

**Entree (C) :**

```c
#ifndef SOCKET_SERVER_H
# define SOCKET_SERVER_H

# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <stddef.h>

typedef struct s_server {
    int                 socket_fd;
    struct sockaddr_in  addr;
    int                 port;
    int                 backlog;
    int                 is_running;
} t_server;

typedef struct s_client {
    int                 socket_fd;
    struct sockaddr_in  server_addr;
    struct sockaddr_in  local_addr;
    int                 is_connected;
} t_client;

typedef struct s_connection {
    int                 socket_fd;
    struct sockaddr_in  peer_addr;
    char                peer_ip[INET_ADDRSTRLEN];
    int                 peer_port;
} t_connection;

// === SERVER FUNCTIONS ===

// Cree un serveur TCP ecoutant sur le port specifie
// backlog = nombre max de connexions en attente
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     create_server(t_server *srv, int port, int backlog);

// Accepte une connexion entrante (bloquant)
// Retourne un pointeur vers la nouvelle connexion ou NULL
t_connection *accept_client(t_server *srv);

// Ferme le serveur et libere les ressources
void    close_server(t_server *srv);

// === CLIENT FUNCTIONS ===

// Cree un client et se connecte au serveur specifie
// Retourne 0 en cas de succes, -1 en cas d'erreur
int     create_client(t_client *cli, const char *host, int port);

// Ferme la connexion client
void    close_client(t_client *cli);

// === COMMUNICATION FUNCTIONS ===

// Envoie des donnees sur un socket
// Retourne le nombre d'octets envoyes ou -1 en cas d'erreur
ssize_t send_message(int socket_fd, const void *data, size_t len);

// Recoit des donnees depuis un socket
// Retourne le nombre d'octets recus ou -1 en cas d'erreur
ssize_t receive_message(int socket_fd, void *buffer, size_t max_len);

// Envoie une chaine de caracteres (avec newline)
int     send_line(int socket_fd, const char *line);

// Recoit une ligne (jusqu'au newline)
// Retourne le nombre de caracteres ou -1
ssize_t receive_line(int socket_fd, char *buffer, size_t max_len);

// Ferme proprement une connexion
void    close_connection(t_connection *conn);

// === UTILITY FUNCTIONS ===

// Convertit une adresse IP en chaine
const char *get_peer_ip(t_connection *conn);

// Retourne le port du peer
int     get_peer_port(t_connection *conn);

#endif
```

**Sortie :**
- `create_server` : 0 succes, -1 erreur
- `accept_client` : t_connection* ou NULL
- `create_client` : 0 succes, -1 erreur
- `send_message` : nombre d'octets ou -1
- `receive_message` : nombre d'octets ou -1

**Contraintes :**
- Gerer les erreurs de connexion
- Utiliser SO_REUSEADDR pour eviter "Address already in use"
- Fermer proprement les sockets
- Gerer les signaux (SIGPIPE) pour les connexions fermees

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `create_server(&srv, 8080, 5)` | - | 0 | Serveur sur port 8080 |
| `accept_client(&srv)` | - | conn* | Attente de connexion |
| `create_client(&cli, "127.0.0.1", 8080)` | - | 0 | Connexion au serveur |
| `send_message(fd, "Hello", 5)` | - | 5 | 5 octets envoyes |

---

### 1.3 Prototype

**C :**
```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int     create_server(t_server *srv, int port, int backlog);
t_connection *accept_client(t_server *srv);
void    close_server(t_server *srv);
int     create_client(t_client *cli, const char *host, int port);
void    close_client(t_client *cli);
ssize_t send_message(int socket_fd, const void *data, size_t len);
ssize_t receive_message(int socket_fd, void *buffer, size_t max_len);
int     send_line(int socket_fd, const char *line);
ssize_t receive_line(int socket_fd, char *buffer, size_t max_len);
void    close_connection(t_connection *conn);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Les sockets Berkeley**

Les sockets ont ete inventes pour BSD Unix en 1983 par Bill Joy. Ils sont devenus le standard pour la communication reseau sur tous les OS (meme Windows les utilise avec Winsock).

**PORT 80 et 443**

Les ports en dessous de 1024 sont "privilegies" et necessitent les droits root. C'est pourquoi les serveurs web utilisent souvent nginx/apache en reverse proxy.

**Le three-way handshake**

Chaque connexion TCP commence par un handshake :
1. Client -> SYN -> Server
2. Server -> SYN-ACK -> Client
3. Client -> ACK -> Server

Cela prend ~1.5 RTT (Round Trip Time) avant que les donnees puissent etre envoyees.

**SO_REUSEADDR**

Sans cette option, apres avoir ferme un serveur, le port reste en etat TIME_WAIT pendant ~2 minutes. SO_REUSEADDR permet de rebind immediatement.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Backend Developer** | Serveurs HTTP, API REST |
| **Game Developer** | Serveurs de jeux multijoueurs |
| **DevOps Engineer** | Load balancers, proxies |
| **Security Engineer** | Scanners de ports, honeypots |
| **Embedded Developer** | IoT, communication M2M |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat server_main.c
#include "socket_server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

volatile int running = 1;

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    t_server srv;
    if (create_server(&srv, 8080, 5) == -1) {
        perror("create_server");
        return 1;
    }

    printf("Server listening on port %d...\n", srv.port);

    while (running) {
        printf("Waiting for connection...\n");
        t_connection *conn = accept_client(&srv);
        if (!conn) continue;

        printf("Client connected from %s:%d\n",
               get_peer_ip(conn), get_peer_port(conn));

        char buffer[1024];
        ssize_t n = receive_line(conn->socket_fd, buffer, sizeof(buffer));
        if (n > 0) {
            printf("Received: %s\n", buffer);
            send_line(conn->socket_fd, "Message received!");
        }

        close_connection(conn);
    }

    close_server(&srv);
    printf("Server stopped.\n");
    return 0;
}

$ cat client_main.c
#include "socket_server.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *msg = argc > 1 ? argv[1] : "Hello, Server!";

    t_client cli;
    if (create_client(&cli, "127.0.0.1", 8080) == -1) {
        perror("create_client");
        return 1;
    }

    printf("Connected to server!\n");

    send_line(cli.socket_fd, msg);
    printf("Sent: %s\n", msg);

    char response[1024];
    ssize_t n = receive_line(cli.socket_fd, response, sizeof(response));
    if (n > 0) {
        printf("Server response: %s\n", response);
    }

    close_client(&cli);
    return 0;
}

$ gcc -Wall -Wextra socket_server.c server_main.c -o server
$ gcc -Wall -Wextra socket_server.c client_main.c -o client

# Terminal 1:
$ ./server
Server listening on port 8080...
Waiting for connection...
Client connected from 127.0.0.1:54321
Received: Hello, Server!
Waiting for connection...
^C
Server stopped.

# Terminal 2:
$ ./client "Testing socket communication"
Connected to server!
Sent: Testing socket communication
Server response: Message received!
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
8/10

**Recompense :**
XP x2.5

**Consigne Bonus :**

Implementer un serveur multi-client concurrent :

```c
typedef void (*client_handler)(t_connection *conn, void *user_data);

typedef struct s_multi_server {
    t_server    base;
    int         max_clients;
    int         current_clients;
} t_multi_server;

// Serveur avec fork() pour chaque client
int run_forking_server(t_server *srv, client_handler handler, void *data);

// Serveur avec select()/poll() pour multiplexage I/O
int run_select_server(t_server *srv, client_handler handler, void *data);

// Exemple de handler:
void echo_handler(t_connection *conn, void *data) {
    char buf[1024];
    ssize_t n;
    while ((n = receive_message(conn->socket_fd, buf, sizeof(buf))) > 0) {
        send_message(conn->socket_fd, buf, n);  // Echo back
    }
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_server | create_server(&s, 8080, 5) | 0 | 10 | Basic |
| 2 | server_listen | netstat -tlnp | port open | 5 | Basic |
| 3 | client_connect | create_client to server | 0 | 10 | Connect |
| 4 | send_receive | send "hello", receive | "hello" | 15 | IO |
| 5 | multiple_clients | 3 sequential clients | all work | 10 | Multi |
| 6 | large_message | send 1MB | received intact | 10 | Stress |
| 7 | connection_refused | connect to closed port | -1 | 10 | Error |
| 8 | reuse_addr | restart server quickly | works | 10 | Option |
| 9 | peer_info | get_peer_ip/port | correct | 5 | Info |
| 10 | clean_shutdown | close all | no leaks | 15 | Cleanup |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "socket_server.h"

#define TEST_PORT 19876

void test_create_server(void) {
    t_server srv;
    assert(create_server(&srv, TEST_PORT, 5) == 0);
    assert(srv.socket_fd >= 0);
    assert(srv.port == TEST_PORT);
    close_server(&srv);
    printf("Test create_server: OK\n");
}

void test_client_connect(void) {
    t_server srv;
    create_server(&srv, TEST_PORT + 1, 5);

    pid_t pid = fork();
    if (pid == 0) {
        // Child: client
        usleep(100000); // Wait for server
        t_client cli;
        int ret = create_client(&cli, "127.0.0.1", TEST_PORT + 1);
        close_client(&cli);
        exit(ret == 0 ? 0 : 1);
    }

    // Parent: server
    t_connection *conn = accept_client(&srv);
    assert(conn != NULL);
    close_connection(conn);

    int status;
    wait(&status);
    assert(WEXITSTATUS(status) == 0);

    close_server(&srv);
    printf("Test client_connect: OK\n");
}

void test_send_receive(void) {
    t_server srv;
    create_server(&srv, TEST_PORT + 2, 5);

    pid_t pid = fork();
    if (pid == 0) {
        usleep(100000);
        t_client cli;
        create_client(&cli, "127.0.0.1", TEST_PORT + 2);
        send_message(cli.socket_fd, "Hello Server!", 13);

        char buf[64];
        receive_message(cli.socket_fd, buf, sizeof(buf));
        close_client(&cli);
        exit(strcmp(buf, "Hello Client!") == 0 ? 0 : 1);
    }

    t_connection *conn = accept_client(&srv);
    char buf[64] = {0};
    ssize_t n = receive_message(conn->socket_fd, buf, sizeof(buf));
    assert(n == 13);
    assert(strcmp(buf, "Hello Server!") == 0);

    send_message(conn->socket_fd, "Hello Client!", 13);
    close_connection(conn);

    int status;
    wait(&status);
    assert(WEXITSTATUS(status) == 0);

    close_server(&srv);
    printf("Test send_receive: OK\n");
}

void test_peer_info(void) {
    t_server srv;
    create_server(&srv, TEST_PORT + 3, 5);

    pid_t pid = fork();
    if (pid == 0) {
        usleep(100000);
        t_client cli;
        create_client(&cli, "127.0.0.1", TEST_PORT + 3);
        sleep(1);
        close_client(&cli);
        exit(0);
    }

    t_connection *conn = accept_client(&srv);
    assert(conn != NULL);
    assert(strcmp(get_peer_ip(conn), "127.0.0.1") == 0);
    assert(get_peer_port(conn) > 0);

    close_connection(conn);
    wait(NULL);
    close_server(&srv);
    printf("Test peer_info: OK\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    test_create_server();
    test_client_connect();
    test_send_receive();
    test_peer_info();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "socket_server.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int create_server(t_server *srv, int port, int backlog) {
    if (!srv || port <= 0 || port > 65535)
        return -1;

    memset(srv, 0, sizeof(t_server));

    srv->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->socket_fd == -1)
        return -1;

    // Allow reuse of address
    int opt = 1;
    if (setsockopt(srv->socket_fd, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)) == -1) {
        close(srv->socket_fd);
        return -1;
    }

    srv->addr.sin_family = AF_INET;
    srv->addr.sin_addr.s_addr = INADDR_ANY;
    srv->addr.sin_port = htons(port);
    srv->port = port;
    srv->backlog = backlog;

    if (bind(srv->socket_fd, (struct sockaddr*)&srv->addr,
             sizeof(srv->addr)) == -1) {
        close(srv->socket_fd);
        return -1;
    }

    if (listen(srv->socket_fd, backlog) == -1) {
        close(srv->socket_fd);
        return -1;
    }

    srv->is_running = 1;
    return 0;
}

t_connection *accept_client(t_server *srv) {
    if (!srv || srv->socket_fd < 0)
        return NULL;

    t_connection *conn = malloc(sizeof(t_connection));
    if (!conn)
        return NULL;

    socklen_t addr_len = sizeof(conn->peer_addr);
    conn->socket_fd = accept(srv->socket_fd,
                             (struct sockaddr*)&conn->peer_addr,
                             &addr_len);

    if (conn->socket_fd == -1) {
        free(conn);
        return NULL;
    }

    inet_ntop(AF_INET, &conn->peer_addr.sin_addr,
              conn->peer_ip, INET_ADDRSTRLEN);
    conn->peer_port = ntohs(conn->peer_addr.sin_port);

    return conn;
}

void close_server(t_server *srv) {
    if (!srv)
        return;
    if (srv->socket_fd >= 0) {
        close(srv->socket_fd);
        srv->socket_fd = -1;
    }
    srv->is_running = 0;
}

int create_client(t_client *cli, const char *host, int port) {
    if (!cli || !host || port <= 0 || port > 65535)
        return -1;

    memset(cli, 0, sizeof(t_client));

    cli->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cli->socket_fd == -1)
        return -1;

    cli->server_addr.sin_family = AF_INET;
    cli->server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &cli->server_addr.sin_addr) <= 0) {
        close(cli->socket_fd);
        return -1;
    }

    if (connect(cli->socket_fd, (struct sockaddr*)&cli->server_addr,
                sizeof(cli->server_addr)) == -1) {
        close(cli->socket_fd);
        return -1;
    }

    cli->is_connected = 1;
    return 0;
}

void close_client(t_client *cli) {
    if (!cli)
        return;
    if (cli->socket_fd >= 0) {
        close(cli->socket_fd);
        cli->socket_fd = -1;
    }
    cli->is_connected = 0;
}

ssize_t send_message(int socket_fd, const void *data, size_t len) {
    if (socket_fd < 0 || !data || len == 0)
        return -1;

    ssize_t total = 0;
    const char *ptr = data;

    while (total < (ssize_t)len) {
        ssize_t n = send(socket_fd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return total > 0 ? total : -1;
        }
        total += n;
    }

    return total;
}

ssize_t receive_message(int socket_fd, void *buffer, size_t max_len) {
    if (socket_fd < 0 || !buffer || max_len == 0)
        return -1;

    ssize_t n;
    while ((n = recv(socket_fd, buffer, max_len, 0)) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }

    return n;
}

int send_line(int socket_fd, const char *line) {
    if (!line)
        return -1;

    size_t len = strlen(line);
    if (send_message(socket_fd, line, len) != (ssize_t)len)
        return -1;
    if (send_message(socket_fd, "\n", 1) != 1)
        return -1;

    return 0;
}

ssize_t receive_line(int socket_fd, char *buffer, size_t max_len) {
    if (socket_fd < 0 || !buffer || max_len == 0)
        return -1;

    size_t total = 0;
    char c;

    while (total < max_len - 1) {
        ssize_t n = recv(socket_fd, &c, 1, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        if (c == '\n')
            break;
        buffer[total++] = c;
    }

    buffer[total] = '\0';
    return total;
}

void close_connection(t_connection *conn) {
    if (!conn)
        return;
    if (conn->socket_fd >= 0)
        close(conn->socket_fd);
    free(conn);
}

const char *get_peer_ip(t_connection *conn) {
    return conn ? conn->peer_ip : NULL;
}

int get_peer_port(t_connection *conn) {
    return conn ? conn->peer_port : -1;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de verification port**

```c
/* Mutant A : Port invalide */
int create_server(t_server *srv, int port, int backlog) {
    srv->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    srv->addr.sin_port = htons(port); // Port peut etre negatif ou > 65535 !
    bind(srv->socket_fd, ...);
    return 0;
}
// Pourquoi c'est faux: htons(-1) = 65535, mais bind peut echouer
```

**Mutant B (Safety) : Pas de SO_REUSEADDR**

```c
/* Mutant B : Address already in use */
int create_server(t_server *srv, int port, int backlog) {
    srv->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    // ERREUR: pas de setsockopt(SO_REUSEADDR) !
    bind(srv->socket_fd, ...);
    listen(srv->socket_fd, backlog);
    return 0;
}
// Pourquoi c'est faux: Impossible de redemarrer le serveur pendant 2min
```

**Mutant C (Resource) : Fuite de socket sur erreur**

```c
/* Mutant C : Socket leak */
int create_server(t_server *srv, int port, int backlog) {
    srv->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(srv->socket_fd, ...) == -1)
        return -1;  // ERREUR: socket pas ferme !
    ...
}
// Pourquoi c'est faux: Fuite de FD sur chaque erreur bind()
```

**Mutant D (Logic) : Pas de conversion byte order**

```c
/* Mutant D : Big/Little endian bug */
int create_server(t_server *srv, int port, int backlog) {
    srv->addr.sin_port = port;  // ERREUR: devrait etre htons(port) !
    // Sur little endian: port 8080 (0x1F90) devient 36895 (0x901F)
    bind(srv->socket_fd, ...);
    ...
}
// Pourquoi c'est faux: Port incorrect sur architectures little-endian
```

**Mutant E (Return) : Ignore les erreurs send/recv**

```c
/* Mutant E : Donnees perdues */
ssize_t send_message(int socket_fd, const void *data, size_t len) {
    return send(socket_fd, data, len, 0);
    // ERREUR: send peut envoyer moins que demande !
}
// Pourquoi c'est faux: Partial send non gere, donnees perdues
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| socket() | Creation de point de communication | Fondamental |
| bind() | Association adresse/port | Essentiel |
| listen()/accept() | Mode serveur | Essentiel |
| connect() | Mode client | Essentiel |
| send()/recv() | Echange de donnees | Fondamental |

---

### 5.2 LDA - Traduction litterale

```
FONCTION create_server QUI PREND srv, port, backlog
DEBUT FONCTION
    CREER UN SOCKET TCP AVEC socket(AF_INET, SOCK_STREAM, 0)
    SI ERREUR ALORS RETOURNER -1

    ACTIVER L'OPTION SO_REUSEADDR

    CONFIGURER L'ADRESSE:
        famille = IPv4
        adresse = toutes les interfaces (INADDR_ANY)
        port = htons(port)  // Conversion byte order

    ASSOCIER LE SOCKET A L'ADRESSE AVEC bind()
    SI ERREUR ALORS FERMER SOCKET ET RETOURNER -1

    METTRE LE SOCKET EN MODE ECOUTE AVEC listen()
    SI ERREUR ALORS FERMER SOCKET ET RETOURNER -1

    RETOURNER 0 (succes)
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
TCP CONNECTION : Le Three-Way Handshake
========================================

    CLIENT                                SERVER
       |                                     |
       |         socket() + bind()           |
       |         listen()                    |
       |                                     |
       |   --------- SYN ----------->        |
       |                                     | accept() (bloque)
       |   <------- SYN-ACK ---------        |
       |                                     |
       |   --------- ACK ----------->        |
       |                                     | accept() retourne
       |   <==== CONNECTION ESTABLISHED ====>|
       |                                     |


SERVER SOCKET FLOW
==================

+--------+     +--------+     +--------+     +--------+
|socket()|---->| bind() |---->|listen()|---->|accept()|
+--------+     +--------+     +--------+     +--------+
                   |                              |
            Assigne IP:Port              Retourne nouveau FD
                                         pour chaque client


CLIENT SOCKET FLOW
==================

+--------+     +---------+
|socket()|---->|connect()|
+--------+     +---------+
                    |
             Connexion au serveur


MULTIPLEXAGE : Un serveur, plusieurs clients
============================================

                    +----------+
                    |  SERVER  |
                    | socket=3 |
                    +----+-----+
                         |
           +-------------+-------------+
           |             |             |
      +----+----+   +----+----+   +----+----+
      |Client 1 |   |Client 2 |   |Client 3 |
      | conn=4  |   | conn=5  |   | conn=6  |
      +---------+   +---------+   +---------+

Le serveur a un socket d'ecoute (3) et un socket
de connexion par client (4, 5, 6).


BYTE ORDER : Network vs Host
============================

Host (Little-Endian x86):          Network (Big-Endian):
Port 8080 = 0x1F90                 Port 8080 = 0x901F

Memory:    [90] [1F]               Memory:    [1F] [90]
           Low  High                          Low  High

htons(8080) convertit:
    0x1F90 (host) -> 0x901F (network)

ntohs(0x901F) convertit:
    0x901F (network) -> 0x1F90 (host)


STRUCTURE sockaddr_in
=====================

struct sockaddr_in {
    sa_family_t    sin_family;   // AF_INET (IPv4)
    in_port_t      sin_port;     // Port (network byte order)
    struct in_addr sin_addr;     // IP address
    char           sin_zero[8];  // Padding
};

          +----------------+
          | sin_family (2) |  AF_INET = 2
          +----------------+
          | sin_port (2)   |  htons(8080)
          +----------------+
          | sin_addr (4)   |  0.0.0.0 ou IP specifique
          +----------------+
          | sin_zero (8)   |  Padding (zeros)
          +----------------+
```

---

## SECTION 6 : AIDE ET RESSOURCES

### 6.1 Ressources recommandees

- `man 2 socket` - Creation de socket
- `man 7 ip` - Protocole IP
- `man 7 tcp` - Protocole TCP
- "Beej's Guide to Network Programming" (classique!)
- `man 2 select` / `man 2 poll` - Pour le bonus

### 6.2 Commandes utiles

```bash
# Voir les ports ouverts
netstat -tlnp
ss -tlnp

# Tester un serveur avec netcat
nc localhost 8080

# Scanner les ports
nmap -p 8080 localhost

# Voir les connexions etablies
netstat -an | grep ESTABLISHED

# Tracer les appels reseau
strace -e socket,bind,listen,accept,connect ./server
```

---

## SECTION 7 : SORTIE ACADEMIQUE

### 7.1 Competences acquises

A la fin de cet exercice, l'etudiant sera capable de :

1. **Creer** des serveurs et clients TCP en C
2. **Comprendre** le modele client/serveur
3. **Utiliser** les fonctions socket de BSD
4. **Gerer** les erreurs reseau courantes
5. **Implementer** des protocoles applicatifs simples

### 7.2 Liens avec d'autres modules

| Module | Connexion |
|--------|-----------|
| 0.9.39 pipes | IPC locale vs reseau |
| 0.9.38 mmap | Alternatives pour gros transferts |
| HTTP/REST | Application des sockets |
| Securite | TLS, authentification |
