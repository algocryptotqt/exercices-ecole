# Exercice C.1.5-a : http_basics

**Module :**
C.1.5 — Protocole HTTP

**Concept :**
a-e — HTTP methods, status codes, headers, request/response format

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.19 (strings), C.1.4 (sockets)

**Domaines :**
Reseaux, Encodage

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `http_basics.c`
- `http_basics.h`

### 1.2 Consigne

Implementer des fonctions pour manipuler les messages HTTP.

**Ta mission :**

```c
// Structure requete HTTP
typedef struct http_request {
    char method[16];
    char path[256];
    char version[16];
    char *headers;
    char *body;
} http_request;

// Structure reponse HTTP
typedef struct http_response {
    int status_code;
    char status_text[64];
    char *headers;
    char *body;
} http_response;

// Parser une ligne de requete HTTP
int parse_request_line(const char *line, http_request *req);

// Parser une ligne de status HTTP
int parse_status_line(const char *line, http_response *resp);

// Construire une requete GET
char *build_get_request(const char *host, const char *path);

// Construire une reponse simple
char *build_response(int status, const char *body);

// Extraire une valeur de header
char *get_header_value(const char *headers, const char *name);

// Obtenir le texte pour un status code
const char *status_text(int code);
```

**Comportement:**

1. `parse_request_line("GET /index.html HTTP/1.1", &req)` -> req.method="GET"
2. `parse_status_line("HTTP/1.1 200 OK", &resp)` -> resp.status_code=200
3. `build_get_request("example.com", "/")` -> requete formatee
4. `build_response(200, "Hello")` -> reponse HTTP complete
5. `status_text(404)` -> "Not Found"

**Exemples:**
```
HTTP Request Line:
"GET /page HTTP/1.1"
-> method: "GET"
-> path: "/page"
-> version: "HTTP/1.1"

HTTP Status Line:
"HTTP/1.1 404 Not Found"
-> status_code: 404
-> status_text: "Not Found"

get_header_value("Content-Type: text/html\r\n", "Content-Type")
-> "text/html"
```

### 1.3 Prototype

```c
// http_basics.h
#ifndef HTTP_BASICS_H
#define HTTP_BASICS_H

typedef struct http_request {
    char method[16];
    char path[256];
    char version[16];
    char *headers;
    char *body;
} http_request;

typedef struct http_response {
    int status_code;
    char status_text[64];
    char *headers;
    char *body;
} http_response;

int parse_request_line(const char *line, http_request *req);
int parse_status_line(const char *line, http_response *resp);
char *build_get_request(const char *host, const char *path);
char *build_response(int status, const char *body);
char *get_header_value(const char *headers, const char *name);
const char *status_text(int code);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | parse_request_line GET | correct | 15 |
| T02 | parse_request_line POST | correct | 10 |
| T03 | parse_status_line 200 | correct | 15 |
| T04 | parse_status_line 404 | correct | 10 |
| T05 | build_get_request | valid HTTP | 20 |
| T06 | build_response | valid HTTP | 15 |
| T07 | get_header_value | correct | 15 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http_basics.h"

int parse_request_line(const char *line, http_request *req)
{
    if (!line || !req)
        return -1;

    int result = sscanf(line, "%15s %255s %15s",
                        req->method, req->path, req->version);

    return (result == 3) ? 0 : -1;
}

int parse_status_line(const char *line, http_response *resp)
{
    if (!line || !resp)
        return -1;

    char version[16];
    int result = sscanf(line, "%15s %d %63[^\r\n]",
                        version, &resp->status_code, resp->status_text);

    return (result >= 2) ? 0 : -1;
}

char *build_get_request(const char *host, const char *path)
{
    if (!host || !path)
        return NULL;

    char *request = malloc(1024);
    if (!request)
        return NULL;

    snprintf(request, 1024,
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);

    return request;
}

char *build_response(int status, const char *body)
{
    if (!body)
        body = "";

    size_t body_len = strlen(body);
    char *response = malloc(1024 + body_len);
    if (!response)
        return NULL;

    snprintf(response, 1024 + body_len,
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             status, status_text(status), body_len, body);

    return response;
}

char *get_header_value(const char *headers, const char *name)
{
    if (!headers || !name)
        return NULL;

    size_t name_len = strlen(name);
    const char *pos = headers;

    while (*pos)
    {
        // Check if this line starts with the header name
        if (strncasecmp(pos, name, name_len) == 0 && pos[name_len] == ':')
        {
            pos += name_len + 1;

            // Skip whitespace
            while (*pos == ' ' || *pos == '\t')
                pos++;

            // Find end of value
            const char *end = pos;
            while (*end && *end != '\r' && *end != '\n')
                end++;

            size_t len = end - pos;
            char *value = malloc(len + 1);
            if (value)
            {
                strncpy(value, pos, len);
                value[len] = '\0';
            }
            return value;
        }

        // Move to next line
        while (*pos && *pos != '\n')
            pos++;
        if (*pos)
            pos++;
    }
    return NULL;
}

const char *status_text(int code)
{
    switch (code)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: parse_request_line buffer overflow
int parse_request_line(const char *line, http_request *req)
{
    sscanf(line, "%s %s %s",  // Sans limites de taille!
           req->method, req->path, req->version);
    return 0;
}

// MUTANT 2: build_get_request sans CRLF
char *build_get_request(const char *host, const char *path)
{
    char *request = malloc(1024);
    snprintf(request, 1024,
             "GET %s HTTP/1.1\n"  // \n au lieu de \r\n
             "Host: %s\n",
             path, host);
    return request;
}

// MUTANT 3: build_response sans Content-Length
char *build_response(int status, const char *body)
{
    char *response = malloc(1024);
    snprintf(response, 1024,
             "HTTP/1.1 %d %s\r\n"
             "\r\n"  // Manque Content-Length header
             "%s",
             status, status_text(status), body);
    return response;
}

// MUTANT 4: get_header_value case-sensitive
char *get_header_value(const char *headers, const char *name)
{
    // Utilise strncmp au lieu de strncasecmp
    // "content-type" ne matchera pas "Content-Type"
}

// MUTANT 5: status_text retourne code au lieu de texte
const char *status_text(int code)
{
    static char buf[16];
    snprintf(buf, 16, "%d", code);  // Retourne "200" au lieu de "OK"
    return buf;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le protocole **HTTP**:

1. **Methodes** - GET, POST, PUT, DELETE, etc.
2. **Status codes** - 2xx success, 4xx client error, 5xx server error
3. **Headers** - Metadonnees de la requete/reponse
4. **Format** - Ligne de requete/status, headers, body

### 5.3 Visualisation ASCII

```
HTTP REQUEST:
+----------------------------------+
| GET /index.html HTTP/1.1         | <- Request Line
+----------------------------------+
| Host: example.com                | <- Headers
| Accept: text/html                |
+----------------------------------+
|                                  | <- Empty line (CRLF)
+----------------------------------+
| (body if POST/PUT)               | <- Body
+----------------------------------+

HTTP RESPONSE:
+----------------------------------+
| HTTP/1.1 200 OK                  | <- Status Line
+----------------------------------+
| Content-Type: text/html          | <- Headers
| Content-Length: 13               |
+----------------------------------+
|                                  | <- Empty line
+----------------------------------+
| Hello, World!                    | <- Body
+----------------------------------+

STATUS CODES:
1xx - Informational
2xx - Success (200 OK, 201 Created)
3xx - Redirection (301, 302, 304)
4xx - Client Error (400, 401, 403, 404)
5xx - Server Error (500, 502, 503)
```

---

## SECTION 7 : QCM

### Question 1
Quelle methode HTTP est utilisee pour obtenir une ressource ?

A) POST
B) PUT
C) GET
D) DELETE
E) PATCH

**Reponse correcte: C**

### Question 2
Que signifie le code 404 ?

A) OK
B) Not Found
C) Server Error
D) Unauthorized
E) Bad Request

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "C.1.5-a",
  "name": "http_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["http_basics.c", "http_basics.h"],
  "tests": {
    "request": "http_request_tests",
    "response": "http_response_tests",
    "headers": "http_header_tests"
  }
}
```
