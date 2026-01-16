# Exercice 0.6.7-a : hash_table

**Module :**
0.6.7 — Structures de Donnees Avancees

**Concept :**
a-c — hash function, collision handling, buckets

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc), 0.6.4 (linked list), pointeurs

**Domaines :**
Structures, Mem, Algorithmes

**Duree estimee :**
300 min

**XP Base :**
450

**Complexite :**
T1 O(1) moyenne / O(n) pire cas x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `hash_table.c`
- `hash_table.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stddef.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `free()`, `printf()`, `memcpy()`, `strlen()`, `strcmp()`

### 1.2 Consigne

Implementer une table de hachage (hash table) avec gestion des collisions par chainage.

**Ta mission :**

Creer une structure de donnees hash table permettant le stockage et la recuperation rapide de paires cle-valeur (strings).

**Prototypes :**
```c
// Structure d'une entree (noeud)
typedef struct ht_entry {
    char *key;
    char *value;
    struct ht_entry *next;  // Chainage pour collisions
} ht_entry_t;

// Structure de la table de hachage
typedef struct hash_table {
    ht_entry_t **buckets;   // Tableau de pointeurs vers entries
    size_t size;            // Nombre de buckets
    size_t count;           // Nombre d'elements
} hash_table_t;

// Cree une nouvelle hash table avec 'size' buckets
hash_table_t *ht_create(size_t size);

// Insere ou met a jour une paire cle-valeur
bool ht_insert(hash_table_t *ht, const char *key, const char *value);

// Recherche une valeur par cle (retourne NULL si non trouve)
char *ht_get(hash_table_t *ht, const char *key);

// Supprime une entree par cle
bool ht_delete(hash_table_t *ht, const char *key);

// Libere toute la table de hachage
void ht_destroy(hash_table_t *ht);

// Fonction de hachage (djb2)
size_t ht_hash(const char *key, size_t size);
```

**Comportement :**
- `ht_create` initialise tous les buckets a NULL
- `ht_insert` met a jour la valeur si la cle existe deja
- `ht_get` retourne NULL si la cle n'existe pas
- `ht_delete` retourne false si la cle n'existe pas
- `ht_destroy` libere toutes les entries et leurs strings
- La fonction de hachage doit utiliser l'algorithme djb2

**Exemples :**
```
ht_create(16)                    -> table avec 16 buckets
ht_insert(ht, "nom", "Alice")    -> true
ht_insert(ht, "age", "25")       -> true
ht_get(ht, "nom")                -> "Alice"
ht_get(ht, "inexistant")         -> NULL
ht_delete(ht, "nom")             -> true
ht_delete(ht, "inexistant")      -> false
```

**Contraintes :**
- Utiliser l'algorithme djb2 pour le hachage
- Gerer les collisions par chainage (linked list)
- Dupliquer les cles et valeurs (ne pas stocker les pointeurs originaux)
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// hash_table.h
#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stddef.h>
#include <stdbool.h>

typedef struct ht_entry {
    char *key;
    char *value;
    struct ht_entry *next;
} ht_entry_t;

typedef struct hash_table {
    ht_entry_t **buckets;
    size_t size;
    size_t count;
} hash_table_t;

hash_table_t *ht_create(size_t size);
bool ht_insert(hash_table_t *ht, const char *key, const char *value);
char *ht_get(hash_table_t *ht, const char *key);
bool ht_delete(hash_table_t *ht, const char *key);
void ht_destroy(hash_table_t *ht);
size_t ht_hash(const char *key, size_t size);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'algorithme djb2

L'algorithme djb2, cree par Daniel J. Bernstein, est l'une des fonctions de hachage les plus simples et efficaces pour les chaines:
```c
hash = 5381;
while (*str)
    hash = ((hash << 5) + hash) + *str++;  // hash * 33 + c
```

### 2.2 Pourquoi 5381 et 33 ?

Ces nombres "magiques" ont ete choisis empiriquement:
- **5381** est un nombre premier qui donne une bonne distribution
- **33** (2^5 + 1) permet une multiplication rapide avec shift et addition
- Cette combinaison minimise les collisions pour la plupart des datasets

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Database Engineer**

Les hash tables sont au coeur de:
- Index de bases de donnees (hash index)
- Caches (Redis, Memcached)
- Systemes de fichiers (ext4 utilise des hash pour les repertoires)

**Metier : Systems Programmer**

Applications critiques:
- Tables de symboles des compilateurs
- Routage reseau (hash tables pour lookup IP)
- Deduplication de donnees

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_ht test_main.c hash_table.c
$ ./test_ht
Creating hash table with 16 buckets...
  OK: Table created

Testing insertions...
  ht_insert("alice", "engineer"): OK
  ht_insert("bob", "designer"): OK
  ht_insert("charlie", "manager"): OK
  Count: 3

Testing lookups...
  ht_get("alice"): "engineer" - OK
  ht_get("bob"): "designer" - OK
  ht_get("unknown"): NULL - OK

Testing collision handling...
  Keys "abc" and "bca" have same hash: 193485963
  ht_insert("abc", "value1"): OK
  ht_insert("bca", "value2"): OK
  ht_get("abc"): "value1" - OK (collision resolved)
  ht_get("bca"): "value2" - OK (collision resolved)

Testing deletion...
  ht_delete("bob"): true - OK
  ht_get("bob"): NULL - OK (deleted)
  Count: 4

Destroying table...
  OK: All memory freed

All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★☆☆☆ (7/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer le redimensionnement dynamique (rehashing) quand le facteur de charge depasse 0.75.

```c
// Calcule le facteur de charge (count / size)
double ht_load_factor(hash_table_t *ht);

// Redimensionne la table (double la taille)
bool ht_resize(hash_table_t *ht, size_t new_size);

// Iterateur sur toutes les entries
typedef void (*ht_iterator_fn)(const char *key, const char *value, void *ctx);
void ht_foreach(hash_table_t *ht, ht_iterator_fn fn, void *ctx);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | ht_create valid | size=16 | non-NULL, size=16 | 10 |
| T02 | ht_create zero | size=0 | NULL | 5 |
| T03 | ht_insert new key | "key","val" | true, count=1 | 15 |
| T04 | ht_insert update | same key | true, updated | 10 |
| T05 | ht_get existing | "key" | "val" | 15 |
| T06 | ht_get missing | "unknown" | NULL | 10 |
| T07 | ht_delete existing | "key" | true, count-- | 15 |
| T08 | ht_delete missing | "unknown" | false | 5 |
| T09 | collision handling | same hash keys | both retrievable | 15 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_table.h"

int main(void)
{
    int pass = 0, fail = 0;

    // T01: ht_create valid
    hash_table_t *ht = ht_create(16);
    if (ht != NULL && ht->size == 16 && ht->count == 0) {
        printf("T01 PASS: ht_create(16) works\n");
        pass++;
    } else {
        printf("T01 FAIL: ht_create(16) failed\n");
        fail++;
    }

    // T02: ht_create zero
    hash_table_t *ht_zero = ht_create(0);
    if (ht_zero == NULL) {
        printf("T02 PASS: ht_create(0) returned NULL\n");
        pass++;
    } else {
        printf("T02 FAIL: ht_create(0) should return NULL\n");
        ht_destroy(ht_zero);
        fail++;
    }

    // T03: ht_insert new key
    if (ht_insert(ht, "name", "Alice") && ht->count == 1) {
        printf("T03 PASS: ht_insert new key works\n");
        pass++;
    } else {
        printf("T03 FAIL: ht_insert new key failed\n");
        fail++;
    }

    // T04: ht_insert update
    if (ht_insert(ht, "name", "Bob") && ht->count == 1) {
        char *val = ht_get(ht, "name");
        if (val && strcmp(val, "Bob") == 0) {
            printf("T04 PASS: ht_insert update works\n");
            pass++;
        } else {
            printf("T04 FAIL: value not updated\n");
            fail++;
        }
    } else {
        printf("T04 FAIL: ht_insert update failed\n");
        fail++;
    }

    // T05: ht_get existing
    ht_insert(ht, "city", "Paris");
    char *city = ht_get(ht, "city");
    if (city && strcmp(city, "Paris") == 0) {
        printf("T05 PASS: ht_get existing works\n");
        pass++;
    } else {
        printf("T05 FAIL: ht_get existing failed\n");
        fail++;
    }

    // T06: ht_get missing
    if (ht_get(ht, "unknown") == NULL) {
        printf("T06 PASS: ht_get missing returns NULL\n");
        pass++;
    } else {
        printf("T06 FAIL: ht_get missing should return NULL\n");
        fail++;
    }

    // T07: ht_delete existing
    size_t count_before = ht->count;
    if (ht_delete(ht, "city") && ht->count == count_before - 1) {
        printf("T07 PASS: ht_delete existing works\n");
        pass++;
    } else {
        printf("T07 FAIL: ht_delete existing failed\n");
        fail++;
    }

    // T08: ht_delete missing
    if (!ht_delete(ht, "nonexistent")) {
        printf("T08 PASS: ht_delete missing returns false\n");
        pass++;
    } else {
        printf("T08 FAIL: ht_delete missing should return false\n");
        fail++;
    }

    // T09: collision handling (force collision)
    // Insert multiple entries to test chaining
    ht_insert(ht, "aa", "val1");
    ht_insert(ht, "bb", "val2");
    ht_insert(ht, "cc", "val3");
    char *v1 = ht_get(ht, "aa");
    char *v2 = ht_get(ht, "bb");
    char *v3 = ht_get(ht, "cc");
    if (v1 && v2 && v3 && strcmp(v1, "val1") == 0 &&
        strcmp(v2, "val2") == 0 && strcmp(v3, "val3") == 0) {
        printf("T09 PASS: collision handling works\n");
        pass++;
    } else {
        printf("T09 FAIL: collision handling failed\n");
        fail++;
    }

    ht_destroy(ht);

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * hash_table.c
 * Implementation d'une table de hachage avec chainage
 * Exercice ex30_hash_table
 */

#include "hash_table.h"
#include <stdlib.h>
#include <string.h>

// Fonction de hachage djb2
size_t ht_hash(const char *key, size_t size)
{
    size_t hash = 5381;
    int c;

    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }

    return hash % size;
}

// Cree une nouvelle entry
static ht_entry_t *ht_entry_create(const char *key, const char *value)
{
    ht_entry_t *entry = malloc(sizeof(*entry));
    if (entry == NULL)
    {
        return NULL;
    }

    entry->key = malloc(strlen(key) + 1);
    entry->value = malloc(strlen(value) + 1);

    if (entry->key == NULL || entry->value == NULL)
    {
        free(entry->key);
        free(entry->value);
        free(entry);
        return NULL;
    }

    strcpy(entry->key, key);
    strcpy(entry->value, value);
    entry->next = NULL;

    return entry;
}

// Libere une entry
static void ht_entry_destroy(ht_entry_t *entry)
{
    if (entry != NULL)
    {
        free(entry->key);
        free(entry->value);
        free(entry);
    }
}

hash_table_t *ht_create(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    hash_table_t *ht = malloc(sizeof(*ht));
    if (ht == NULL)
    {
        return NULL;
    }

    ht->buckets = calloc(size, sizeof(*ht->buckets));
    if (ht->buckets == NULL)
    {
        free(ht);
        return NULL;
    }

    ht->size = size;
    ht->count = 0;

    return ht;
}

bool ht_insert(hash_table_t *ht, const char *key, const char *value)
{
    if (ht == NULL || key == NULL || value == NULL)
    {
        return false;
    }

    size_t index = ht_hash(key, ht->size);
    ht_entry_t *current = ht->buckets[index];

    // Cherche si la cle existe deja
    while (current != NULL)
    {
        if (strcmp(current->key, key) == 0)
        {
            // Met a jour la valeur
            char *new_value = malloc(strlen(value) + 1);
            if (new_value == NULL)
            {
                return false;
            }
            strcpy(new_value, value);
            free(current->value);
            current->value = new_value;
            return true;
        }
        current = current->next;
    }

    // Cree une nouvelle entry
    ht_entry_t *entry = ht_entry_create(key, value);
    if (entry == NULL)
    {
        return false;
    }

    // Insere en tete de liste
    entry->next = ht->buckets[index];
    ht->buckets[index] = entry;
    ht->count++;

    return true;
}

char *ht_get(hash_table_t *ht, const char *key)
{
    if (ht == NULL || key == NULL)
    {
        return NULL;
    }

    size_t index = ht_hash(key, ht->size);
    ht_entry_t *current = ht->buckets[index];

    while (current != NULL)
    {
        if (strcmp(current->key, key) == 0)
        {
            return current->value;
        }
        current = current->next;
    }

    return NULL;
}

bool ht_delete(hash_table_t *ht, const char *key)
{
    if (ht == NULL || key == NULL)
    {
        return false;
    }

    size_t index = ht_hash(key, ht->size);
    ht_entry_t *current = ht->buckets[index];
    ht_entry_t *prev = NULL;

    while (current != NULL)
    {
        if (strcmp(current->key, key) == 0)
        {
            if (prev == NULL)
            {
                ht->buckets[index] = current->next;
            }
            else
            {
                prev->next = current->next;
            }
            ht_entry_destroy(current);
            ht->count--;
            return true;
        }
        prev = current;
        current = current->next;
    }

    return false;
}

void ht_destroy(hash_table_t *ht)
{
    if (ht == NULL)
    {
        return;
    }

    for (size_t i = 0; i < ht->size; i++)
    {
        ht_entry_t *current = ht->buckets[i];
        while (current != NULL)
        {
            ht_entry_t *next = current->next;
            ht_entry_destroy(current);
            current = next;
        }
    }

    free(ht->buckets);
    free(ht);
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: Open addressing (linear probing)
// Note: Necessite une structure differente
typedef struct {
    char *key;
    char *value;
    bool deleted;  // Marqueur pour deleted entries
} ht_entry_open_t;

// Alternative 2: Hash avec multiplication
size_t ht_hash_mult(const char *key, size_t size)
{
    size_t hash = 0;
    double A = 0.6180339887;  // (sqrt(5) - 1) / 2
    while (*key)
    {
        hash = hash * 31 + *key++;
    }
    double frac = hash * A - (size_t)(hash * A);
    return (size_t)(size * frac);
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Stocker les pointeurs originaux sans copie
bool ht_insert(hash_table_t *ht, const char *key, const char *value)
{
    ht_entry_t *entry = malloc(sizeof(*entry));
    entry->key = (char*)key;    // DANGER: pas de copie!
    entry->value = (char*)value;
    // ...
}
// Raison: Si la string originale est modifiee/liberee, corruption

// REFUSE 2: Pas de gestion des collisions
bool ht_insert(hash_table_t *ht, const char *key, const char *value)
{
    size_t index = ht_hash(key, ht->size);
    ht->buckets[index] = ht_entry_create(key, value);  // Ecrase!
    // ...
}
// Raison: Perd les entries existantes dans le meme bucket

// REFUSE 3: Fuite memoire lors de la mise a jour
bool ht_insert(hash_table_t *ht, const char *key, const char *value)
{
    // ...
    if (strcmp(current->key, key) == 0)
    {
        current->value = malloc(strlen(value) + 1);  // Fuite!
        strcpy(current->value, value);
        return true;
    }
}
// Raison: L'ancienne value n'est pas liberee
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.7-a",
  "name": "hash_table",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["hash_table.c", "hash_table.h"],
    "test": ["test_hash_table.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_ht"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "leak_check": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 65,
    "memory_safety": 25
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Logic): Hash sans modulo
size_t ht_hash(const char *key, size_t size)
{
    size_t hash = 5381;
    while (*key)
        hash = ((hash << 5) + hash) + *key++;
    return hash;  // Manque % size -> index hors limites!
}
// Detection: Segfault sur acces buckets

// MUTANT 2 (Memory): Pas de liberation de l'ancienne valeur
bool ht_insert(hash_table_t *ht, const char *key, const char *value)
{
    // Dans la mise a jour:
    current->value = malloc(strlen(value) + 1);  // Leak!
    strcpy(current->value, value);
}
// Detection: Valgrind definitely lost

// MUTANT 3 (Logic): strcmp au lieu de == pour comparer
while (current != NULL)
{
    if (current->key == key)  // Compare pointeurs, pas contenu!
    {
        return current->value;
    }
}
// Detection: ht_get retourne NULL meme si cle presente

// MUTANT 4 (Memory): Double free dans delete
bool ht_delete(hash_table_t *ht, const char *key)
{
    // ...
    ht_entry_destroy(current);
    ht_entry_destroy(current);  // Double free!
}
// Detection: Crash ou valgrind error

// MUTANT 5 (Boundary): Off-by-one dans destroy
void ht_destroy(hash_table_t *ht)
{
    for (size_t i = 0; i <= ht->size; i++)  // <= au lieu de <
    {
        // Acces hors limites
    }
}
// Detection: Valgrind invalid read
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des tables de hachage** en C:

1. **Hash function** - Convertir une cle en index numerique
2. **Collision handling** - Gerer quand deux cles ont le meme hash
3. **Buckets** - Tableau de listes chainees pour stocker les entries

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION inserer(table, cle, valeur):
DEBUT
    index <- calculer_hash(cle) MODULO taille_table

    POUR CHAQUE entree DANS table.buckets[index] FAIRE
        SI entree.cle EGALE cle ALORS
            entree.valeur <- copie(valeur)
            RETOURNER VRAI
        FIN SI
    FIN POUR

    nouvelle_entree <- creer_entree(cle, valeur)
    nouvelle_entree.suivant <- table.buckets[index]
    table.buckets[index] <- nouvelle_entree
    table.compteur <- table.compteur + 1

    RETOURNER VRAI
FIN
```

### 5.3 Visualisation ASCII

```
HASH TABLE avec chaining (taille = 4)
======================================

Insertions: ("alice", "A"), ("bob", "B"), ("eve", "E"), ("dave", "D")
Hash: alice->2, bob->1, eve->2 (collision!), dave->0

buckets[]
+---+
| 0 |---> [dave|D|NULL]
+---+
| 1 |---> [bob|B|NULL]
+---+
| 2 |---> [eve|E] ---> [alice|A|NULL]  <- Collision resolue par chainage
+---+
| 3 |---> NULL
+---+

Recherche de "eve":
1. hash("eve") % 4 = 2
2. Parcours bucket[2]: eve->eve (trouve!)
3. Retourne "E"

Recherche de "alice":
1. hash("alice") % 4 = 2
2. Parcours bucket[2]: eve != alice, suivant
3. alice == alice (trouve!)
4. Retourne "A"

COMPLEXITE:
- Insertion: O(1) amortie
- Recherche: O(1) amortie, O(n) pire cas
- Suppression: O(1) amortie

Facteur de charge = count / size
- Si > 0.75, performances degradees
- Solution: rehashing (doubler la taille)
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier le modulo dans le hash
```c
// FAUX - Index peut depasser la taille
size_t index = ht_hash(key, size);  // Si hash retourne juste le hash
ht->buckets[index];  // SEGFAULT!

// CORRECT
size_t index = ht_hash(key, size) % size;  // Ou dans la fonction
```

#### Piege 2: Stocker les pointeurs sans copie
```c
// FAUX - Danger si string originale modifiee
entry->key = (char*)key;

// CORRECT - Toujours copier
entry->key = malloc(strlen(key) + 1);
strcpy(entry->key, key);
```

#### Piege 3: Fuite memoire lors de mise a jour
```c
// FAUX - Ancienne valeur perdue
current->value = strdup(new_value);

// CORRECT
free(current->value);
current->value = strdup(new_value);
```

### 5.5 Cours Complet

#### 5.5.1 Fonction de hachage

Une bonne fonction de hachage doit:
- Etre deterministe (meme input = meme output)
- Distribuer uniformement les valeurs
- Etre rapide a calculer

L'algorithme **djb2**:
```c
size_t djb2(const char *str)
{
    size_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}
```

#### 5.5.2 Gestion des collisions

**Chainage (separate chaining):**
- Chaque bucket contient une liste chainee
- Facile a implementer
- Pas de limite sur le nombre d'elements

**Adressage ouvert (open addressing):**
- Cherche le prochain slot libre
- Meilleur cache locality
- Necessite rehashing plus frequent

#### 5.5.3 Facteur de charge

```
load_factor = n / m
```
- n = nombre d'elements
- m = nombre de buckets
- Ideal: 0.5 a 0.75
- Au-dela: performances degradees

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Toujours copier les strings | Evite corruption si original modifie | `strdup(key)` |
| Modulo sur le hash | Garde l'index dans les limites | `hash % size` |
| Liberer avant mise a jour | Evite memory leaks | `free(old); new = strdup()` |
| Verifier NULL partout | Hash table ou key peut etre NULL | `if (ht == NULL)` |

### 5.7 Simulation avec trace d'execution

```
Programme: ht_insert(ht, "test", "value")

1. Verifie ht != NULL, key != NULL, value != NULL
2. Calcule hash: djb2("test") = 2090756197
3. Index: 2090756197 % 16 = 5
4. Parcourt bucket[5]:
   - bucket[5] == NULL (vide)
5. Cree nouvelle entry:
   - malloc(sizeof(ht_entry_t)) = 0x1000
   - entry->key = strdup("test") = 0x1020
   - entry->value = strdup("value") = 0x1030
   - entry->next = NULL
6. Insere en tete:
   - entry->next = bucket[5] (NULL)
   - bucket[5] = entry (0x1000)
7. Incremente count: 0 -> 1
8. Retourne true

Etat final:
buckets[5] -> [test|value|NULL]
count = 1
```

### 5.8 Mnemotechniques

**"HIC" - Les 3 operations cles**
- **H**ash - Calculer l'index
- **I**nsert/Index - Trouver le bucket
- **C**hain - Parcourir la liste

**"DUCS" - Regles d'insertion**
- **D**upliquer les strings
- **U**pdate si existe
- **C**hainer si collision
- **S**tore en tete

### 5.9 Applications pratiques

1. **Dictionnaires/Maps**: Stockage cle-valeur rapide
2. **Caches**: Lookup O(1) pour donnees frequentes
3. **Deduplication**: Detecter les doublons rapidement
4. **Compilateurs**: Tables de symboles

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Hash sans modulo | Segfault | `hash % size` |
| Pas de copie strings | Corruption | `strdup()` |
| Leak en update | Memory leak | `free()` avant update |
| Mauvais chainage | Perte de donnees | Inserer en tete |
| Oubli count update | Mauvais count | `count++` / `count--` |

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite moyenne de recherche dans une hash table bien dimensionnee ?

A) O(n)
B) O(log n)
C) O(1)
D) O(n log n)
E) O(n^2)

**Reponse correcte: C**

### Question 2
Que se passe-t-il en cas de collision dans une hash table avec chainage ?

A) L'insertion echoue
B) L'ancienne valeur est ecrasee
C) L'element est ajoute a une liste chainee
D) La table est automatiquement redimensionnee
E) Une exception est levee

**Reponse correcte: C**

### Question 3
Pourquoi utilise-t-on le modulo dans une fonction de hachage ?

A) Pour accelerer le calcul
B) Pour garder l'index dans les limites du tableau
C) Pour eviter les collisions
D) Pour ameliorer la distribution
E) C'est optionnel

**Reponse correcte: B**

### Question 4
Quel est le facteur de charge ideal pour une hash table ?

A) 0.1 a 0.2
B) 0.5 a 0.75
C) 1.0 a 1.5
D) 2.0 ou plus
E) Le plus bas possible

**Reponse correcte: B**

### Question 5
Pourquoi faut-il copier les cles et valeurs dans une hash table ?

A) Pour accelerer les comparaisons
B) Pour eviter les collisions
C) Pour eviter la corruption si l'original est modifie
D) C'est obligatoire en C17
E) Pour economiser la memoire

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Operation | Complexite Moyenne | Complexite Pire Cas |
|-----------|-------------------|---------------------|
| insert | O(1) | O(n) |
| get | O(1) | O(n) |
| delete | O(1) | O(n) |
| create | O(n) | O(n) |
| destroy | O(n) | O(n) |

| Concept | Description |
|---------|-------------|
| Hash function | Convertit cle en index |
| Bucket | Slot dans le tableau |
| Chaining | Liste chainee pour collisions |
| Load factor | Ratio elements/taille |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.7-a",
    "name": "hash_table",
    "module": "0.6.7",
    "phase": 0,
    "difficulty": 6,
    "xp": 450,
    "time_minutes": 300
  },
  "metadata": {
    "concepts": ["hash function", "collision handling", "buckets"],
    "prerequisites": ["0.6.1", "0.6.4", "pointers"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "hash_table.c",
    "header": "hash_table.h",
    "solution": "hash_table_solution.c",
    "test": "test_hash_table.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 65,
    "memory_weight": 25
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 7
  }
}
```
