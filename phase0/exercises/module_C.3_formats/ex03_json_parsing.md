# Exercice C.3.3-a : json_parsing

**Module :**
C.3.3 — Formats JSON

**Concept :**
a-d — JSON syntax, parsing, serialization, data types

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.19 (strings), 0.5.20 (structs)

**Domaines :**
Encodage, Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `json_parsing.c`
- `json_parsing.h`

### 1.2 Consigne

Implementer un parseur JSON simplifie.

**Ta mission :**

```c
// Types JSON
typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

// Structure JSON value
typedef struct json_value {
    json_type type;
    union {
        int boolean;
        double number;
        char *string;
        struct {
            struct json_value *items;
            int count;
        } array;
        struct {
            char **keys;
            struct json_value *values;
            int count;
        } object;
    } data;
} json_value;

// Parser un nombre JSON
json_value parse_number(const char *str);

// Parser une chaine JSON
json_value parse_string(const char *str);

// Parser un booleen ou null
json_value parse_literal(const char *str);

// Serialiser en JSON
char *json_stringify(json_value *val);

// Liberer memoire
void json_free(json_value *val);
```

**Comportement:**

1. `parse_number("42")` -> json_value avec number=42.0
2. `parse_number("-3.14")` -> json_value avec number=-3.14
3. `parse_string("\"hello\"")` -> json_value avec string="hello"
4. `parse_literal("true")` -> json_value avec boolean=1
5. `parse_literal("null")` -> json_value avec type=JSON_NULL

**Exemples:**
```
parse_number("123")     -> {type: JSON_NUMBER, data.number: 123.0}
parse_number("-45.67")  -> {type: JSON_NUMBER, data.number: -45.67}
parse_string("\"test\"") -> {type: JSON_STRING, data.string: "test"}
parse_literal("true")    -> {type: JSON_BOOL, data.boolean: 1}
parse_literal("false")   -> {type: JSON_BOOL, data.boolean: 0}
parse_literal("null")    -> {type: JSON_NULL}

json_stringify(number_val)  -> "42"
json_stringify(string_val)  -> "\"hello\""
json_stringify(bool_val)    -> "true"
```

### 1.3 Prototype

```c
// json_parsing.h
#ifndef JSON_PARSING_H
#define JSON_PARSING_H

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value {
    json_type type;
    union {
        int boolean;
        double number;
        char *string;
        struct {
            struct json_value *items;
            int count;
        } array;
        struct {
            char **keys;
            struct json_value *values;
            int count;
        } object;
    } data;
} json_value;

json_value parse_number(const char *str);
json_value parse_string(const char *str);
json_value parse_literal(const char *str);
char *json_stringify(json_value *val);
void json_free(json_value *val);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | parse_number("42") | 42.0 | 15 |
| T02 | parse_number("-3.14") | -3.14 | 15 |
| T03 | parse_string("\"hello\"") | "hello" | 15 |
| T04 | parse_literal("true") | bool 1 | 15 |
| T05 | parse_literal("false") | bool 0 | 10 |
| T06 | parse_literal("null") | null | 10 |
| T07 | json_stringify | correct | 20 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json_parsing.h"

json_value parse_number(const char *str)
{
    json_value val;
    val.type = JSON_NUMBER;
    val.data.number = strtod(str, NULL);
    return val;
}

json_value parse_string(const char *str)
{
    json_value val;
    val.type = JSON_STRING;

    // Skip opening quote
    if (*str == '"')
        str++;

    size_t len = strlen(str);
    // Remove closing quote if present
    if (len > 0 && str[len - 1] == '"')
        len--;

    val.data.string = malloc(len + 1);
    if (val.data.string)
    {
        strncpy(val.data.string, str, len);
        val.data.string[len] = '\0';
    }
    return val;
}

json_value parse_literal(const char *str)
{
    json_value val;

    if (strcmp(str, "true") == 0)
    {
        val.type = JSON_BOOL;
        val.data.boolean = 1;
    }
    else if (strcmp(str, "false") == 0)
    {
        val.type = JSON_BOOL;
        val.data.boolean = 0;
    }
    else
    {
        val.type = JSON_NULL;
    }

    return val;
}

char *json_stringify(json_value *val)
{
    char *buffer = malloc(256);
    if (!buffer)
        return NULL;

    switch (val->type)
    {
        case JSON_NULL:
            strcpy(buffer, "null");
            break;
        case JSON_BOOL:
            strcpy(buffer, val->data.boolean ? "true" : "false");
            break;
        case JSON_NUMBER:
            snprintf(buffer, 256, "%g", val->data.number);
            break;
        case JSON_STRING:
            snprintf(buffer, 256, "\"%s\"", val->data.string);
            break;
        default:
            strcpy(buffer, "null");
    }

    return buffer;
}

void json_free(json_value *val)
{
    if (val->type == JSON_STRING && val->data.string)
    {
        free(val->data.string);
        val->data.string = NULL;
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: parse_number utilise atoi (perd precision)
json_value parse_number(const char *str)
{
    json_value val;
    val.type = JSON_NUMBER;
    val.data.number = atoi(str);  // Perd les decimales
    return val;
}

// MUTANT 2: parse_string ne retire pas les quotes
json_value parse_string(const char *str)
{
    json_value val;
    val.type = JSON_STRING;
    val.data.string = strdup(str);  // Garde les quotes
    return val;
}

// MUTANT 3: parse_literal compare avec ==
json_value parse_literal(const char *str)
{
    json_value val;
    if (str == "true")  // Compare pointeurs, pas contenu!
        val.type = JSON_BOOL;
    return val;
}

// MUTANT 4: json_stringify ne met pas les quotes
char *json_stringify(json_value *val)
{
    char *buffer = malloc(256);
    if (val->type == JSON_STRING)
        strcpy(buffer, val->data.string);  // Manque les quotes
    return buffer;
}

// MUTANT 5: json_free ne met pas a NULL
void json_free(json_value *val)
{
    if (val->type == JSON_STRING)
        free(val->data.string);
    // val->data.string reste dangling pointer
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le format **JSON** (JavaScript Object Notation):

1. **Types primitifs** - null, boolean, number, string
2. **Types composites** - array, object
3. **Syntaxe** - Guillemets pour strings, {} pour objets, [] pour arrays
4. **Parsing** - Conversion texte vers structure

### 5.3 Visualisation ASCII

```
JSON SYNTAX:

null        -> JSON_NULL
true/false  -> JSON_BOOL
42, -3.14   -> JSON_NUMBER
"hello"     -> JSON_STRING
[1, 2, 3]   -> JSON_ARRAY
{"k": "v"}  -> JSON_OBJECT

STRUCTURE:
json_value
+--------+------------------+
| type   |      data        |
+--------+------------------+
| NUMBER | number: 42.0     |
+--------+------------------+
| STRING | string: "hello"  |
+--------+------------------+
| BOOL   | boolean: 1       |
+--------+------------------+
```

---

## SECTION 7 : QCM

### Question 1
Comment sont delimitees les chaines en JSON ?

A) Apostrophes simples '
B) Guillemets doubles "
C) Backticks `
D) Rien
E) Les deux ' et "

**Reponse correcte: B**

### Question 2
Quel type JSON n'existe PAS ?

A) null
B) undefined
C) boolean
D) number
E) string

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "C.3.3-a",
  "name": "json_parsing",
  "language": "c",
  "language_version": "c17",
  "files": ["json_parsing.c", "json_parsing.h"],
  "tests": {
    "parse": "json_parse_tests",
    "stringify": "json_stringify_tests"
  }
}
```
