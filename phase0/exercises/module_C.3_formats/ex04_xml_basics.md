# Exercice C.3.4-a : xml_basics

**Module :**
C.3.4 — Formats XML

**Concept :**
a-d — XML syntax, elements, attributes, parsing basics

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.19 (strings), C.3.3 (json)

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
- `xml_basics.c`
- `xml_basics.h`

### 1.2 Consigne

Implementer des fonctions de manipulation XML simplifiees.

**Ta mission :**

```c
// Structure pour un attribut XML
typedef struct xml_attr {
    char *name;
    char *value;
} xml_attr;

// Structure pour un element XML
typedef struct xml_element {
    char *tag;
    xml_attr *attrs;
    int attr_count;
    char *content;
    struct xml_element *children;
    int child_count;
} xml_element;

// Extraire le nom de tag d'une balise ouvrante
char *extract_tag_name(const char *tag_str);

// Extraire la valeur d'un attribut
char *get_attribute(const char *tag_str, const char *attr_name);

// Extraire le contenu entre deux balises
char *extract_content(const char *xml, const char *tag);

// Verifier si une balise est auto-fermante
int is_self_closing(const char *tag_str);

// Compter les occurrences d'un tag
int count_tags(const char *xml, const char *tag);

// Liberer un element
void xml_free_element(xml_element *elem);
```

**Comportement:**

1. `extract_tag_name("<div class=\"main\">")` -> "div"
2. `get_attribute("<a href=\"url\">", "href")` -> "url"
3. `extract_content("<p>Hello</p>", "p")` -> "Hello"
4. `is_self_closing("<br/>")` -> 1
5. `count_tags("<a><a></a></a>", "a")` -> 2

**Exemples:**
```
extract_tag_name("<html>")           -> "html"
extract_tag_name("<div id=\"main\">") -> "div"
extract_tag_name("<br />")           -> "br"

get_attribute("<a href=\"test\">", "href") -> "test"
get_attribute("<div class=\"x\">", "id")   -> NULL

extract_content("<p>text</p>", "p") -> "text"
extract_content("<b></b>", "b")     -> ""

is_self_closing("<img/>")  -> 1
is_self_closing("<div>")   -> 0
```

### 1.3 Prototype

```c
// xml_basics.h
#ifndef XML_BASICS_H
#define XML_BASICS_H

typedef struct xml_attr {
    char *name;
    char *value;
} xml_attr;

typedef struct xml_element {
    char *tag;
    xml_attr *attrs;
    int attr_count;
    char *content;
    struct xml_element *children;
    int child_count;
} xml_element;

char *extract_tag_name(const char *tag_str);
char *get_attribute(const char *tag_str, const char *attr_name);
char *extract_content(const char *xml, const char *tag);
int is_self_closing(const char *tag_str);
int count_tags(const char *xml, const char *tag);
void xml_free_element(xml_element *elem);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | extract_tag_name("<div>") | "div" | 15 |
| T02 | extract_tag_name("<br/>") | "br" | 10 |
| T03 | get_attribute found | correct | 20 |
| T04 | get_attribute not found | NULL | 10 |
| T05 | extract_content | correct | 20 |
| T06 | is_self_closing | correct | 15 |
| T07 | count_tags | correct | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "xml_basics.h"

char *extract_tag_name(const char *tag_str)
{
    if (!tag_str || *tag_str != '<')
        return NULL;

    tag_str++;  // Skip '<'

    // Skip whitespace
    while (isspace(*tag_str))
        tag_str++;

    // Find end of tag name
    const char *start = tag_str;
    while (*tag_str && !isspace(*tag_str) &&
           *tag_str != '>' && *tag_str != '/')
    {
        tag_str++;
    }

    size_t len = tag_str - start;
    char *name = malloc(len + 1);
    if (name)
    {
        strncpy(name, start, len);
        name[len] = '\0';
    }
    return name;
}

char *get_attribute(const char *tag_str, const char *attr_name)
{
    if (!tag_str || !attr_name)
        return NULL;

    size_t attr_len = strlen(attr_name);
    const char *pos = tag_str;

    while ((pos = strstr(pos, attr_name)) != NULL)
    {
        // Verify it's the full attribute name
        if ((pos == tag_str || isspace(*(pos - 1))) &&
            pos[attr_len] == '=')
        {
            pos += attr_len + 1;  // Skip attr name and '='

            // Find the quote
            char quote = *pos;
            if (quote != '"' && quote != '\'')
                return NULL;

            pos++;  // Skip opening quote
            const char *end = strchr(pos, quote);
            if (!end)
                return NULL;

            size_t len = end - pos;
            char *value = malloc(len + 1);
            if (value)
            {
                strncpy(value, pos, len);
                value[len] = '\0';
            }
            return value;
        }
        pos++;
    }
    return NULL;
}

char *extract_content(const char *xml, const char *tag)
{
    if (!xml || !tag)
        return NULL;

    // Build opening tag pattern
    char open_tag[128];
    snprintf(open_tag, sizeof(open_tag), "<%s", tag);

    const char *start = strstr(xml, open_tag);
    if (!start)
        return NULL;

    // Find end of opening tag
    start = strchr(start, '>');
    if (!start)
        return NULL;
    start++;  // Skip '>'

    // Build closing tag
    char close_tag[128];
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

    const char *end = strstr(start, close_tag);
    if (!end)
        return NULL;

    size_t len = end - start;
    char *content = malloc(len + 1);
    if (content)
    {
        strncpy(content, start, len);
        content[len] = '\0';
    }
    return content;
}

int is_self_closing(const char *tag_str)
{
    if (!tag_str)
        return 0;

    size_t len = strlen(tag_str);
    if (len < 3)
        return 0;

    // Check for /> at the end
    return (tag_str[len - 2] == '/' && tag_str[len - 1] == '>');
}

int count_tags(const char *xml, const char *tag)
{
    if (!xml || !tag)
        return 0;

    int count = 0;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "<%s", tag);

    const char *pos = xml;
    while ((pos = strstr(pos, pattern)) != NULL)
    {
        // Verify it's actually a tag (followed by space, > or /)
        char next = pos[strlen(pattern)];
        if (isspace(next) || next == '>' || next == '/')
            count++;
        pos++;
    }
    return count;
}

void xml_free_element(xml_element *elem)
{
    if (!elem)
        return;

    free(elem->tag);
    free(elem->content);

    for (int i = 0; i < elem->attr_count; i++)
    {
        free(elem->attrs[i].name);
        free(elem->attrs[i].value);
    }
    free(elem->attrs);

    for (int i = 0; i < elem->child_count; i++)
    {
        xml_free_element(&elem->children[i]);
    }
    free(elem->children);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: extract_tag_name ne gere pas les espaces
char *extract_tag_name(const char *tag_str)
{
    tag_str++;  // Skip '<'
    // Oublie de sauter les espaces apres '<'
    const char *end = strchr(tag_str, '>');
    // ...
}

// MUTANT 2: get_attribute compare partiellement
char *get_attribute(const char *tag_str, const char *attr_name)
{
    const char *pos = strstr(tag_str, attr_name);
    // Ne verifie pas que c'est le debut du nom d'attribut
    // "data-href" matcherait "href"
}

// MUTANT 3: extract_content ne trouve pas closing tag
char *extract_content(const char *xml, const char *tag)
{
    char close_tag[128];
    snprintf(close_tag, sizeof(close_tag), "<%s>", tag);  // Manque le /
    // ...
}

// MUTANT 4: is_self_closing ne gere pas l'espace
int is_self_closing(const char *tag_str)
{
    size_t len = strlen(tag_str);
    return tag_str[len - 2] == '/';  // "<br />" echoue (espace)
}

// MUTANT 5: count_tags compte aussi les closing tags
int count_tags(const char *xml, const char *tag)
{
    int count = 0;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "%s", tag);  // Sans le <
    // Compte "div" dans "</div>" aussi
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le format **XML** (eXtensible Markup Language):

1. **Elements** - `<tag>content</tag>`
2. **Attributs** - `<tag attr="value">`
3. **Auto-fermant** - `<br/>`
4. **Hierarchie** - Elements imbriques

### 5.3 Visualisation ASCII

```
XML STRUCTURE:

<root>                    Level 0
  <parent attr="val">     Level 1
    <child>text</child>   Level 2
  </parent>
</root>

PARSING:
Input: "<div class=\"main\">Hello</div>"

extract_tag_name -> "div"
get_attribute("class") -> "main"
extract_content -> "Hello"

AUTO-CLOSING:
<img src="x.png"/>   -> is_self_closing = 1
<br />               -> is_self_closing = 1
<p>                  -> is_self_closing = 0
```

---

## SECTION 7 : QCM

### Question 1
Quelle balise est auto-fermante ?

A) `<div></div>`
B) `<br/>`
C) `<p>`
D) `</span>`
E) `<img>`

**Reponse correcte: B**

### Question 2
Comment specifier un attribut en XML ?

A) tag.attr = value
B) tag[attr] = value
C) `<tag attr="value">`
D) tag: attr: value
E) tag(attr=value)

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "C.3.4-a",
  "name": "xml_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["xml_basics.c", "xml_basics.h"],
  "tests": {
    "tag_extraction": "xml_tag_tests",
    "attribute": "xml_attr_tests",
    "content": "xml_content_tests"
  }
}
```
