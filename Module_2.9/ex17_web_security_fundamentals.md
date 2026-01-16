# ex17: Web Security Fundamentals & OWASP

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.32: Web Security Fundamentals (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | HTTP | Stateless protocol |
| b | Cookies | State management |
| c | Sessions | Server-side state |
| d | Same-origin policy | Browser security |
| e | CORS | Cross-Origin Resource Sharing |
| f | Content-Security-Policy | XSS mitigation |
| g | HTTPS | Encrypted HTTP |

### 2.9.33: OWASP Top 10 (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | A01 Broken Access Control | Authorization failures |
| b | A02 Cryptographic Failures | Weak crypto |
| c | A03 Injection | SQL, OS, LDAP |
| d | A04 Insecure Design | Flawed architecture |
| e | A05 Security Misconfiguration | Default settings |
| f | A06 Vulnerable Components | Known CVEs |
| g | A07 Authentication Failures | Identity problems |
| h | A08 Software Integrity | Untrusted updates |
| i | A09 Logging Failures | Missing logs |
| j | A10 SSRF | Server-Side Request Forgery |

---

## Sujet

Comprendre les fondamentaux de la securite web et le Top 10 OWASP.

---

## Exemple

```c
#include "web_security_fundamentals.h"

int main(void) {
    printf("=== Web Security Fundamentals ===\n\n");

    // HTTP
    printf("HTTP Protocol:\n");
    printf("  Stateless: Each request independent\n");
    printf("  No built-in session tracking\n");
    printf("\n  Request:\n");
    printf("    GET /page HTTP/1.1\n");
    printf("    Host: example.com\n");
    printf("    Cookie: session=abc123\n");
    printf("\n  Response:\n");
    printf("    HTTP/1.1 200 OK\n");
    printf("    Content-Type: text/html\n");
    printf("    Set-Cookie: session=abc123\n");

    // Cookies
    printf("\n\nCookies:\n");
    printf("  State storage in browser\n");
    printf("  Sent with every request to domain\n");
    printf("\n  Attributes:\n");
    printf("    Domain:   Which hosts receive cookie\n");
    printf("    Path:     URL path scope\n");
    printf("    Secure:   HTTPS only\n");
    printf("    HttpOnly: No JavaScript access\n");
    printf("    SameSite: Cross-site sending rules\n");
    printf("\n  Example:\n");
    printf("    Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict\n");

    // Sessions
    printf("\n\nSessions:\n");
    printf("  Server-side state storage\n");
    printf("  Client has session ID only\n");
    printf("\n  Flow:\n");
    printf("    1. User authenticates\n");
    printf("    2. Server creates session, stores user data\n");
    printf("    3. Server sends session ID in cookie\n");
    printf("    4. Client sends session ID with requests\n");
    printf("    5. Server looks up session data\n");

    // Same-Origin Policy
    printf("\n\nSame-Origin Policy (SOP):\n");
    printf("  Browser security fundamental\n");
    printf("  Prevents cross-origin data access\n");
    printf("\n  Origin = scheme + host + port\n");
    printf("    https://example.com:443\n");
    printf("\n  Same origin examples:\n");
    printf("    https://a.com/page1  <-> https://a.com/page2  (YES)\n");
    printf("    https://a.com        <-> http://a.com         (NO - scheme)\n");
    printf("    https://a.com        <-> https://b.com        (NO - host)\n");
    printf("    https://a.com:443    <-> https://a.com:8080   (NO - port)\n");

    // CORS
    printf("\n\nCORS (Cross-Origin Resource Sharing):\n");
    printf("  Controlled bypass of SOP\n");
    printf("  Server allows specific cross-origin requests\n");
    printf("\n  Headers:\n");
    printf("    Access-Control-Allow-Origin: https://trusted.com\n");
    printf("    Access-Control-Allow-Methods: GET, POST\n");
    printf("    Access-Control-Allow-Headers: Content-Type\n");
    printf("    Access-Control-Allow-Credentials: true\n");
    printf("\n  Preflight request (OPTIONS):\n");
    printf("    Browser asks: 'Can I do this cross-origin request?'\n");
    printf("    Server responds with allowed methods/headers\n");

    // CSP
    printf("\n\nContent-Security-Policy (CSP):\n");
    printf("  HTTP header controlling resource loading\n");
    printf("  Mitigates XSS by restricting script sources\n");
    printf("\n  Example:\n");
    printf("    Content-Security-Policy: \n");
    printf("      default-src 'self';\n");
    printf("      script-src 'self' https://cdn.example.com;\n");
    printf("      style-src 'self' 'unsafe-inline';\n");
    printf("      img-src *;\n");
    printf("\n  Directives:\n");
    printf("    default-src: Fallback for other directives\n");
    printf("    script-src:  JavaScript sources\n");
    printf("    style-src:   CSS sources\n");
    printf("    img-src:     Image sources\n");
    printf("    connect-src: XHR/Fetch destinations\n");

    // HTTPS
    printf("\n\nHTTPS:\n");
    printf("  HTTP over TLS\n");
    printf("  Provides:\n");
    printf("    - Confidentiality (encrypted)\n");
    printf("    - Integrity (tamper detection)\n");
    printf("    - Authentication (server identity)\n");
    printf("\n  Always use for:\n");
    printf("    - Login forms\n");
    printf("    - Any sensitive data\n");
    printf("    - Modern web (everything)\n");

    // OWASP Top 10
    printf("\n\n=== OWASP Top 10 (2021) ===\n\n");

    printf("A01: Broken Access Control\n");
    printf("  #1 most common vulnerability\n");
    printf("  Examples:\n");
    printf("    - IDOR: /user/123 -> change to /user/124\n");
    printf("    - Missing authorization checks\n");
    printf("    - Privilege escalation\n");
    printf("  Prevention: Check authorization on EVERY request\n");

    printf("\n\nA02: Cryptographic Failures\n");
    printf("  Weak or missing encryption\n");
    printf("  Examples:\n");
    printf("    - Passwords stored in plaintext\n");
    printf("    - Weak algorithms (MD5, SHA1)\n");
    printf("    - Hardcoded keys\n");
    printf("    - Missing HTTPS\n");
    printf("  Prevention: Use modern crypto, encrypt sensitive data\n");

    printf("\n\nA03: Injection\n");
    printf("  Untrusted data in commands/queries\n");
    printf("  Examples:\n");
    printf("    - SQL: SELECT * WHERE id = '1' OR '1'='1'\n");
    printf("    - OS: ; rm -rf /\n");
    printf("    - LDAP, XPath, NoSQL\n");
    printf("  Prevention: Parameterized queries, input validation\n");

    printf("\n\nA04: Insecure Design\n");
    printf("  Fundamental design flaws\n");
    printf("  Examples:\n");
    printf("    - No rate limiting on password reset\n");
    printf("    - Unlimited resource creation\n");
    printf("    - Missing threat modeling\n");
    printf("  Prevention: Threat model, security requirements\n");

    printf("\n\nA05: Security Misconfiguration\n");
    printf("  Insecure default settings\n");
    printf("  Examples:\n");
    printf("    - Default credentials\n");
    printf("    - Unnecessary features enabled\n");
    printf("    - Verbose error messages\n");
    printf("    - Missing security headers\n");
    printf("  Prevention: Hardening, automated config checks\n");

    printf("\n\nA06: Vulnerable Components\n");
    printf("  Using components with known CVEs\n");
    printf("  Examples:\n");
    printf("    - Outdated libraries (Log4j!)\n");
    printf("    - Unpatched frameworks\n");
    printf("    - Abandoned dependencies\n");
    printf("  Prevention: Dependency scanning, updates\n");

    printf("\n\nA07: Authentication Failures\n");
    printf("  Broken identity verification\n");
    printf("  Examples:\n");
    printf("    - Weak passwords allowed\n");
    printf("    - No brute-force protection\n");
    printf("    - Session fixation\n");
    printf("    - Credential stuffing\n");
    printf("  Prevention: MFA, strong password policy\n");

    printf("\n\nA08: Software Integrity Failures\n");
    printf("  Untrusted code/data\n");
    printf("  Examples:\n");
    printf("    - CI/CD pipeline compromise\n");
    printf("    - Unsigned updates\n");
    printf("    - Deserialization attacks\n");
    printf("  Prevention: Verify signatures, SRI for CDN\n");

    printf("\n\nA09: Security Logging Failures\n");
    printf("  Missing or inadequate logging\n");
    printf("  Examples:\n");
    printf("    - Login attempts not logged\n");
    printf("    - No alerting on attacks\n");
    printf("    - Logs not protected\n");
    printf("  Prevention: Log security events, monitor, alert\n");

    printf("\n\nA10: Server-Side Request Forgery (SSRF)\n");
    printf("  Server makes attacker-controlled requests\n");
    printf("  Examples:\n");
    printf("    - fetch(user_url) -> internal services\n");
    printf("    - Cloud metadata: http://169.254.169.254/\n");
    printf("    - Port scanning internal network\n");
    printf("  Prevention: Allowlist URLs, block internal ranges\n");

    // Summary table
    printf("\n\n=== OWASP Summary ===\n");
    printf("  +-----+------------------------+---------------+\n");
    printf("  | #   | Category               | Key Fix       |\n");
    printf("  +-----+------------------------+---------------+\n");
    printf("  | A01 | Broken Access Control  | AuthZ checks  |\n");
    printf("  | A02 | Cryptographic Failures | Modern crypto |\n");
    printf("  | A03 | Injection              | Param queries |\n");
    printf("  | A04 | Insecure Design        | Threat model  |\n");
    printf("  | A05 | Security Misconfig     | Hardening     |\n");
    printf("  | A06 | Vulnerable Components  | Patching      |\n");
    printf("  | A07 | Auth Failures          | MFA           |\n");
    printf("  | A08 | Integrity Failures     | Signatures    |\n");
    printf("  | A09 | Logging Failures       | Monitoring    |\n");
    printf("  | A10 | SSRF                   | Allowlisting  |\n");
    printf("  +-----+------------------------+---------------+\n");

    return 0;
}
```

---

## Fichiers

```
ex17/
├── web_security_fundamentals.h
├── http_basics.c
├── cookies_sessions.c
├── browser_security.c
├── owasp_top10.c
└── Makefile
```
