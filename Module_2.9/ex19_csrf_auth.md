# ex19: CSRF & Authentication Security

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.36: CSRF (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Attack | Forged request from victim |
| b | Mechanism | Browser sends cookies |
| c | Impact | Unauthorized actions |
| d | CSRF token | Random per-request |
| e | SameSite cookie | Prevent cross-site |
| f | Referer check | Verify origin |
| g | Custom headers | X-Requested-With |

### 2.9.37: Authentication Security (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Password storage | Hash with salt |
| b | Session management | Secure session ID |
| c | Session fixation | Attack |
| d | Token-based | JWT, etc. |
| e | Multi-factor | Something you know/have/are |
| f | Rate limiting | Prevent brute force |
| g | Account lockout | After failures |
| h | Secure recovery | Password reset |

---

## Sujet

Comprendre CSRF et les bonnes pratiques d'authentification.

---

## Exemple

```c
#include "csrf_auth.h"

int main(void) {
    printf("=== CSRF (Cross-Site Request Forgery) ===\n\n");

    // CSRF concept
    printf("CSRF Attack:\n");
    printf("  Attacker tricks victim's browser into making request\n");
    printf("  Browser automatically includes victim's cookies\n");
    printf("  Server thinks it's legitimate request from victim\n");

    printf("\n  Attack scenario:\n");
    printf("  1. Victim logged into bank.com (has session cookie)\n");
    printf("  2. Victim visits evil.com\n");
    printf("  3. evil.com has: <img src='https://bank.com/transfer?to=attacker&amount=1000'>\n");
    printf("  4. Browser loads image, sends request WITH bank cookies\n");
    printf("  5. Bank processes transfer as victim's request!\n");

    printf("\n  Why it works:\n");
    printf("  - Browser sends cookies automatically\n");
    printf("  - Server trusts cookie = authenticated user\n");
    printf("  - No verification request came from bank's page\n");

    // CSRF examples
    printf("\n\n=== CSRF Attack Examples ===\n\n");

    printf("GET-based (simple):\n");
    printf("  <img src='http://bank.com/transfer?to=attacker&amt=1000'>\n");
    printf("  <iframe src='...'>\n");
    printf("  <script src='...'>\n");

    printf("\nPOST-based (form):\n");
    printf("  <form action='http://bank.com/transfer' method='POST' id='f'>\n");
    printf("    <input type='hidden' name='to' value='attacker'>\n");
    printf("    <input type='hidden' name='amount' value='1000'>\n");
    printf("  </form>\n");
    printf("  <script>document.getElementById('f').submit();</script>\n");

    printf("\n  Auto-submits when page loads!\n");

    // CSRF Prevention
    printf("\n\n=== CSRF Prevention ===\n\n");

    printf("1. CSRF Tokens:\n");
    printf("  Server includes random token in forms\n");
    printf("  Token validated on submission\n");
    printf("  Attacker can't know the token!\n");
    printf("\n  <form>\n");
    printf("    <input type='hidden' name='csrf_token' value='random123'>\n");
    printf("    ...\n");
    printf("  </form>\n");

    printf("\n2. SameSite Cookies:\n");
    printf("  Set-Cookie: session=abc; SameSite=Strict\n");
    printf("  \n");
    printf("  Strict: Never sent cross-site\n");
    printf("  Lax: Sent for GET navigation (not forms)\n");
    printf("  None: Always sent (requires Secure)\n");

    printf("\n3. Origin/Referer Validation:\n");
    printf("  Check Origin header matches expected domain\n");
    printf("  Referer shows source page\n");
    printf("  Can be spoofed in some cases\n");

    printf("\n4. Custom Headers:\n");
    printf("  X-Requested-With: XMLHttpRequest\n");
    printf("  Cross-origin requests can't set custom headers\n");
    printf("  (CORS preflight would block)\n");

    // Authentication Security
    printf("\n\n=== Authentication Security ===\n\n");

    // Password storage
    printf("Password Storage:\n");
    printf("  NEVER store plaintext passwords!\n");
    printf("  NEVER use MD5/SHA1 for passwords (too fast)\n");
    printf("\n  Correct approach:\n");
    printf("    hash = Argon2id(password, salt, params)\n");
    printf("    Store: salt + hash\n");
    printf("\n  Recommended:\n");
    printf("    - Argon2id (winner of PHC)\n");
    printf("    - bcrypt (proven)\n");
    printf("    - scrypt (memory-hard)\n");

    // Session management
    printf("\n\nSession Management:\n");
    printf("  Session ID requirements:\n");
    printf("    - High entropy (128+ bits random)\n");
    printf("    - Unpredictable (CSPRNG)\n");
    printf("    - Regenerated on login\n");
    printf("    - Expires after timeout\n");

    printf("\n  Cookie settings:\n");
    printf("    Set-Cookie: session=...; \n");
    printf("      Secure;        // HTTPS only\n");
    printf("      HttpOnly;      // No JavaScript\n");
    printf("      SameSite=Lax;  // CSRF protection\n");
    printf("      Path=/;        // Full site\n");
    printf("      Max-Age=3600;  // 1 hour expiry\n");

    // Session fixation
    printf("\n\nSession Fixation Attack:\n");
    printf("  1. Attacker gets valid session ID: abc123\n");
    printf("  2. Tricks victim: http://site.com/?session=abc123\n");
    printf("  3. Site sets victim's session to abc123\n");
    printf("  4. Victim logs in\n");
    printf("  5. Attacker uses session abc123 as victim!\n");
    printf("\n  Prevention:\n");
    printf("    REGENERATE session ID on authentication!\n");

    // Token-based auth
    printf("\n\nToken-Based Authentication:\n");
    printf("  JWT, API keys, OAuth tokens\n");
    printf("\n  Advantages:\n");
    printf("    - Stateless (no server session)\n");
    printf("    - Works across services\n");
    printf("    - Mobile-friendly\n");
    printf("\n  Considerations:\n");
    printf("    - Token storage (secure)\n");
    printf("    - Token expiration\n");
    printf("    - Token revocation (harder)\n");

    // MFA
    printf("\n\nMulti-Factor Authentication (MFA):\n");
    printf("  Something you know + have + are\n");
    printf("\n  Factors:\n");
    printf("    Knowledge: Password, PIN\n");
    printf("    Possession: Phone, hardware key\n");
    printf("    Inherence: Fingerprint, face\n");
    printf("\n  Methods:\n");
    printf("    - TOTP (Google Authenticator)\n");
    printf("    - SMS (weak, SIM swapping)\n");
    printf("    - Hardware keys (FIDO2, YubiKey)\n");
    printf("    - Push notifications\n");

    // Rate limiting
    printf("\n\nRate Limiting & Account Lockout:\n");
    printf("  Prevent brute force attacks\n");
    printf("\n  Rate limiting:\n");
    printf("    - Max N attempts per minute/IP\n");
    printf("    - Exponential backoff\n");
    printf("    - CAPTCHA after failures\n");
    printf("\n  Account lockout:\n");
    printf("    - Lock after 5-10 failures\n");
    printf("    - Temporary vs permanent\n");
    printf("    - Notify user of attempts\n");
    printf("    - DoS risk: balance security/usability\n");

    // Secure recovery
    printf("\n\nSecure Password Recovery:\n");
    printf("  Common mistakes:\n");
    printf("    - Security questions (guessable)\n");
    printf("    - Sending password in email\n");
    printf("    - Predictable reset tokens\n");

    printf("\n  Best practices:\n");
    printf("    - Random token in email link\n");
    printf("    - Token expires quickly (1 hour)\n");
    printf("    - Single-use token\n");
    printf("    - HTTPS link only\n");
    printf("    - Invalidate after use/expiry\n");
    printf("    - Log reset requests\n");
    printf("    - Rate limit reset requests\n");

    // Summary
    printf("\n\n=== Security Checklist ===\n\n");
    printf("  [ ] CSRF tokens on all state-changing requests\n");
    printf("  [ ] SameSite=Lax/Strict cookies\n");
    printf("  [ ] Passwords hashed with Argon2id/bcrypt\n");
    printf("  [ ] Sessions regenerated on login\n");
    printf("  [ ] Secure, HttpOnly cookies\n");
    printf("  [ ] Rate limiting on login\n");
    printf("  [ ] MFA available\n");
    printf("  [ ] Secure password reset\n");

    return 0;
}
```

---

## Fichiers

```
ex19/
├── csrf_auth.h
├── csrf.c
├── authentication.c
├── session_management.c
└── Makefile
```
