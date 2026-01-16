# ex20: JWT Security & OAuth 2.0

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.38: JWT Security (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | JWT structure | Header.Payload.Signature |
| b | Header | Algorithm |
| c | Payload | Claims |
| d | Signature | Verification |
| e | alg=none | Vulnerability |
| f | Key confusion | RS256 vs HS256 |
| g | Expiration | Short-lived |
| h | Refresh tokens | Renew access |
| i | Best practices | Validate all claims |

### 2.9.39: OAuth 2.0 (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Purpose | Delegated authorization |
| b | Roles | Resource owner, client, auth server, resource server |
| c | Grant types | Authorization code, implicit, client credentials |
| d | Authorization code | Most secure |
| e | PKCE | Proof Key for Code Exchange |
| f | Access token | Bearer token |
| g | Refresh token | Get new access token |
| h | Scopes | Permissions |
| i | OpenID Connect | Authentication layer |

---

## Sujet

Maitriser la securite JWT et le protocole OAuth 2.0.

---

## Exemple

```c
#include "jwt_oauth.h"

int main(void) {
    printf("=== JWT (JSON Web Token) ===\n\n");

    // JWT Structure
    printf("JWT Structure:\n");
    printf("  Header.Payload.Signature\n");
    printf("  (Base64URL encoded, dot-separated)\n");

    printf("\n  Example:\n");
    printf("  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\n");
    printf("  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\n");
    printf("  SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n");

    // Header
    printf("\n\n=== JWT Header ===\n");
    printf("  {\n");
    printf("    'alg': 'HS256',    // Signing algorithm\n");
    printf("    'typ': 'JWT'       // Token type\n");
    printf("  }\n");
    printf("\n  Common algorithms:\n");
    printf("    HS256: HMAC with SHA-256 (symmetric)\n");
    printf("    RS256: RSA with SHA-256 (asymmetric)\n");
    printf("    ES256: ECDSA with SHA-256 (asymmetric)\n");
    printf("    none:  NO SIGNATURE (DANGEROUS!)\n");

    // Payload
    printf("\n\n=== JWT Payload (Claims) ===\n");
    printf("  {\n");
    printf("    'sub': '1234567890',     // Subject (user ID)\n");
    printf("    'name': 'John Doe',      // Custom claim\n");
    printf("    'iat': 1516239022,       // Issued at\n");
    printf("    'exp': 1516242622,       // Expiration\n");
    printf("    'aud': 'myapp',          // Audience\n");
    printf("    'iss': 'auth.example.com' // Issuer\n");
    printf("  }\n");
    printf("\n  Registered claims:\n");
    printf("    iss: Issuer\n");
    printf("    sub: Subject\n");
    printf("    aud: Audience\n");
    printf("    exp: Expiration time\n");
    printf("    iat: Issued at\n");
    printf("    nbf: Not before\n");
    printf("    jti: JWT ID (unique identifier)\n");

    // Signature
    printf("\n\n=== JWT Signature ===\n");
    printf("  HMAC-SHA256:\n");
    printf("    signature = HMAC-SHA256(\n");
    printf("      base64url(header) + '.' + base64url(payload),\n");
    printf("      secret_key\n");
    printf("    )\n");
    printf("\n  RSA-SHA256:\n");
    printf("    signature = RSA-Sign(\n");
    printf("      base64url(header) + '.' + base64url(payload),\n");
    printf("      private_key\n");
    printf("    )\n");

    // JWT Vulnerabilities
    printf("\n\n=== JWT Vulnerabilities ===\n\n");

    printf("1. alg=none Attack:\n");
    printf("   Original: {'alg':'HS256',...}\n");
    printf("   Attack: {'alg':'none',...}\n");
    printf("   Remove signature, server accepts!\n");
    printf("   \n");
    printf("   Prevention: Whitelist allowed algorithms\n");

    printf("\n2. Key Confusion (RS256 vs HS256):\n");
    printf("   Server expects: RS256 (public key verify)\n");
    printf("   Attacker sends: alg=HS256\n");
    printf("   Signs with PUBLIC key as HMAC secret!\n");
    printf("   Server verifies using same public key!\n");
    printf("   \n");
    printf("   Prevention: Explicitly specify expected algorithm\n");

    printf("\n3. Weak Secret:\n");
    printf("   HS256 with weak secret: 'password123'\n");
    printf("   Brute force the secret, forge tokens\n");
    printf("   \n");
    printf("   Prevention: Use 256+ bit random secrets\n");

    printf("\n4. Missing Expiration:\n");
    printf("   Token without 'exp' claim\n");
    printf("   Valid forever!\n");
    printf("   \n");
    printf("   Prevention: Always set and validate exp\n");

    // Best practices
    printf("\n\n=== JWT Best Practices ===\n");
    printf("  1. Always validate signature\n");
    printf("  2. Whitelist allowed algorithms\n");
    printf("  3. Validate all claims (exp, aud, iss)\n");
    printf("  4. Use short expiration (15 min access)\n");
    printf("  5. Use refresh tokens for renewal\n");
    printf("  6. Store securely (HttpOnly cookie or memory)\n");
    printf("  7. Use asymmetric keys in distributed systems\n");

    // Refresh tokens
    printf("\n\nRefresh Tokens:\n");
    printf("  Access token: Short-lived (15 min)\n");
    printf("  Refresh token: Longer-lived (7 days)\n");
    printf("\n  Flow:\n");
    printf("  1. User logs in, gets access + refresh tokens\n");
    printf("  2. Access token expires\n");
    printf("  3. Client sends refresh token\n");
    printf("  4. Server issues new access token\n");
    printf("  5. Repeat until refresh token expires\n");

    // OAuth 2.0
    printf("\n\n=== OAuth 2.0 ===\n\n");

    printf("Purpose:\n");
    printf("  Delegated authorization\n");
    printf("  'Log in with Google' / 'Connect with Facebook'\n");
    printf("  User grants app access to their data\n");
    printf("  Without sharing password!\n");

    // OAuth Roles
    printf("\n\nOAuth Roles:\n");
    printf("  Resource Owner: User (owns the data)\n");
    printf("  Client: Application (wants access)\n");
    printf("  Authorization Server: Issues tokens (Google, etc.)\n");
    printf("  Resource Server: Hosts protected resources (API)\n");

    // Authorization Code Flow
    printf("\n\n=== Authorization Code Grant ===\n");
    printf("  Most secure flow (for server-side apps)\n");
    printf("\n  Flow:\n");
    printf("  1. User clicks 'Login with Google'\n");
    printf("  2. Redirect to: https://auth.google.com/authorize?\n");
    printf("       client_id=xxx&\n");
    printf("       redirect_uri=https://myapp.com/callback&\n");
    printf("       response_type=code&\n");
    printf("       scope=email profile&\n");
    printf("       state=random123\n");
    printf("  3. User logs in, grants permissions\n");
    printf("  4. Google redirects to callback with code:\n");
    printf("       https://myapp.com/callback?code=abc&state=random123\n");
    printf("  5. App exchanges code for tokens (server-side):\n");
    printf("       POST https://oauth2.googleapis.com/token\n");
    printf("       code=abc&client_secret=xxx&grant_type=authorization_code\n");
    printf("  6. Receive access_token (and optional refresh_token)\n");
    printf("  7. Use access_token to call APIs\n");

    // PKCE
    printf("\n\n=== PKCE (Proof Key for Code Exchange) ===\n");
    printf("  For public clients (mobile, SPA)\n");
    printf("  No client_secret (would be exposed)\n");
    printf("\n  Flow:\n");
    printf("  1. Generate code_verifier (random string)\n");
    printf("  2. Create code_challenge = SHA256(code_verifier)\n");
    printf("  3. Include code_challenge in authorize request\n");
    printf("  4. Include code_verifier in token exchange\n");
    printf("  5. Server verifies: SHA256(verifier) == challenge\n");
    printf("\n  Prevents: Code interception attacks\n");

    // Scopes
    printf("\n\nScopes:\n");
    printf("  Define permissions granted\n");
    printf("  Examples:\n");
    printf("    scope=email          // Read email address\n");
    printf("    scope=profile        // Read profile info\n");
    printf("    scope=read:repos     // Read GitHub repos\n");
    printf("    scope=write:repos    // Write GitHub repos\n");
    printf("\n  Principle: Request minimum necessary scopes\n");

    // OpenID Connect
    printf("\n\n=== OpenID Connect (OIDC) ===\n");
    printf("  Authentication layer on OAuth 2.0\n");
    printf("  OAuth = Authorization\n");
    printf("  OIDC = Authentication + Authorization\n");
    printf("\n  Adds:\n");
    printf("    - id_token (JWT with user info)\n");
    printf("    - UserInfo endpoint\n");
    printf("    - Standard claims (sub, email, name)\n");
    printf("    - scope=openid required\n");
    printf("\n  id_token contains verified user identity\n");

    // Security considerations
    printf("\n\n=== OAuth Security ===\n");
    printf("  1. Always use HTTPS\n");
    printf("  2. Validate state parameter (CSRF)\n");
    printf("  3. Use PKCE for public clients\n");
    printf("  4. Validate redirect_uri strictly\n");
    printf("  5. Store tokens securely\n");
    printf("  6. Use short-lived access tokens\n");
    printf("  7. Implement token revocation\n");

    return 0;
}
```

---

## Fichiers

```
ex20/
├── jwt_oauth.h
├── jwt.c
├── jwt_vulnerabilities.c
├── oauth2.c
├── oidc.c
└── Makefile
```
