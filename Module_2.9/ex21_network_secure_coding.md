# ex21: Network Security & Secure Coding

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.40: Network Security (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Firewall | Packet filtering |
| b | iptables | Linux firewall |
| c | nftables | Modern replacement |
| d | IDS | Intrusion Detection |
| e | IPS | Intrusion Prevention |
| f | VPN | Virtual Private Network |
| g | DDoS | Distributed Denial of Service |
| h | DNS security | DNSSEC |
| i | Network segmentation | Isolation |

### 2.9.41: Secure Coding Practices (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Input validation | Never trust input |
| b | Output encoding | Context-aware |
| c | Parameterized queries | No SQL injection |
| d | Safe functions | strncpy vs strcpy |
| e | Bounds checking | Always |
| f | Error handling | Don't leak info |
| g | Least privilege | Minimum permissions |
| h | Defense in depth | Multiple layers |

---

## Sujet

Comprendre la securite reseau et les pratiques de codage securise.

---

## Exemple

```c
#include "network_secure_coding.h"

int main(void) {
    printf("=== Network Security ===\n\n");

    // Firewall
    printf("Firewalls:\n");
    printf("  Filter network traffic based on rules\n");
    printf("  Types:\n");
    printf("    - Packet filtering (stateless)\n");
    printf("    - Stateful inspection\n");
    printf("    - Application layer (WAF)\n");

    // iptables
    printf("\n\niptables (Linux Firewall):\n");
    printf("  # Drop all incoming by default\n");
    printf("  iptables -P INPUT DROP\n");
    printf("  \n");
    printf("  # Allow established connections\n");
    printf("  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n");
    printf("  \n");
    printf("  # Allow SSH\n");
    printf("  iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n");
    printf("  \n");
    printf("  # Allow HTTP/HTTPS\n");
    printf("  iptables -A INPUT -p tcp --dport 80 -j ACCEPT\n");
    printf("  iptables -A INPUT -p tcp --dport 443 -j ACCEPT\n");

    // nftables
    printf("\n\nnftables (Modern replacement):\n");
    printf("  nft add table inet filter\n");
    printf("  nft add chain inet filter input { type filter hook input priority 0 ; }\n");
    printf("  nft add rule inet filter input tcp dport 22 accept\n");

    // IDS/IPS
    printf("\n\nIDS/IPS:\n");
    printf("  IDS (Intrusion Detection System):\n");
    printf("    - Monitors traffic for suspicious activity\n");
    printf("    - Alerts administrators\n");
    printf("    - Examples: Snort, Suricata, OSSEC\n");
    printf("  \n");
    printf("  IPS (Intrusion Prevention System):\n");
    printf("    - Same as IDS but can block\n");
    printf("    - Active defense\n");
    printf("    - Can cause false positives\n");

    // VPN
    printf("\n\nVPN (Virtual Private Network):\n");
    printf("  Encrypted tunnel over public network\n");
    printf("  Types:\n");
    printf("    - Site-to-site: Connect networks\n");
    printf("    - Remote access: Connect users\n");
    printf("  Protocols:\n");
    printf("    - WireGuard (modern, fast)\n");
    printf("    - OpenVPN (mature, flexible)\n");
    printf("    - IPsec (complex, enterprise)\n");

    // DDoS
    printf("\n\nDDoS (Distributed Denial of Service):\n");
    printf("  Overwhelm target with traffic\n");
    printf("  Types:\n");
    printf("    - Volumetric: Flood bandwidth\n");
    printf("    - Protocol: Exhaust resources (SYN flood)\n");
    printf("    - Application: Target specific service\n");
    printf("  \n");
    printf("  Mitigations:\n");
    printf("    - Rate limiting\n");
    printf("    - CDN/DDoS protection (Cloudflare)\n");
    printf("    - Anycast distribution\n");
    printf("    - Traffic scrubbing\n");

    // DNS Security
    printf("\n\nDNS Security:\n");
    printf("  DNSSEC:\n");
    printf("    - Signs DNS records cryptographically\n");
    printf("    - Prevents DNS spoofing\n");
    printf("    - Chain of trust from root\n");
    printf("  \n");
    printf("  DNS over HTTPS (DoH):\n");
    printf("    - Encrypts DNS queries\n");
    printf("    - Prevents eavesdropping\n");
    printf("  \n");
    printf("  DNS over TLS (DoT):\n");
    printf("    - Alternative to DoH\n");
    printf("    - Dedicated port 853\n");

    // Network Segmentation
    printf("\n\nNetwork Segmentation:\n");
    printf("  Isolate networks to limit breach impact\n");
    printf("  \n");
    printf("  Common zones:\n");
    printf("    - DMZ: Public-facing servers\n");
    printf("    - Internal: Employee workstations\n");
    printf("    - Restricted: Sensitive systems\n");
    printf("  \n");
    printf("  Benefits:\n");
    printf("    - Limits lateral movement\n");
    printf("    - Reduces attack surface\n");
    printf("    - Easier monitoring\n");

    // Secure Coding
    printf("\n\n=== Secure Coding Practices ===\n\n");

    // Input validation
    printf("1. Input Validation:\n");
    printf("   NEVER trust user input!\n");
    printf("   \n");
    printf("   Bad:\n");
    printf("     int size = atoi(user_input);\n");
    printf("     char *buf = malloc(size);  // Negative? Huge?\n");
    printf("   \n");
    printf("   Good:\n");
    printf("     long size = strtol(user_input, &end, 10);\n");
    printf("     if (*end != '\\0' || size <= 0 || size > MAX_SIZE)\n");
    printf("         return ERROR;\n");

    // Output encoding
    printf("\n2. Output Encoding:\n");
    printf("   Encode for output context\n");
    printf("   \n");
    printf("   HTML: &lt; &gt; &amp; &quot;\n");
    printf("   JavaScript: \\x3c \\x3e\n");
    printf("   URL: %%3C %%3E\n");
    printf("   SQL: Use parameterized queries\n");

    // Parameterized queries
    printf("\n3. Parameterized Queries:\n");
    printf("   Prevent SQL injection\n");
    printf("   \n");
    printf("   Bad:\n");
    printf("     query = \"SELECT * FROM users WHERE id = '\" + id + \"'\";\n");
    printf("   \n");
    printf("   Good:\n");
    printf("     stmt = conn.prepare(\"SELECT * FROM users WHERE id = ?\");\n");
    printf("     stmt.execute([id]);\n");

    // Safe functions
    printf("\n4. Safe Functions:\n");
    printf("   Avoid unbounded operations\n");
    printf("   \n");
    printf("   Dangerous -> Safe:\n");
    printf("     gets()     -> fgets()\n");
    printf("     strcpy()   -> strncpy() / strlcpy()\n");
    printf("     strcat()   -> strncat() / strlcat()\n");
    printf("     sprintf()  -> snprintf()\n");
    printf("     scanf()    -> fgets() + sscanf()\n");

    // Bounds checking
    printf("\n5. Bounds Checking:\n");
    printf("   Always check array bounds\n");
    printf("   \n");
    printf("   Bad:\n");
    printf("     char buf[100];\n");
    printf("     for (int i = 0; i <= 100; i++)  // Off-by-one!\n");
    printf("         buf[i] = data[i];\n");
    printf("   \n");
    printf("   Good:\n");
    printf("     if (len >= sizeof(buf)) return ERROR;\n");
    printf("     memcpy(buf, data, len);\n");

    // Error handling
    printf("\n6. Error Handling:\n");
    printf("   Don't leak sensitive information\n");
    printf("   \n");
    printf("   Bad:\n");
    printf("     printf(\"Error: %%s\", strerror(errno));\n");
    printf("     printf(\"SQL: %%s\", query);  // Shows query!\n");
    printf("   \n");
    printf("   Good:\n");
    printf("     log_internal(\"Error: %%s\", strerror(errno));\n");
    printf("     return \"An error occurred\";  // Generic to user\n");

    // Least privilege
    printf("\n7. Least Privilege:\n");
    printf("   Only request minimum permissions\n");
    printf("   \n");
    printf("   - Run as non-root\n");
    printf("   - Drop privileges after binding port\n");
    printf("   - Limit file access\n");
    printf("   - Use capabilities instead of root\n");
    printf("   \n");
    printf("   Example:\n");
    printf("     bind(sock, addr, len);  // Needs root for port 80\n");
    printf("     setuid(nobody_uid);      // Drop to nobody\n");

    // Defense in depth
    printf("\n8. Defense in Depth:\n");
    printf("   Multiple layers of security\n");
    printf("   \n");
    printf("   Layers:\n");
    printf("     - Input validation\n");
    printf("     - Parameterized queries\n");
    printf("     - Output encoding\n");
    printf("     - CSP headers\n");
    printf("     - Firewall rules\n");
    printf("     - IDS/IPS\n");
    printf("   \n");
    printf("   If one layer fails, others still protect\n");

    // Summary
    printf("\n\n=== Secure Coding Checklist ===\n");
    printf("  [ ] Validate all input\n");
    printf("  [ ] Use parameterized queries\n");
    printf("  [ ] Encode output for context\n");
    printf("  [ ] Use safe string functions\n");
    printf("  [ ] Check all bounds\n");
    printf("  [ ] Handle errors safely\n");
    printf("  [ ] Run with least privilege\n");
    printf("  [ ] Enable compiler protections\n");
    printf("  [ ] Keep dependencies updated\n");

    return 0;
}
```

---

## Fichiers

```
ex21/
├── network_secure_coding.h
├── firewall.c
├── network_security.c
├── secure_coding.c
└── Makefile
```
