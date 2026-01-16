# ex23: Security Tools & CTF Skills

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.44: Security Tools (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | nmap | Port scanner |
| b | Wireshark | Packet analyzer |
| c | Burp Suite | Web proxy |
| d | Metasploit | Exploitation framework |
| e | John the Ripper | Password cracker |
| f | hashcat | GPU password cracker |
| g | Nessus | Vulnerability scanner |
| h | OWASP ZAP | Web scanner |

### 2.9.45: CTF Skills (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | CTF | Capture The Flag |
| b | Categories | Pwn, web, crypto, forensics, reverse |
| c | Pwn | Binary exploitation |
| d | Web | Web vulnerabilities |
| e | Crypto | Cryptography challenges |
| f | Forensics | File analysis |
| g | Reverse | Reverse engineering |
| h | Practice sites | picoCTF, HackTheBox, TryHackMe |

---

## Sujet

Maitriser les outils de securite et les competences CTF.

---

## Exemple

```c
#include "security_tools_ctf.h"

int main(void) {
    printf("=== Security Tools ===\n\n");

    // nmap
    printf("nmap (Network Mapper):\n");
    printf("  Port scanning and service detection\n");
    printf("\n  Basic scans:\n");
    printf("    nmap 192.168.1.1           # Default scan (1000 ports)\n");
    printf("    nmap -p- 192.168.1.1       # All 65535 ports\n");
    printf("    nmap -sV 192.168.1.1       # Service version detection\n");
    printf("    nmap -sC 192.168.1.1       # Default scripts\n");
    printf("    nmap -A 192.168.1.1        # Aggressive (OS, version, scripts)\n");
    printf("\n  Scan types:\n");
    printf("    -sT: TCP connect (full handshake)\n");
    printf("    -sS: SYN scan (stealth, needs root)\n");
    printf("    -sU: UDP scan\n");
    printf("    -sn: Ping scan (host discovery)\n");

    // Wireshark
    printf("\n\nWireshark:\n");
    printf("  Network packet analyzer\n");
    printf("  Capture and inspect traffic\n");
    printf("\n  Filters:\n");
    printf("    ip.addr == 192.168.1.1\n");
    printf("    tcp.port == 80\n");
    printf("    http.request.method == \"POST\"\n");
    printf("    tcp.flags.syn == 1\n");
    printf("\n  Follow streams: Right-click -> Follow -> TCP Stream\n");

    // Burp Suite
    printf("\n\nBurp Suite:\n");
    printf("  Web application security testing\n");
    printf("  Intercept and modify HTTP requests\n");
    printf("\n  Features:\n");
    printf("    Proxy: Intercept browser traffic\n");
    printf("    Repeater: Modify and resend requests\n");
    printf("    Intruder: Automated attacks (fuzzing)\n");
    printf("    Scanner: Automated vulnerability detection (Pro)\n");
    printf("    Decoder: Encode/decode data\n");

    // Metasploit
    printf("\n\nMetasploit Framework:\n");
    printf("  Exploitation framework\n");
    printf("\n  Usage:\n");
    printf("    msfconsole\n");
    printf("    search apache\n");
    printf("    use exploit/multi/http/apache_mod_cgi_bash_env_exec\n");
    printf("    show options\n");
    printf("    set RHOSTS 192.168.1.100\n");
    printf("    set LHOST 192.168.1.50\n");
    printf("    exploit\n");
    printf("\n  Payloads:\n");
    printf("    meterpreter: Advanced shell\n");
    printf("    reverse_tcp: Connect back shell\n");
    printf("    bind_tcp: Listen on target\n");

    // Password crackers
    printf("\n\nPassword Cracking:\n");
    printf("\n  John the Ripper:\n");
    printf("    john --wordlist=rockyou.txt hashes.txt\n");
    printf("    john --show hashes.txt\n");
    printf("    john --format=raw-md5 hashes.txt\n");
    printf("\n  hashcat (GPU-accelerated):\n");
    printf("    hashcat -m 0 hashes.txt rockyou.txt     # MD5\n");
    printf("    hashcat -m 1000 hashes.txt rockyou.txt  # NTLM\n");
    printf("    hashcat -m 1800 hashes.txt rockyou.txt  # SHA-512 crypt\n");
    printf("    hashcat -a 3 hashes.txt ?a?a?a?a?a?a    # Brute force\n");

    // Vulnerability scanners
    printf("\n\nVulnerability Scanners:\n");
    printf("\n  Nessus:\n");
    printf("    Commercial scanner\n");
    printf("    Comprehensive vulnerability database\n");
    printf("    Compliance checking\n");
    printf("\n  OpenVAS:\n");
    printf("    Open source alternative\n");
    printf("    Similar functionality\n");
    printf("\n  OWASP ZAP:\n");
    printf("    Web application scanner\n");
    printf("    Active and passive scanning\n");
    printf("    Spider and fuzzer\n");

    // CTF
    printf("\n\n=== CTF (Capture The Flag) ===\n\n");

    printf("What is CTF?\n");
    printf("  Security competition\n");
    printf("  Solve challenges to find 'flags'\n");
    printf("  Flag format: flag{s0m3_t3xt_h3r3}\n");
    printf("\n  Formats:\n");
    printf("    Jeopardy: Pick challenges from categories\n");
    printf("    Attack-Defense: Attack others, defend yours\n");
    printf("    King of the Hill: Maintain control\n");

    // Categories
    printf("\n\n=== CTF Categories ===\n\n");

    printf("PWN (Binary Exploitation):\n");
    printf("  Exploit memory corruption bugs\n");
    printf("  Stack overflows, heap exploits, ROP\n");
    printf("  Tools: pwntools, GDB, ROPgadget\n");
    printf("  Skills: Assembly, C, debugging\n");

    printf("\nWEB:\n");
    printf("  Exploit web vulnerabilities\n");
    printf("  SQLi, XSS, CSRF, SSRF\n");
    printf("  Tools: Burp Suite, curl, browser devtools\n");
    printf("  Skills: HTTP, JavaScript, PHP/Python\n");

    printf("\nCRYPTO:\n");
    printf("  Break cryptographic systems\n");
    printf("  Classical ciphers, RSA, AES misuse\n");
    printf("  Tools: Python, CyberChef, SageMath\n");
    printf("  Skills: Math, number theory\n");

    printf("\nREVERSE:\n");
    printf("  Analyze compiled programs\n");
    printf("  Find hidden functionality\n");
    printf("  Tools: Ghidra, IDA, radare2\n");
    printf("  Skills: Assembly, debugging\n");

    printf("\nFORENSICS:\n");
    printf("  Analyze files and data\n");
    printf("  File carving, steganography, memory dumps\n");
    printf("  Tools: Autopsy, binwalk, steghide\n");
    printf("  Skills: File formats, data recovery\n");

    printf("\nMISC:\n");
    printf("  Everything else!\n");
    printf("  OSINT, programming, logic puzzles\n");

    // Practice platforms
    printf("\n\n=== Practice Platforms ===\n\n");

    printf("Beginner-friendly:\n");
    printf("  picoCTF: https://picoctf.org/\n");
    printf("    - Free, always available\n");
    printf("    - Great for beginners\n");
    printf("    - Progressive difficulty\n");

    printf("\n  TryHackMe: https://tryhackme.com/\n");
    printf("    - Guided learning paths\n");
    printf("    - Browser-based VMs\n");
    printf("    - Free tier available\n");

    printf("\n  OverTheWire: https://overthewire.org/\n");
    printf("    - Classic wargames\n");
    printf("    - Bandit, Natas, etc.\n");
    printf("    - Free SSH access\n");

    printf("\nIntermediate/Advanced:\n");
    printf("  HackTheBox: https://hackthebox.com/\n");
    printf("    - Realistic machines\n");
    printf("    - Active community\n");
    printf("    - Invite-only (solve challenge to join)\n");

    printf("\n  VulnHub: https://vulnhub.com/\n");
    printf("    - Downloadable VMs\n");
    printf("    - Run locally\n");
    printf("    - Various difficulties\n");

    printf("\n  pwnable.kr / pwnable.tw:\n");
    printf("    - Focus on binary exploitation\n");

    printf("\n  CryptoHack: https://cryptohack.org/\n");
    printf("    - Cryptography challenges\n");

    // CTF workflow
    printf("\n\n=== CTF Workflow ===\n\n");

    printf("1. Read the challenge description carefully\n");
    printf("2. Identify the category and likely techniques\n");
    printf("3. Gather information (recon)\n");
    printf("4. Research unfamiliar concepts\n");
    printf("5. Try different approaches\n");
    printf("6. Document your progress\n");
    printf("7. Ask for hints if stuck (after trying!)\n");
    printf("8. Write a writeup after solving\n");

    // Essential tools
    printf("\n\n=== CTF Toolkit ===\n\n");

    printf("General:\n");
    printf("  Python 3, pwntools\n");
    printf("  CyberChef (online decoder)\n");
    printf("  curl, wget, netcat\n");

    printf("\nPwn:\n");
    printf("  GDB + pwndbg/GEF\n");
    printf("  pwntools, ROPgadget\n");
    printf("  checksec, one_gadget\n");

    printf("\nWeb:\n");
    printf("  Burp Suite\n");
    printf("  Browser developer tools\n");
    printf("  sqlmap, dirbuster\n");

    printf("\nReverse:\n");
    printf("  Ghidra, IDA Free\n");
    printf("  radare2/Cutter\n");
    printf("  strace, ltrace\n");

    printf("\nCrypto:\n");
    printf("  Python (PyCryptodome)\n");
    printf("  SageMath\n");
    printf("  factordb.com, RsaCtfTool\n");

    printf("\nForensics:\n");
    printf("  binwalk, foremost\n");
    printf("  Volatility (memory)\n");
    printf("  Wireshark\n");

    return 0;
}
```

---

## Fichiers

```
ex23/
├── security_tools_ctf.h
├── security_tools.c
├── ctf_basics.c
├── ctf_categories.c
└── Makefile
```
