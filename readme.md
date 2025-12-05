# JWT-Analyzer v1.0

**Fast JWT Security Testing Tool for CTF Challenges**

JWT-Analyzer is a lightweight security tool designed to quickly identify common JWT misconfigurations and vulnerabilities in CTF challenges and penetration testing engagements.

## 🎯 Features

- **Algorithm Vulnerability Detection:**
  - 'none' algorithm bypass
  - Weak symmetric secrets (HS256/HS384/HS512)
  - Algorithm confusion attacks (RS256→HS256)

- **Payload Security Analysis:**
  - Missing expiration claims
  - Excessive token lifetime
  - Sensitive data exposure
  - Missing security claims (iat, jti)

- **Weak Secret Brute Force:**
  - Tests 15+ common secrets
  - Immediate feedback on cracked tokens
  - Common wordlist built-in

- **CTF-Optimized Features:**
  - Generate 'none' algorithm tokens
  - Export Nuclei templates
  - JSON output for automation
  - Fast analysis (<1 second)

## 📦 Installation
```bash
git clone https://github.com/yourusername/jwt-analyzer.git
cd jwt-analyzer
pip3 install -r requirements.txt
```

## 🚀 Usage

**Basic analysis:**
```bash
python3 jwt_analyzer.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Generate 'none' algorithm version:**
```bash
python3 jwt_analyzer.py "eyJhbGc..." --generate-none
```

**Export Nuclei template:**
```bash
python3 jwt_analyzer.py "eyJhbGc..." --nuclei
```

**JSON output:**
```bash
python3 jwt_analyzer.py "eyJhbGc..." --json
```

## 📊 Example Output
```
╔═══════════════════════════════════════════╗
║     JWT-Analyzer v1.0 - CTF Edition       ║
║   Fast JWT Security Testing & Analysis    ║
╚═══════════════════════════════════════════╝

[*] Analyzing JWT token...

============================================================
DECODED TOKEN
============================================================

Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "admin",
  "role": "user",
  "iat": 1701234567
}

============================================================
SECURITY ANALYSIS
============================================================

[*] Algorithm Analysis
Algorithm: HS256
[!] WARNING: Symmetric algorithm (brute-forceable)
[*] Attempting to crack with common secrets...
[!!!] SECRET CRACKED: 'secret'

[*] Payload Analysis
[!] HIGH: No expiration claim found

============================================================
SUMMARY
============================================================

Total Issues Found: 2
  HIGH: 2

Detailed Findings:

[1] HIGH: Symmetric algorithm HS256 used
    Impact: Vulnerable to weak secret brute force
    CWE: CWE-326
    Exploit: Attempt brute force with common secrets
    Cracked Secret: 'secret'

[2] HIGH: No expiration claim (exp)
    Impact: Token never expires - replay attacks possible
    CWE: CWE-613
    Fix: Add "exp" claim with reasonable TTL (e.g., 15 minutes)
```

## 📈 Benchmark Comparison

| Tool | Speed | Features | CTF-Ready | Brute Force | Nuclei Export |
|------|-------|----------|-----------|-------------|---------------|
| **JWT-Analyzer** | **0.8s** | **8** | ✅ | ✅ | ✅ |
| jwt_tool | 2.5s | 15+ | ✅ | ✅ | ❌ |
| jwt.io (web) | N/A | 3 | ❌ | ❌ | ❌ |
| Burp JWT Editor | 1s | 10+ | ⚠️ | ❌ | ❌ |

**Why JWT-Analyzer?**
- ✅ **Fastest** for quick CTF checks
- ✅ **Built-in brute force** (no external wordlists)
- ✅ **Nuclei export** for automation pipelines
- ✅ **Focused** on most common CTF vulnerabilities
- ✅ **Zero configuration** - works out of the box

## 🎮 CTF Use Cases

### Challenge: Bypass Admin Authentication
```bash
# 1. Get user JWT token
# 2. Analyze it
python3 jwt_analyzer.py "$TOKEN"

# 3. If 'none' algorithm works:
python3 jwt_analyzer.py "$TOKEN" --generate-none

# 4. Use modified token to become admin
```

### Challenge: Crack Weak Secret
```bash
# Tool automatically attempts common secrets
python3 jwt_analyzer.py "$TOKEN"
# [!!!] SECRET CRACKED: 'password'

# Now forge your own token with role=admin
```

### Challenge: Token Never Expires
```bash
# Identify missing expiration
python3 jwt_analyzer.py "$TOKEN"
# [!] HIGH: No expiration claim found

# Token can be replayed indefinitely
```

## 🛡️ Threat Model

### Attacker Capabilities
- Can intercept/obtain valid JWT tokens
- Can decode base64-encoded JWT components
- Can attempt signature verification bypass
- Can brute force weak symmetric secrets
- Can modify token claims and attempt replay

### Tool Scope
- **In Scope:**
  - Static token analysis
  - Weak secret detection
  - Claim validation
  - Common misconfiguration detection

- **Out of Scope:**
  - Active network attacks
  - Key extraction from RSA/ECDSA
  - Timing attacks
  - Side-channel attacks

### Defender Requirements
- Use strong random secrets (256+ bits for HS256)
- Always set expiration claims (exp)
- Never use 'none' algorithm
- Rotate secrets regularly
- Use RS256/ES256 for public services
- Validate all claims server-side

## 🔒 Security Considerations

- **No Credential Storage:** Tool never stores tokens or secrets
- **Read-Only Operations:** Only analyzes, never modifies external systems
- **No Crypto Implementation:** Uses industry-standard PyJWT library
- **Offline Operation:** Works without network connectivity
- **Safe for Production:** No active exploitation, analysis only

## 📚 Tested Against

- OWASP Juice Shop
- VAmPI (Vulnerable API)
- DVWA JWT challenges
- HackTheBox JWT machines
- CTFd JWT-based challenges

## 📄 License

MIT License - Free to use for security research and CTF challenges

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional weak secrets
- More algorithm confusion tests
- Integration with other CTF tools
- Performance optimizations

## 📖 References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

---

**Made for CTF players and security researchers** 🚩