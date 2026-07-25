---
title: "06. Defenses & Secure Coding Cheatsheet"
description: "Use this quick-reference matrix and static analysis rule set during code reviews and security audits."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Owasp Top 10", "06 Defenses Cheatsheet.Md"]
---

# 06. Defenses & Secure Coding Cheatsheet

Use this quick-reference matrix and static analysis rule set during code reviews and security audits.

---

## 1. Multi-Language Secure Coding Matrix

| Vulnerability | Python Fix | Node.js Fix | Go Fix | Java Fix |
|---|---|---|---|---|
| **SQL Injection** | `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` | `db.query("SELECT * FROM users WHERE id = ?", [uid])` | `db.Where("id = ?", uid).First(&user)` | `PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setInt(1, uid);` |
| **Command Injection** | `subprocess.run(["ping", "-c", "1", ip])` (No `shell=True`) | `execFile('ping', ['-c', '1', ip])` | `exec.Command("ping", "-c", "1", ip)` | `new ProcessBuilder("ping", "-c", "1", ip).start()` |
| **XSS Prevention** | `html.escape(user_input)` or Jinja autoescaping | `DOMPurify.sanitize(user_input)` | `html/template` (Auto-escapes) | `ESAPI.encoder().encodeForHTML(input)` |
| **Password Hashing** | `argon2.PasswordHasher().hash(password)` | `bcrypt.hash(password, 12)` | `golang.org/x/crypto/argon2` | `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()` |

---

## 2. Automated SAST Rules (Semgrep Rules)

Save this configuration as `.semgrep.yml` in your repository root to detect common OWASP Top 10 flaws automatically in CI/CD:

```yaml
rules:
  - id: python-sqli-string-formatting
    pattern-either:
      - pattern: $CURSOR.execute(f"..." + ...)
      - pattern: $CURSOR.execute("..." % ...)
      - pattern: $CURSOR.execute("...".format(...))
    message: "Potential SQL Injection detected. Use parameterized queries instead of string formatting."
    severity: ERROR
    languages: [python]

  - id: python-subprocess-shell-true
    pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "Command Injection Risk: subprocess executed with shell=True."
    severity: WARNING
    languages: [python]

  - id: express-cors-wildcard-with-credentials
    patterns:
      - pattern: res.header("Access-Control-Allow-Origin", req.headers.origin)
    message: "CORS Misconfiguration: Reflecting Origin header dynamically allows credential theft."
    severity: ERROR
    languages: [javascript, typescript]
```

### Running Semgrep Locally
```bash
# Install Semgrep
pip install semgrep

# Scan repository for security flaws
semgrep --config auto .
```

---

*Next Chapter: [07. Hands-On Vulnerability Lab →](07-hands-on-lab.md)*
