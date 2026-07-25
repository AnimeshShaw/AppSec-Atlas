---
title: "06. Defenses & Secure Coding Cheatsheet"
description: "Cross-language defense matrix (Python, Node.js, Go, Java), production Semgrep SAST rule set, and pull request security review checklist."
keywords: ["AppSec", "Cheatsheet", "Semgrep Rules", "Secure Coding", "Python", "Node.js", "Go", "Java", "SAST", "DAST"]
---

# 06. Defenses & Secure Coding Cheatsheet

This chapter provides a quick-reference secure coding matrix, production static analysis (Semgrep SAST) rules, and a pull request security review checklist across **Python**, **Node.js**, **Go**, and **Java**.

---

## 1. Multi-Language Secure Coding Matrix

| Vulnerability Category | Python Fix | Node.js Fix | Go Fix | Java Fix |
|---|---|---|---|---|
| **A01: Broken Access Control** | `User.query.filter_by(id=uid, owner_id=current_user).first_or_404()` | `Doc.findOneAndDelete({_id: id, ownerId: req.user.id})` | `db.Where("id = ? AND user_id = ?", id, userID).First(&res)` | `@PreAuthorize("#order.username == authentication.name")` |
| **A02: Password Hashing** | `argon2.PasswordHasher().hash(pwd)` | `bcrypt.hash(pwd, 12)` | `bcrypt.GenerateFromPassword([]byte(pwd), 12)` | `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()` |
| **A02: Data Encryption** | `AES-256-GCM` via `cryptography.fernet` / `hazmat` | `crypto.createCipheriv('aes-256-gcm', key, iv)` | `cipher.NewGCM(block)` | `Cipher.getInstance("AES/GCM/NoPadding")` |
| **A03: SQL Injection** | `cursor.execute("SELECT * FROM u WHERE id = %s", (uid,))` | `db.query("SELECT * FROM u WHERE id = $1", [uid])` | `db.QueryRow("SELECT * FROM u WHERE id = ?", uid)` | `PreparedStatement stmt = conn.prepareStatement(...)` |
| **A03: Command Injection** | `subprocess.run(["ping", "-c", "1", valid_ip])` | `execFile('ping', ['-c', '1', valid_ip])` | `exec.Command("ping", "-c", "1", valid_ip)` | `new ProcessBuilder("ping", "-c", "1", valid_ip).start()` |
| **A03: SSRF Defense** | Validate IP subnet against `127.0.0.0/8`, `169.254.0.0/16` | Verify DNS resolved IP before `axios.get()` | Custom `net.Dialer` blocking internal CIDRs | Restrict `HttpClient` target IP range |
| **A05: XXE Defense** | `import defusedxml.ElementTree as ET` | `libxmljs.parseXml(xml, { nonet: true })` | `encoding/xml` (Safe by default) | `dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)` |

---

## 2. Production Semgrep SAST Rules (`.semgrep.yml`)

Save the following configuration as `.semgrep.yml` in your repository root to automatically catch critical OWASP Top 10 vulnerabilities during code reviews or CI/CD runs:

```yaml
rules:
  - id: python-sqli-string-formatting
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute(f"..." + ...)
          - pattern: $CURSOR.execute("..." % ...)
          - pattern: $CURSOR.execute("...".format(...))
    message: "Critical: Potential SQL Injection detected. Use parameterized queries (%s) instead of string formatting."
    severity: ERROR
    languages: [python]

  - id: python-command-injection-shell-true
    patterns:
      - pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "Critical: Command Injection risk. Avoid subprocess execution with shell=True."
    severity: ERROR
    languages: [python]

  - id: express-cors-dynamic-origin-echo
    patterns:
      - pattern: res.header("Access-Control-Allow-Origin", req.headers.origin)
    message: "High: CORS Misconfiguration. Reflecting the Origin header dynamically with credentials allowed risks cross-domain data theft."
    severity: ERROR
    languages: [javascript, typescript]

  - id: python-unsafe-xml-parser
    patterns:
      - pattern-either:
          - pattern: lxml.etree.XMLParser(resolve_entities=True, ...)
          - pattern: xml.etree.ElementTree.fromstring(...)
    message: "High: Unsafe XML parsing detected. Use 'defusedxml' to prevent XXE and DTD bomb attacks."
    severity: WARNING
    languages: [python]

  - id: python-ssrf-unvalidated-request
    patterns:
      - pattern: requests.$METHOD(request.args.get(...), ...)
    message: "High: Potential SSRF flaw. Validate target URLs and block access to 169.254.169.254 and internal subnets."
    severity: ERROR
    languages: [python]
```

### Running Semgrep in CI/CD
```bash
# Install Semgrep
pip install semgrep

# Scan repository using local rules file
semgrep --config .semgrep.yml .
```

---

## 3. OWASP ZAP DAST CLI Scan Automation

Execute OWASP ZAP against your staging environment automatically in CI/CD pipelines:

```bash
# Run OWASP ZAP Baseline Scan using Docker
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
  -t https://staging.example.com \
  -g gen.conf \
  -r zap_report.html
```

---

## 4. Pull Request (PR) Security Review Checklist

Use this checklist during code reviews to ensure OWASP Top 10 compliance:

| Category | Audit Verification Item | Status |
|---|---|:---:|
| **Authentication** | Are password hashes generated using Argon2id or bcrypt (work factor >= 12)? | [ ] |
| **Authorization** | Does every route fetching/modifying database records verify ownership server-side? | [ ] |
| **Database Queries** | Are ALL SQL queries parameterized without string formatting or concatenation? | [ ] |
| **Command Execution**| Are system calls using rigid argument vectors without passing through a shell? | [ ] |
| **SSRF** | Are user-supplied URLs validated against internal IP ranges (`127.0.0.1`, `169.254.169.254`)? | [ ] |
| **CORS** | Are CORS origins strictly allowlisted rather than reflecting `req.headers.origin`? | [ ] |
| **Secrets** | Are all secrets/API keys injected via environment variables rather than hardcoded? | [ ] |
| **Logging** | Are sensitive fields (passwords, SSNs, tokens) filtered from application logs? | [ ] |

---

> [!TIP]
> **Proactive Security Gate:** Set up a pre-commit git hook with `gitleaks` and `semgrep` to block developers from committing hardcoded credentials or dangerous code patterns locally!

---

*Next Chapter: [07. Hands-On Vulnerability Lab →](07-hands-on-lab.md)*
