---
title: "05. A04 & A05: Insecure Design & Security Misconfiguration"
description: "This chapter covers design-level flaws (missing business logic limits) and environment misconfigurations (overly permissive headers, default credentia..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Owasp Top 10", "05 A04 Insecure Design And Misconfig.Md"]
---

# 05. A04 & A05: Insecure Design & Security Misconfiguration

This chapter covers design-level flaws (missing business logic limits) and environment misconfigurations (overly permissive headers, default credentials, verbose stack traces).

---

## 1. Missing Rate Limiting (Insecure Design)

Without rate limiting, attackers can perform automated credential stuffing, brute force password attempts, or trigger Denial of Service (DoS) against computationally expensive endpoints.

### ❌ Vulnerable Code (Express.js)
```javascript
// VULNERABLE: Unlimited login attempts allowed
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  // Attacker can attempt 10,000 passwords per minute!
});
```

### ✅ Secure Code (Express.js + express-rate-limit)
```javascript
const rateLimit = require('express-rate-limit');

// SECURE: Enforce strict rate limit on sensitive endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 failed login attempts per window
  message: { error: "Too many login attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // Safe: Rate limited login handler
});
```

---

## 2. CORS Misconfiguration (Security Misconfiguration)

Wildcard CORS headers combined with credentials allow malicious third-party websites to make authenticated API calls on behalf of users.

### ❌ Vulnerable Code (Node.js)
```javascript
// VULNERABLE: Reflects any Origin header and allows credentials!
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin); // Dangerous echo!
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});
```

### ✅ Secure Code (Node.js)
```javascript
const cors = require('cors');

const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com'
];

// SECURE: Strict allowlist check for CORS origin
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy error: Origin not allowed'));
    }
  },
  credentials: true
}));
```

---

## 3. XML External Entity (XXE) Prevention

XXE occurs when an XML parser parses untrusted XML input containing references to external entities (allowing attackers to read local files or trigger SSRF).

### ❌ Vulnerable Code (Python - lxml)
```python
from lxml import etree

# VULNERABLE: Resolves external entities automatically
def parse_xml_bad(xml_data: str):
    parser = etree.XMLParser(resolve_entities=True) # Dangerous!
    return etree.fromstring(xml_data, parser)
```

### ✅ Secure Code (Python - defusedxml)
```python
import defusedxml.ElementTree as ET

# SECURE: Safe XML parser that blocks entity resolution and DTD bomb attacks
def parse_xml_secure(xml_data: str):
    return ET.fromstring(xml_data)
```

---

*Next Chapter: [06. Defenses & Secure Coding Cheatsheet →](06-defenses-cheatsheet.md)*
