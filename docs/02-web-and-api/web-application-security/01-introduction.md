---
title: "Introduction to Web Application Security"
description: "Master modern web application security fundamentals, architecture flaws, root causes of vulnerabilities, and implement secure HTTP transport protocol headers."
keywords: ["web application security", "HTTP security headers", "HSTS", "CSP", "X-Frame-Options", "Referrer-Policy", "secure coding", "web architecture"]
---
# 01 - Introduction to Web Application Security

## The Modern Web Architecture
Modern web applications consist of dynamic interactions between the client (usually a web browser) and the server. This interaction is primarily governed by the HTTP protocol. Applications often follow a multi-tier architecture, including presentation, application/logic, and data tiers.

### Root Causes of Vulnerabilities
> [!WARNING]
> Most security breaches occur not from complex zero-days, but from simple misconfigurations and fundamental logical errors in the application architecture.

Most web vulnerabilities stem from:
1. **Unsafe data processing:** Trusting user input implicitly.
2. **Broken access control:** Failure to restrict authenticated users properly.
3. **Misconfigurations:** Default settings, exposed administrative interfaces, or verbose error messages.

## HTTP Protocol Security Headers
Securing the transport layer is critical. Security headers instruct the browser on how to handle the application's content safely.

### 1. HTTP Strict Transport Security (HSTS)
Forces the browser to communicate with the server over HTTPS, mitigating SSL stripping attacks.
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### 2. Content Security Policy (CSP)
Prevents Cross-Site Scripting (XSS) and data injection attacks by restricting the sources from which content can be loaded.
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.example.com; object-src 'none';
```

### 3. X-Frame-Options
Protects against Clickjacking by ensuring the content cannot be embedded into other sites.
```http
X-Frame-Options: DENY
```
*Note: This is largely superseded by the `frame-ancestors` directive in CSP.*

### 4. Referrer-Policy
Controls how much referrer information (sent via the `Referer` header) should be included with requests.
```http
Referrer-Policy: strict-origin-when-cross-origin
```

> [!TIP]
> The `strict-origin-when-cross-origin` policy offers a great balance between security and functionality, keeping full URLs within the same origin but downgrading to origin-only for cross-origin HTTPS requests.

## Security Headers Comparison Table

| Header Name | Primary Purpose | Recommended Value | Threat Mitigated |
|---|---|---|---|
| `Strict-Transport-Security` | Enforce HTTPS | `max-age=31536000; includeSubDomains` | SSL Stripping, MiTM |
| `Content-Security-Policy` | Restrict resources | `default-src 'self'` (baseline) | XSS, Data Injection |
| `X-Frame-Options` | Prevent framing | `DENY` or `SAMEORIGIN` | Clickjacking |
| `Referrer-Policy` | Control referrer info | `strict-origin-when-cross-origin` | Info Leakage |

## Configuring Headers

### Python (Flask)
```python
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def set_security_headers(response: Response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

### Node.js (Express via Helmet)
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Helmet automatically sets secure headers including HSTS, X-Frame-Options, etc.
app.use(helmet());

// Customizing CSP
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://trusted.com"]
  }
}));
```
